//! Test simple transfer
//!   See ./evm-contracts/SimpleTransfer.sol

use crate::helper::{
    self, contract_script_to_short_script_hash, deploy, eth_addr_to_ethabi_addr, new_block_info,
    new_contract_account_script, setup, simple_storage_get, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};
use std::convert::TryInto;

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const INIT_CODE: &str = include_str!("./evm-contracts/SimpleTransfer.bin");

#[test]
fn test_simple_transfer() {
    let (store, mut state, generator) = setup();
    let block_producer_id = helper::create_block_producer(&mut state);

    let mint_balance: u128 = 400000;
    let from_eth_address = [1u8; 20];
    let (from_id, from_script_hash) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address, mint_balance);

    let target_eth_addr = [2u8; 20];
    let (target_id, target_script_hash) =
        helper::create_eth_eoa_account(&mut state, &target_eth_addr, 0);
    let target_short_script_hash = &target_script_hash[0..20];

    let from_balance = state
        .get_sudt_balance(
            CKB_SUDT_ACCOUNT_ID,
            from_script_hash[..20].try_into().unwrap(),
        )
        .unwrap();
    assert_eq!(from_balance, mint_balance);
    let target_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_script_hash)
        .unwrap();
    assert_eq!(target_balance, 0);

    // Deploy SimpleStorage
    let mut block_number = 0;
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        SS_INIT_CODE,
        50000,
        0,
        block_producer_id,
        block_number,
    );
    block_number += 1;
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );
    let ss_account_script =
        new_contract_account_script(&mut state, from_id, &from_eth_address, false);
    let ss_script_hash = ss_account_script.hash();
    let ss_short_address = &ss_script_hash[0..20];
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    let ss_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, ss_short_address)
        .unwrap();
    assert_eq!(ss_balance, 0);
    let run_result = simple_storage_get(
        &store,
        &state,
        &generator,
        block_number,
        from_id,
        ss_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("000000000000000000000000000000000000000000000000000000000000007b").unwrap()
    );

    println!("================");
    // Deploy SimpleTransfer
    let deploy_value = 200;
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        INIT_CODE,
        50000,
        deploy_value,
        block_producer_id,
        block_number,
    );
    // [Deploy SimpleTransfer] used cycles: 491894 -> 500005 < 501K
    helper::check_cycles("Deploy SimpleTransfer", run_result.used_cycles, 501_000);

    let st_contract_account_script =
        new_contract_account_script(&mut state, from_id, &from_eth_address, false);
    let st_contract_script_hash = st_contract_account_script.hash();
    let st_contract_short_script_hash = &st_contract_script_hash[0..20];
    let st_contract_id = state
        .get_account_id_by_script_hash(&st_contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let st_contract_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
        .unwrap();
    assert_eq!(st_contract_balance, deploy_value);

    println!("================");
    println!(
        "from_id={}, new_account_id={}, target_id={}",
        from_id, st_contract_id, target_id
    );
    {
        // > transfer to EoA
        // SimpleTransfer.transferTo();
        block_number += 1;
        let old_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
            .unwrap();
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        let input = hex::decode(format!(
            "a03fa7e3{}",
            hex::encode(eth_addr_to_ethabi_addr(&target_eth_addr)),
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(40000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(st_contract_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("construct");
        // [SimpleTransfer to EoA] used cycles: 725217 < 736K
        helper::check_cycles("SimpleTransfer to EoA", run_result.used_cycles, 736_000);
        state.apply_run_result(&run_result).expect("update state");

        let new_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
            .unwrap();
        assert_eq!(new_balance, old_balance - 1);
        let target_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_script_hash)
            .unwrap();
        assert_eq!(target_balance, 1);
    }

    // TODO: check this logic: can't transfer to zero_address{0}
    // {
    //     // > transfer to zero address
    //     // SimpleTransfer.transferTo(address{0});
    //     let old_balance = state
    //         .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
    //         .unwrap();
    //     let block_info = new_block_info(block_producer_id, block_number, block_number);
    //     let input = hex::decode(format!(
    //         "a03fa7e30000000000000000000000000000000000000000000000000000000000000000",
    //     ))
    //     .unwrap();
    //     let args = PolyjuiceArgsBuilder::default()
    //         .gas_limit(40000)
    //         .gas_price(1)
    //         .value(0)
    //         .input(&input)
    //         .build();
    //     let raw_tx = RawL2Transaction::new_builder()
    //         .from_id(from_id.pack())
    //         .to_id(st_contract_id.pack())
    //         .args(Bytes::from(args).pack())
    //         .build();
    //     let db = store.begin_transaction();
    //     let tip_block_hash = store.get_tip_block_hash().unwrap();
    //     let run_result = generator
    //         .execute_transaction(
    //             &ChainView::new(&db, tip_block_hash),
    //             &state,
    //             &block_info,
    //             &raw_tx,
    //             L2TX_MAX_CYCLES, None,
    //         )
    //         .expect("SimpleTransfer.transferTo(address{0})");
    //     // [SimpleTransfer to zero address] used cycles: 699554 < 710K
    //     helper::check_cycles(
    //         "SimpleTransfer to zero address",
    //         run_result.used_cycles,
    //         710_000,
    //     );

    //     state.apply_run_result(&run_result).expect("update state");

    //     let new_balance = state
    //         .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
    //         .unwrap();
    //     assert_eq!(new_balance, old_balance - 1);

    //     let zero_account_balance = state
    //         .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &[0u8; 20][..])
    //         .unwrap();
    //     assert_eq!(zero_account_balance, 1);
    // }

    println!("================");
    {
        // SimpleTransfer.transferToSimpleStorage1();
        let old_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
            .unwrap();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "f10c7360{}",
            hex::encode(contract_script_to_short_script_hash(
                &ss_account_script,
                true
            )),
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(80000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(st_contract_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("construct");
        // [SimpleTransfer.transferToSimpleStorage1] used cycles: 1203332 < 1210K
        helper::check_cycles(
            "SimpleTransfer.transferToSimpleStorage1()",
            run_result.used_cycles,
            1_210_000,
        );
        state.apply_run_result(&run_result).expect("update state");

        let new_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
            .unwrap();
        assert_eq!(new_balance, old_balance - 1);
        let ss_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, ss_short_address)
            .unwrap();
        assert_eq!(ss_balance, 1);
        println!("================");
        let run_result = simple_storage_get(
            &store,
            &state,
            &generator,
            block_number,
            from_id,
            ss_account_id,
        );
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap()
        );
    }

    println!("================");
    {
        // SimpleTransfer.transferToSimpleStorage2();
        let old_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
            .unwrap();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "2a5eb963{}",
            hex::encode(contract_script_to_short_script_hash(
                &ss_account_script,
                true
            )),
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(80000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(st_contract_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("construct");
        state.apply_run_result(&run_result).expect("update state");

        let new_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, st_contract_short_script_hash)
            .unwrap();
        assert_eq!(new_balance, old_balance - 1);
        let ss_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, ss_short_address)
            .unwrap();
        assert_eq!(ss_balance, 2);
        let run_result = simple_storage_get(
            &store,
            &state,
            &generator,
            block_number,
            from_id,
            ss_account_id,
        );
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap()
        );
    }
}
