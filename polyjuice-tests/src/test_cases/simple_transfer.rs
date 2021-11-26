//! Test simple transfer
//!   See ./evm-contracts/SimpleTransfer.sol

use crate::helper::{
    self, account_id_to_eth_address, build_eth_l2_script, contract_script_to_eth_address, deploy,
    new_account_script, new_block_info, setup, simple_storage_get, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const INIT_CODE: &str = include_str!("./evm-contracts/SimpleTransfer.bin");

#[test]
fn test_simple_transfer() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    let mint_balance: u128 = 400000;
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, mint_balance)
        .unwrap();
    let target_script = build_eth_l2_script([2u8; 20]);
    let target_script_hash = target_script.hash();
    let target_short_address = &target_script_hash[0..20];
    let target_id = state.create_account_from_script(target_script).unwrap();

    let from_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    assert_eq!(from_balance, mint_balance);
    let target_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_address)
        .unwrap();
    assert_eq!(target_balance, 0);

    let mut block_number = 0;

    println!("================");
    // Deploy SimpleStorage
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
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
    let ss_account_script = new_account_script(&mut state, creator_account_id, from_id, false);
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
    println!("--------");
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
        creator_account_id,
        from_id,
        INIT_CODE,
        50000,
        deploy_value,
        block_producer_id,
        block_number,
    );
    // [Deploy SimpleTransfer] used cycles: 491894 -> 500005 < 501K
    helper::check_cycles("Deploy SimpleTransfer", run_result.used_cycles, 501_000);

    block_number += 1;
    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_script_hash = contract_account_script.hash();
    let new_short_address = &new_script_hash[0..20];
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let new_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
        .unwrap();
    assert_eq!(new_balance, deploy_value);

    println!("================");
    println!(
        "from_id={}, new_account_id={}, target_id={}",
        from_id, new_account_id, target_id
    );
    {
        // > transfer to EoA
        // SimpleTransfer.transferTo();
        let old_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap();
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        let input = hex::decode(format!(
            "a03fa7e3{}",
            hex::encode(account_id_to_eth_address(&state, target_id, true)),
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
            .to_id(new_account_id.pack())
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
            )
            .expect("construct");
        // [SimpleTransfer to EoA] used cycles: 725217 < 736K
        helper::check_cycles("SimpleTransfer to EoA", run_result.used_cycles, 736_000);
        state.apply_run_result(&run_result).expect("update state");

        let new_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap();
        assert_eq!(new_balance, old_balance - 1);
        let target_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_address)
            .unwrap();
        assert_eq!(target_balance, 1);
    }

    {
        // > transfer to zero address
        // SimpleTransfer.transferTo(address{0});
        let old_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap();
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        let input = hex::decode(format!(
            "a03fa7e30000000000000000000000000000000000000000000000000000000000000000",
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
            .to_id(new_account_id.pack())
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
            )
            .expect("construct");
        // [SimpleTransfer to zero address] used cycles: 699554 < 710K
        helper::check_cycles(
            "SimpleTransfer to zero address",
            run_result.used_cycles,
            710_000,
        );

        state.apply_run_result(&run_result).expect("update state");

        let new_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap();
        assert_eq!(new_balance, old_balance - 1);

        let zero_account_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &[0u8; 20][..])
            .unwrap();
        assert_eq!(zero_account_balance, 1);
    }

    println!("================");
    {
        // SimpleTransfer.transferToSimpleStorage1();
        let old_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "f10c7360{}",
            hex::encode(contract_script_to_eth_address(&ss_account_script, true)),
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
            .to_id(new_account_id.pack())
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
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
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
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "2a5eb963{}",
            hex::encode(contract_script_to_eth_address(&ss_account_script, true)),
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
            .to_id(new_account_id.pack())
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
            )
            .expect("construct");
        state.apply_run_result(&run_result).expect("update state");

        let new_balance = state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
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
