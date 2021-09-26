//! Test contract call contract
//!   See ./evm-contracts/CallContract.sol

use crate::helper::{
    self, build_eth_l2_script, contract_script_to_eth_address, deploy, new_account_script,
    new_block_info, setup, simple_storage_get, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::{constants::L2TX_MAX_CYCLES, traits::StateExt};
// use gw_jsonrpc_types::parameter::RunResult;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const INIT_CODE: &str = include_str!("./evm-contracts/CallContract.bin");
const CALL_NON_EXISTS_INIT_CODE: &str = include_str!("./evm-contracts/CallNonExistsContract.bin");

#[test]
fn test_contract_call_contract() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 200000)
        .unwrap();
    let mut block_number = 1;

    // Deploy SimpleStorage
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        SS_INIT_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    block_number += 1;
    let ss_account_script = new_account_script(&mut state, creator_account_id, from_id, false);
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();

    // Deploy CreateContract
    let input = format!(
        "{}{}",
        INIT_CODE,
        hex::encode(contract_script_to_eth_address(&ss_account_script, true)),
    );
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        input.as_str(),
        122000,
        0,
        block_producer_id,
        block_number,
    );
    block_number += 1;
    // [Deploy CreateContract] used cycles: 600288 < 610K
    helper::check_cycles("Deploy CreateContract", run_result.used_cycles, 610_000);

    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );
    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();

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

    {
        // CallContract.proxySet(222); => SimpleStorage.set(x+3)
        let block_info = new_block_info(0, block_number, block_number);
        let input =
            hex::decode("28cc7b2500000000000000000000000000000000000000000000000000000000000000de")
                .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(51000)
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
        // [CallContract.proxySet(222)] used cycles: 961599 < 970K
        helper::check_cycles("CallContract.proxySet()", run_result.used_cycles, 970_000);
    }

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
        hex::decode("00000000000000000000000000000000000000000000000000000000000000e1").unwrap()
    );

    assert_eq!(state.get_nonce(from_id).unwrap(), 3);
    assert_eq!(state.get_nonce(ss_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);
}

#[test]
fn test_contract_call_non_exists_contract() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 200000)
        .unwrap();
    let block_number = 1;

    // Deploy CallNonExistsContract
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        CALL_NON_EXISTS_INIT_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    // [Deploy CallNonExistsContract] used cycles: 657243 < 670K
    helper::check_cycles(
        "Deploy CallNonExistsContract",
        run_result.used_cycles,
        670_000,
    );

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    {
        // Call CallNonExistsContract.rawCall(addr)
        let block_info = new_block_info(0, block_number, block_number);
        let input =
            hex::decode("56c94e70000000000000000000000000000000000fffffffffffffffffffffffffffffff")
                .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(51000)
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
        // [CallNonExistsContract.rawCall(addr)] used cycles: 862060 < 870K
        helper::check_cycles(
            "CallNonExistsContract.rawCall(addr)",
            run_result.used_cycles,
            870_000,
        );

        assert_eq!(
            run_result.return_data,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
