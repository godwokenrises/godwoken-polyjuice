//! Test contract call contract multiple times
//!   See ./evm-contracts/CallContract.sol

use crate::helper::{
    account_id_to_eth_address, build_eth_l2_script, deploy, new_account_script,
    new_account_script_with_nonce, new_block_info, setup, simple_storage_get, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
// use gw_jsonrpc_types::parameter::RunResult;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const INIT_CODE: &str = include_str!("./evm-contracts/DelegateCall.bin");

#[test]
fn test_delegatecall() {
    let (store, mut state, generator, creator_account_id) = setup();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 280000)
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
        block_number,
    );
    block_number += 1;
    let ss_account_script = new_account_script_with_nonce(creator_account_id, from_id, 0);
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();

    // Deploy DelegateCall
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        INIT_CODE,
        122000,
        0,
        block_number,
    );
    block_number += 1;
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

    assert_eq!(state.get_nonce(from_id).unwrap(), 2);
    assert_eq!(state.get_nonce(ss_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);

    for (fn_sighash, expected_return_value) in [
        // DelegateCall.set(address, uint)
        (
            "3825d828",
            "0000000000000000000000000000000000000000000000000000000000000022",
        ),
        // DelegateCall.overwrite(address, uint)
        (
            "3144564b",
            "0000000000000000000000000000000000000000000000000000000000000023",
        ),
        // DelegateCall.multiCall(address, uint)
        (
            "c6c211e9",
            "0000000000000000000000000000000000000000000000000000000000000024",
        ),
    ]
    .iter()
    {
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "{}{}{}",
            fn_sighash,
            hex::encode(&account_id_to_eth_address(&state, ss_account_id, true)),
            "0000000000000000000000000000000000000000000000000000000000000022",
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(200000)
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
            )
            .expect("construct");
        state.apply_run_result(&run_result).expect("update state");
        // println!(
        //     "result {}",
        //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
        // );
        let run_result = simple_storage_get(
            &store,
            &state,
            &generator,
            block_number,
            from_id,
            new_account_id,
        );
        assert_eq!(
            run_result.return_data,
            hex::decode(expected_return_value).unwrap()
        );
    }

    assert_eq!(state.get_nonce(from_id).unwrap(), 5);
    assert_eq!(state.get_nonce(ss_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);

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
}
