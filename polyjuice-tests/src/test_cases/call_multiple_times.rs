//! Test contract call contract multiple times
//!   See ./evm-contracts/CallContract.sol

use crate::helper::{
    build_eth_l2_script, contract_script_to_eth_address, deploy, new_account_script,
    new_account_script_with_nonce, new_block_info, setup, simple_storage_get, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const INIT_CODE: &str = include_str!("./evm-contracts/CallMultipleTimes.bin");

#[test]
fn test_call_multiple_times() {
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
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 280000)
        .unwrap();
    let mut block_number = 1;

    // Deploy two SimpleStorage
    for _ in 0..2 {
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
    }
    let ss1_account_script = new_account_script_with_nonce(&state, creator_account_id, from_id, 0);
    let ss1_account_id = state
        .get_account_id_by_script_hash(&ss1_account_script.hash().into())
        .unwrap()
        .unwrap();
    let ss2_account_script = new_account_script_with_nonce(&state, creator_account_id, from_id, 1);
    let ss2_account_id = state
        .get_account_id_by_script_hash(&ss2_account_script.hash().into())
        .unwrap()
        .unwrap();

    // Deploy CallMultipleTimes
    let input = format!(
        "{}{}",
        INIT_CODE,
        hex::encode(contract_script_to_eth_address(&ss1_account_script, true)),
    );
    let _run_result = deploy(
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
        ss1_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("000000000000000000000000000000000000000000000000000000000000007b").unwrap()
    );
    let run_result = simple_storage_get(
        &store,
        &state,
        &generator,
        block_number,
        from_id,
        ss2_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("000000000000000000000000000000000000000000000000000000000000007b").unwrap()
    );

    assert_eq!(state.get_nonce(from_id).unwrap(), 3);
    assert_eq!(state.get_nonce(ss1_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(ss2_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);

    println!("================");
    {
        // CallMultipleTimes.proxySet(20);
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "bca0b9c2{}{}",
            hex::encode(contract_script_to_eth_address(&ss2_account_script, true)),
            "0000000000000000000000000000000000000000000000000000000000000014",
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
        // println!(
        //     "result {}",
        //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
        // );
    }

    assert_eq!(state.get_nonce(from_id).unwrap(), 4);
    assert_eq!(state.get_nonce(ss1_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(ss2_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);

    let run_result = simple_storage_get(
        &store,
        &state,
        &generator,
        block_number,
        from_id,
        ss1_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("0000000000000000000000000000000000000000000000000000000000000016").unwrap()
    );
    let run_result = simple_storage_get(
        &store,
        &state,
        &generator,
        block_number,
        from_id,
        ss2_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("0000000000000000000000000000000000000000000000000000000000000019").unwrap()
    );
}
