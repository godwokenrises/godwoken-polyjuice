//! Test Recursion Contract
//!   See ./evm-contracts/RecursionContract.sol

use crate::helper::{
    build_eth_l2_script, deploy, new_account_script,
    new_block_info, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::{error::TransactionError, traits::StateExt};
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const RECURSION_INIT_CODE: &str = include_str!("./evm-contracts/RecursionContract.bin");

#[test]
fn test_recursion_contract_call() {
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

    // Deploy RecursionContract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        RECURSION_INIT_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    block_number += 1;
    let recur_account_script = new_account_script(&mut state, creator_account_id, from_id, false);
    let recur_account_id = state
        .get_account_id_by_script_hash(&recur_account_script.hash().into())
        .unwrap()
        .unwrap();

    {// Call Sum(31), 31 < max_depth=32
        let block_info = new_block_info(0, block_number, block_number);
        let input =
            hex::decode("188b85b4000000000000000000000000000000000000000000000000000000000000001f").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(200000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(recur_account_id.pack())
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
            .expect("recursive call depth to 32");
        state.apply_run_result(&run_result).expect("update state");
        println!(
            "\t call result {:?}", run_result.return_data
        );
        let expected_sum = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 240];
        assert_eq!(run_result.return_data, expected_sum);
    }

    {// EVMC_CALL_DEPTH_EXCEEDED Case 
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        let input =
            hex::decode("188b85b40000000000000000000000000000000000000000000000000000000000000020").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(200000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(recur_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let err = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
            )
            .expect_err("EVMC_CALL_DEPTH_EXCEEDED = -52");
        assert_eq!(err, TransactionError::InvalidExitCode(-52));
    }

    {// Case: out of gas and revert
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        let input =
            hex::decode("188b85b40000000000000000000000000000000000000000000000000000000000000020").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(50000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(recur_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let err = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
            )
            .expect_err("EVMC_REVERT = 2");
        assert_eq!(err, TransactionError::InvalidExitCode(2));
    }

    {// Case: out of gas and no revert
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        let input =
            hex::decode("188b85b40000000000000000000000000000000000000000000000000000000000000020").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(4100)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(recur_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let err = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
            )
            .expect_err("EVMC_OUT_OF_GAS = 3");
        assert_eq!(err, TransactionError::InvalidExitCode(3));
    }
}
