//! Test Recursion Contract
//!   See ./evm-contracts/Memory.sol

use crate::helper::{
    build_eth_l2_script, deploy, new_account_script, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID,
};

use gw_common::state::State;
use gw_generator::{traits::StateExt}; // error::TransactionError, 
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const MEMORY_INIT_CODE: &str = include_str!("./evm-contracts/Memory.bin");

#[test]
fn test_heap_momory() {
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
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 20000000)
        .unwrap();
    let mut block_number = 1;

    // Deploy Memory Contract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        MEMORY_INIT_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    let account_script = new_account_script(&mut state, creator_account_id, from_id, false);
    let contract_account_id = state
        .get_account_id_by_script_hash(&account_script.hash().into())
        .unwrap()
        .unwrap();

    {
        // newMemory less than 512K
        let call_code = format!("4e688844{:064x}", 1024 * 15); // < 16 * 32 = 512
        println!("{}", call_code);
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(call_code).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(20000000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_account_id.pack())
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
            .expect("success to malloc memory");
        println!(
            "\t new byte(about {}K) => call result {:?}",
            16 * 32,
            run_result.return_data
        );
    }

    {
        // newMemory more than 512K
        let call_code = format!("4e688844{:064x}", 1024 * 16 + 1);
        println!("{}", call_code);
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(call_code).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(20000000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_account_id.pack())
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
            .expect_err("OOM");
        println!("{:?}", err);
        // assert_eq!(err, TransactionError::VM(InvalidEcall(64)));
    }

    // for k_bytes in 10..17 {
    //     let call_code = format!("4e688844{:064x}", 1024 * k_bytes);
    //     println!("{}", call_code);
    //     block_number += 1;
    //     let block_info = new_block_info(0, block_number, block_number);
    //     let input = hex::decode(call_code).unwrap();
    //     let args = PolyjuiceArgsBuilder::default()
    //         .gas_limit(20000000)
    //         .gas_price(1)
    //         .value(0)
    //         .input(&input)
    //         .build();
    //     let raw_tx = RawL2Transaction::new_builder()
    //         .from_id(from_id.pack())
    //         .to_id(contract_account_id.pack())
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
    //         )
    //         .expect("success to malloc memory");
    //     println!(
    //         "\t new byte({}K) => call result {:?}",
    //         k_bytes, run_result.return_data
    //     );
    // }
}
