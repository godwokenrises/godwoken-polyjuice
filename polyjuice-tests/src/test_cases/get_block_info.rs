//! Test get block info
//!   See ./evm-contracts/BlockInfo.sol

use crate::helper::{
    _deprecated_new_account_script, account_id_to_short_script_hash, build_eth_l2_script,
    new_block_info, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID,
    L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_db::schema::COLUMN_INDEX;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_store::traits::kv_store::KVStoreWrite;
use gw_types::{
    bytes::Bytes,
    packed::{RawL2Transaction, Uint64},
    prelude::*,
};

const INIT_CODE: &str = include_str!("./evm-contracts/BlockInfo.bin");

#[test]
fn test_get_block_info() {
    let (store, mut state, generator) = setup();
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    {
        let genesis_number: Uint64 = 0.pack();
        // See: BlockInfo.sol
        let block_hash = [7u8; 32];
        let tx = store.begin_transaction();
        tx.insert_raw(COLUMN_INDEX, genesis_number.as_slice(), &block_hash[..])
            .unwrap();
        tx.commit().unwrap();
        println!("block_hash(0): {:?}", tx.get_block_hash_by_number(0));
    }

    let from_script = build_eth_l2_script(&[1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 400000)
        .unwrap();
    let aggregator_script = build_eth_l2_script(&[2u8; 20]);
    let aggregator_id = state.create_account_from_script(aggregator_script).unwrap();
    assert_eq!(aggregator_id, 5);
    let coinbase_hex = hex::encode(&account_id_to_short_script_hash(
        &state,
        aggregator_id,
        true,
    ));
    println!("coinbase_hex: {}", coinbase_hex);

    // Deploy BlockInfo
    let mut block_number = 0x05;
    let timestamp: u64 = 0xff33 * 1000;
    let block_info = new_block_info(aggregator_id, block_number, timestamp);
    let input = hex::decode(INIT_CODE).unwrap();
    let args = PolyjuiceArgsBuilder::default()
        .do_create(true)
        .gas_limit(160000)
        .gas_price(1)
        .value(0)
        .input(&input)
        .build();
    let raw_tx = RawL2Transaction::new_builder()
        .from_id(from_id.pack())
        .to_id(CREATOR_ACCOUNT_ID.pack())
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
    state.apply_run_result(&run_result).expect("update state");
    block_number += 1;
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );

    let contract_account_script =
        _deprecated_new_account_script(&mut state, CREATOR_ACCOUNT_ID, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(new_account_id, 6);

    for (fn_sighash, expected_return_data) in [
        // getGenesisHash()
        (
            "f6c99388",
            "0707070707070707070707070707070707070707070707070707070707070707",
        ),
        // getDifficulty() => 2500000000000000
        (
            "b6baffe3",
            "0000000000000000000000000000000000000000000000000008e1bc9bf04000",
        ),
        // getGasLimit()
        (
            "1a93d1c3",
            "0000000000000000000000000000000000000000000000000000000000bebc20",
        ),
        // getNumber()
        (
            "f2c9ecd8",
            "0000000000000000000000000000000000000000000000000000000000000005",
        ),
        // getTimestamp()
        (
            "188ec356",
            "000000000000000000000000000000000000000000000000000000000000ff33",
        ),
        // getCoinbase()
        ("d1a82a9d", coinbase_hex.as_str()),
    ]
    .iter()
    {
        let block_info = new_block_info(aggregator_id, block_number + 1, timestamp + 1);
        let input = hex::decode(fn_sighash).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(21000)
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
        assert_eq!(
            run_result.return_data,
            hex::decode(expected_return_data).unwrap()
        );
    }
}
