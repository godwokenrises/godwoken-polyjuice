//! Test SimpleStorage
//!   See ./evm-contracts/SimpleStorage.sol

use crate::helper::{
    build_eth_l2_script, new_account_script, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");

#[test]
fn test_simple_storage() {
    let (store, mut state, generator, creator_account_id) = setup();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 200000)
        .unwrap();

    let from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_id)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance1);
    {
        // Deploy SimpleStorage
        let block_info = new_block_info(0, 1, 0);
        let input = hex::decode(INIT_CODE).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(creator_account_id.pack())
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
        // println!("result {:?}", run_result);
        println!("return_data: {}", hex::encode(&run_result.return_data[..]));
    }

    let contract_account_script = new_account_script(&mut state, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let from_balance2 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_id)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance2);
    {
        // SimpleStorage.set(0x0d10);
        let block_info = new_block_info(0, 2, 0);
        let input =
            hex::decode("60fe47b10000000000000000000000000000000000000000000000000000000000000d10")
                .unwrap();
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
        // println!("result {:?}", run_result);
    }

    {
        // SimpleStorage.get();
        let block_info = new_block_info(0, 3, 0);
        let input = hex::decode("6d4ce63c").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .static_call(true)
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
        let mut expected_return_data = vec![0u8; 32];
        expected_return_data[30] = 0x0d;
        expected_return_data[31] = 0x10;
        assert_eq!(run_result.return_data, expected_return_data);
        // println!("result {:?}", run_result);
    }
}
