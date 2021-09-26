//! Test FallbackFunction
//!   See ./evm-contracts/FallbackFunction.sol

use crate::helper::{
    self, build_eth_l2_script, new_account_script, new_block_info, setup, simple_storage_get,
    PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::{constants::L2TX_MAX_CYCLES, traits::StateExt};
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/FallbackFunction.bin");

#[test]
fn test_fallback_function() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 200000)
        .unwrap();

    {
        // Deploy FallbackFunction Contract
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
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        // [Deploy FallbackFunction] used cycles: 587271 < 590K
        helper::check_cycles("Deploy FallbackFunction", run_result.used_cycles, 590_000);
        state.apply_run_result(&run_result).expect("update state");
    }

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let run_result = simple_storage_get(&store, &state, &generator, 0, from_id, new_account_id);
    assert_eq!(
        run_result.return_data,
        hex::decode("000000000000000000000000000000000000000000000000000000000000007b").unwrap()
    );

    {
        // Call fallback()
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode("3333").unwrap();
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
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        // [Call fallback()] used cycles: 504210 < 510K
        helper::check_cycles("Call fallback()", run_result.used_cycles, 510_000);
        assert!(run_result.return_data.is_empty());
        state.apply_run_result(&run_result).expect("update state");
    }

    let run_result = simple_storage_get(&store, &state, &generator, 0, from_id, new_account_id);
    assert_eq!(
        run_result.return_data,
        hex::decode("00000000000000000000000000000000000000000000000000000000000003e7").unwrap()
    );
}
