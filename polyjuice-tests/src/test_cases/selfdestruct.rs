//! Test SELFDESTRUCT op code
//!   See ./evm-contracts/SelfDestruct.sol

use crate::helper::{
    self, account_id_to_short_script_hash, build_eth_l2_script, new_account_script, new_block_info,
    setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/SelfDestruct.bin");

#[test]
fn test_selfdestruct() {
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

    let beneficiary_script = build_eth_l2_script([2u8; 20]);
    let beneficiary_script_hash = beneficiary_script.hash();
    let beneficiary_short_address = &beneficiary_script_hash[0..20];
    let beneficiary_id = state
        .create_account_from_script(beneficiary_script)
        .unwrap();
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_short_address)
            .unwrap(),
        0
    );

    {
        // Deploy SelfDestruct
        let block_info = new_block_info(0, 1, 0);
        let mut input = hex::decode(INIT_CODE).unwrap();
        input.extend(account_id_to_short_script_hash(
            &state,
            beneficiary_id,
            true,
        ));
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(200)
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
        // [Deploy SelfDestruct] used cycles: 570570 < 580K
        helper::check_cycles("Deploy SelfDestruct", run_result.used_cycles, 580_000);
        state.apply_run_result(&run_result).expect("update state");
    }

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_script_hash = contract_account_script.hash();
    let new_short_address = &new_script_hash[0..20];
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap(),
        200
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_short_address)
            .unwrap(),
        0
    );
    {
        // call SelfDestruct.done();
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode("ae8421e1").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
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
        // [call SelfDestruct.done()] used cycles: 589657 < 600K
        helper::check_cycles("call SelfDestruct.done()", run_result.used_cycles, 600_000);
        state.apply_run_result(&run_result).expect("update state");
    }
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_short_address)
            .unwrap(),
        200
    );

    {
        // call SelfDestruct.done();
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode("ae8421e1").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
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
        let result = generator.execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            &state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
        );
        println!("result {:?}", result);
        assert!(result.is_err());
    }
}
