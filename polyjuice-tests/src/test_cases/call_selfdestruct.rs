//! Test call selfdestruct from a contract account
//!   See ./evm-contracts/SelfDestruct.sol

use crate::helper::{
    self, account_id_to_short_script_hash, build_eth_l2_script, contract_script_to_eth_address,
    deploy, new_account_script_with_nonce, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SD_INIT_CODE: &str = include_str!("./evm-contracts/SelfDestruct.bin");
const CALL_SD_INIT_CODE: &str = include_str!("./evm-contracts/CallSelfDestruct.bin");

#[test]
fn test_selfdestruct() {
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
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 400000)
        .unwrap();
    let mut block_number = 1;

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

    // deploy SelfDestruct
    let input = format!(
        "{}{}",
        SD_INIT_CODE,
        hex::encode(account_id_to_short_script_hash(
            &state,
            beneficiary_id,
            true
        ))
    );
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        input.as_str(),
        122000,
        200,
        block_producer_id,
        block_number,
    );
    // 571282 < 580K
    helper::check_cycles("deploy SelfDestruct", run_result.used_cycles, 580_000);

    block_number += 1;
    let sd_account_script = new_account_script_with_nonce(&state, creator_account_id, from_id, 0);
    let sd_script_hash = sd_account_script.hash();
    let sd_short_address = &sd_script_hash[0..20];
    let sd_account_id = state
        .get_account_id_by_script_hash(&sd_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, sd_short_address)
            .unwrap(),
        200
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_short_address)
            .unwrap(),
        0
    );

    // deploy CallSelfDestruct
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        CALL_SD_INIT_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    // [deploy CallSelfDestruct] used cycles: 551984 < 560K
    helper::check_cycles("deploy CallSelfDestruct", run_result.used_cycles, 560_000);

    block_number += 1;
    let new_account_script = new_account_script_with_nonce(&state, creator_account_id, from_id, 1);
    let new_account_id = state
        .get_account_id_by_script_hash(&new_account_script.hash().into())
        .unwrap()
        .unwrap();

    assert_eq!(state.get_nonce(from_id).unwrap(), 2);
    assert_eq!(state.get_nonce(sd_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);

    {
        // call CallSelfDestruct.proxyDone(sd_account_id);
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "9a33d968{}",
            hex::encode(contract_script_to_eth_address(&sd_account_script, true)),
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
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
        // [call CallSelfDestruct.proxyDone(sd_account_id)] used cycles: 1043108 < 1100K
        helper::check_cycles(
            "CallSelfDestruct.proxyDone(sd_account_id)",
            run_result.used_cycles,
            1100_000,
        );
    }

    assert_eq!(state.get_nonce(from_id).unwrap(), 3);
    assert_eq!(state.get_nonce(sd_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(new_account_id).unwrap(), 0);
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, sd_short_address)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_short_address)
            .unwrap(),
        200
    );

    block_number += 1;

    {
        // call SelfDestruct.done();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode("ae8421e1").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(sd_account_id.pack())
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

    {
        // call CallSelfDestruct.proxyDone(sd_account_id);
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "9a33d968{}",
            hex::encode(contract_script_to_eth_address(&sd_account_script, true)),
        ))
        .unwrap();
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
