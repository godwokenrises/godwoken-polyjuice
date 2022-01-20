//! Test simple transfer
//!   See ./evm-contracts/SimpleTransfer.sol

use crate::helper::{
    _deprecated_new_account_script, _deprecated_new_account_script_with_nonce, build_eth_l2_script,
    deploy, register_eoa_account, setup, CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");

#[test]
fn test_account_already_exists() {
    let (store, mut state, generator) = setup();
    let block_producer_id = crate::helper::create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let from_script = build_eth_l2_script(&from_eth_address);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    register_eoa_account(&mut state, &from_eth_address, &from_script_hash);

    let mint_balance: u128 = 400000;
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, mint_balance)
        .unwrap();

    let created_ss_account_script =
        _deprecated_new_account_script_with_nonce(&state, CREATOR_ACCOUNT_ID, from_id, 0);
    let created_ss_account_id = state
        .create_account_from_script(created_ss_account_script)
        .unwrap();

    // Deploy SimpleStorage
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        SS_INIT_CODE,
        50000,
        0,
        block_producer_id,
        0,
    );
    let ss_account_script =
        _deprecated_new_account_script(&mut state, CREATOR_ACCOUNT_ID, from_id, false);
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(created_ss_account_id, ss_account_id);
}
