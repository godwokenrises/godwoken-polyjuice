//! Test simple transfer
//!   See ./evm-contracts/SimpleTransfer.sol

use crate::helper::{
    build_eth_l2_script, deploy, new_account_script, new_account_script_with_nonce, setup,
    CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");

#[test]
fn test_account_already_exists() {
    let (store, mut state, generator, creator_account_id) = setup();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_id = state.create_account_from_script(from_script).unwrap();
    let mint_balance: u128 = 400000;
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, mint_balance)
        .unwrap();

    let created_ss_account_script = new_account_script_with_nonce(from_id, 0);
    let created_ss_account_id = state
        .create_account_from_script(created_ss_account_script)
        .unwrap();

    // Deploy SimpleStorage
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        SS_INIT_CODE,
        50000,
        0,
        0,
    );
    let ss_account_script = new_account_script(&mut state, from_id, false);
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(created_ss_account_id, ss_account_id);
}
