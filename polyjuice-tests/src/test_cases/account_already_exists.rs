//! Test simple transfer
//!   See ./evm-contracts/SimpleTransfer.sol

use crate::helper::{
    account_id_to_eth_address, deploy, new_account_script, new_account_script_with_nonce,
    new_block_info, parse_log, setup, simple_storage_get, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_jsonrpc_types::parameter::RunResult;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");

#[test]
fn test_account_already_exists() {
    let (store, mut tree, generator, creator_account_id) = setup();

    let from_script = gw_generator::sudt::build_l2_sudt_script([1u8; 32].into());
    let from_id = tree.create_account_from_script(from_script).unwrap();
    let mint_balance: u128 = 400000;
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, mint_balance)
        .unwrap();

    let created_ss_account_script = new_account_script_with_nonce(from_id, 0);
    let created_ss_account_id = tree
        .create_account_from_script(created_ss_account_script)
        .unwrap();

    // Deploy SimpleStorage
    let run_result = deploy(
        &generator,
        &store,
        &mut tree,
        creator_account_id,
        from_id,
        SS_INIT_CODE,
        50000,
        0,
        0,
    );
    let ss_account_script = new_account_script(&mut tree, from_id, false);
    let ss_account_id = tree
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(created_ss_account_id, ss_account_id);
}
