//! Test contract create contract
//!   See ./evm-contracts/CreateContract.sol

use crate::helper::{
    deploy,
    new_account_script_with_nonce,
    account_id_to_eth_address, new_account_script, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_jsonrpc_types::parameter::RunResult;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/CreateContract.bin");

#[test]
fn test_contract_create_contract() {
    let (mut tree, generator, creator_account_id) = setup();

    let from_script = gw_generator::sudt::build_l2_sudt_script([1u8; 32].into());
    let from_id = tree.create_account_from_script(from_script).unwrap();
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 200000)
        .unwrap();

    // Deploy CreateContract
    let run_result = deploy(
        &generator,
        &mut tree,
        creator_account_id,
        from_id,
        INIT_CODE,
        122000,
        0,
        1,
    );
    println!(
        "result {}",
        serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    );

    let contract_account_script = new_account_script(&mut tree, from_id, false);
    let new_account_id = tree
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(new_account_id, 4);
    let contract_account_nonce = tree.get_nonce(new_account_id).unwrap();
    // 1 => new SimpleStorage()
    // 2 => ss.get()
    // 3 => ss.set(value + 132)
    assert_eq!(contract_account_nonce, 3);
    let ss_account_script = new_account_script_with_nonce(&mut tree, new_account_id, 0);
    let ss_account_id = tree
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
}
