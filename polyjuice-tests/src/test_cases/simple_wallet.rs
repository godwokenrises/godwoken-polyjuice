//! Deploy muti-sign-wallet Contract
//!   See https://github.com/Flouse/godwoken-examples/blob/contracts/packages/polyjuice/contracts/WalletSimple.sol/WalletSimple.json

use crate::helper::{self, CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID};
use gw_common::state::State;
use gw_generator::traits::StateExt;

const BIN_CODE: &str = include_str!("./evm-contracts/SimpleWallet.bin");

#[test]
fn test_simple_wallet() {
    let (store, mut state, generator) = helper::setup();
    let block_producer_script = helper::build_eth_l2_script(&[0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = helper::build_eth_l2_script(&[1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 20000000)
        .unwrap();
    let mut block_number = 0;

    // Deploy SimpleWallet Contract
    block_number += 1;
    let run_result = helper::deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        BIN_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    // [Deploy SimpleWallet Contract] used cycles: 1803600 < 1810K
    helper::check_cycles("Deploy SimpleWallet", run_result.used_cycles, 1_810_000);

    let account_script = helper::_deprecated_new_contract_account_script(
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        false,
    );
    let _contract_account_id = state
        .get_account_id_by_script_hash(&account_script.hash().into())
        .unwrap()
        .unwrap();
}
