//! Test contract call contract
//!   See ./evm-contracts/CallContract.sol

use crate::helper::{
    self, compute_create2_script, deploy, new_block_info, new_contract_account_script, setup,
    simple_storage_get, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID,
    L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const CREATE2_IMPL_CODE: &str = include_str!("./evm-contracts/Create2Impl.bin");

#[test]
fn test_create2() {
    let (store, mut state, generator) = setup();
    let block_producer_id = helper::create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address, 2000000);

    // Deploy CREATE2_IMPL_CODE
    let mut block_number = 1;
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        CREATE2_IMPL_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    // [Deploy Create2Impl] used cycles: 819215 < 820K
    helper::check_cycles("Deploy Create2Impl", run_result.used_cycles, 820_000);
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );
    let create2_contract_script =
        new_contract_account_script(&state, from_id, &from_eth_address, false);
    let create2_contract_script_hash = create2_contract_script.hash();
    let create2_contract_id = state
        .get_account_id_by_script_hash(&create2_contract_script_hash.into())
        .unwrap()
        .unwrap();
    println!("create2_contract account id = {}", create2_contract_id);
    let create2_contract_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &create2_contract_script_hash[0..20])
        .unwrap();
    assert_eq!(create2_contract_balance, 0);

    let input_value_u128: u128 = 0x9a;
    // bytes32 salt
    let input_salt = "1111111111111111111111111111111111111111111111111111111111111111";

    // Create2Impl.deploy(uint256 value, bytes32 salt, bytes memory code)
    let run_result = {
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        // uint256 value: 0x000000000000000000000000000000000000000000000000000000000000009a
        let input_value = format!(
            "00000000000000000000000000000000000000000000000000000000000000{:2x}",
            input_value_u128
        );
        let input = hex::decode(format!("66cfa057{}{}00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000101{}00000000000000000000000000000000000000000000000000000000000000", input_value, input_salt, SS_INIT_CODE)).unwrap();

        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(91000)
            .gas_price(1)
            .value(input_value_u128)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(create2_contract_id.pack())
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
            .expect("Create2Impl.deploy(uint256 value, bytes32 salt, bytes memory code)");
        // [Create2Impl.deploy(...)] used cycles: 1197555 < 1230K
        helper::check_cycles("Create2Impl.deploy(...)", run_result.used_cycles, 1230_000);
        state.apply_run_result(&run_result).expect("update state");
        run_result
    };

    let create2_script = compute_create2_script(
        &state,
        create2_contract_id,
        &hex::decode(input_salt).unwrap()[..],
        &hex::decode(SS_INIT_CODE).unwrap()[..],
    );
    let create2_script_hash = create2_script.hash();
    let create2_short_script_hash = &create2_script_hash[0..20];
    println!("create2_address: {}", hex::encode(&run_result.return_data));
    assert_eq!(&run_result.return_data[12..32], create2_short_script_hash);
    let create2_account_id = state
        .get_account_id_by_script_hash(&create2_script_hash.into())
        .unwrap()
        .unwrap();
    let create2_account_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, create2_short_script_hash)
        .unwrap();
    assert_eq!(create2_account_balance, input_value_u128);

    let run_result = simple_storage_get(
        &store,
        &state,
        &generator,
        block_number,
        from_id,
        create2_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("000000000000000000000000000000000000000000000000000000000000007b").unwrap()
    );
}
