//! Test contract call contract
//!   See ./evm-contracts/CallContract.sol

use crate::helper::{
    self, build_eth_l2_script, compute_create2_script, deploy, new_account_script, new_block_info,
    setup, simple_storage_get, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const CREATE2_IMPL_CODE: &str = include_str!("./evm-contracts/Create2Impl.bin");

#[test]
fn test_create2() {
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
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 2000000)
        .unwrap();
    let mut block_number = 1;

    // Deploy CREATE2_IMPL_CODE
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        CREATE2_IMPL_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    block_number += 1;
    // [Deploy Create2Impl] used cycles: 819215 < 820K
    helper::check_cycles("Deploy Create2Impl", run_result.used_cycles, 820_000);
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );
    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_script_hash = contract_account_script.hash();
    let new_short_address = &new_script_hash[0..20];
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();

    let new_account_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_short_address)
        .unwrap();
    assert_eq!(new_account_balance, 0);

    println!("======================== account id = {}", new_account_id);

    let input_value_u128: u128 = 0x9a;
    let input_salt = "1111111111111111111111111111111111111111111111111111111111111111";
    let run_result = {
        let block_info = new_block_info(0, block_number, block_number);

        // Create2Impl.deploy()
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
        // [Create2Impl.deploy(...)] used cycles: 1197555 < 1230K
        helper::check_cycles("Create2Impl.deploy(...)", run_result.used_cycles, 1230_000);
        state.apply_run_result(&run_result).expect("update state");
        run_result
    };

    let create2_script = compute_create2_script(
        &state,
        creator_account_id,
        new_account_id,
        &hex::decode(input_salt).unwrap()[..],
        &hex::decode(SS_INIT_CODE).unwrap()[..],
    );
    let create2_script_hash = create2_script.hash();
    let create2_short_address = &create2_script_hash[0..20];
    println!("create2_address: {}", hex::encode(&run_result.return_data));
    assert_eq!(&run_result.return_data[12..32], create2_short_address,);
    let create2_account_id = state
        .get_account_id_by_script_hash(&create2_script.hash().into())
        .unwrap()
        .unwrap();

    let create2_account_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, create2_short_address)
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
