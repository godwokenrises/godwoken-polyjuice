//! Test ERC20 contract
//!   See ./evm-contracts/ERC20.bin

use crate::helper::{
    self, _deprecated_new_contract_account_script, account_id_to_short_script_hash,
    build_eth_l2_script, build_l2_sudt_script, deploy, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::{error::TransactionError, traits::StateExt};
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INVALID_SUDT_ERC20_PROXY_CODE: &str =
    include_str!("./evm-contracts/InvalidSudtERC20Proxy.bin");

#[test]
fn test_invalid_sudt_erc20_proxy() {
    let (store, mut state, generator) = setup();
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let new_sudt_script = build_l2_sudt_script([0xffu8; 32]);
    let new_sudt_id = state.create_account_from_script(new_sudt_script).unwrap();

    let from_script1 = build_eth_l2_script(&[1u8; 20]);
    let from_script_hash1 = from_script1.hash();
    let from_short_address1 = &from_script_hash1[0..20];
    let from_id1 = state.create_account_from_script(from_script1).unwrap();

    let from_script2 = build_eth_l2_script(&[2u8; 20]);
    let from_script_hash2 = from_script2.hash();
    let from_short_address2 = &from_script_hash2[0..20];
    let from_id2 = state.create_account_from_script(from_script2).unwrap();

    let from_script3 = build_eth_l2_script(&[3u8; 20]);
    let from_script_hash3 = from_script3.hash();
    let from_short_address3 = &from_script_hash3[0..20];
    let from_id3 = state.create_account_from_script(from_script3).unwrap();

    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address1, 2000000)
        .unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address2, 2000000)
        .unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address3, 2000000)
        .unwrap();
    assert_eq!(CKB_SUDT_ACCOUNT_ID, 1);
    // Deploy InvalidSudtERC20Proxy
    // ethabi encode params -v string "test" -v string "tt" -v uint256 000000000000000000000000000000000000000204fce5e3e250261100000000 -v uint256 0000000000000000000000000000000000000000000000000000000000000001
    let mut block_number = 0;
    let args = format!("000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000204fce5e3e25026110000000000000000000000000000000000000000000000000000000000000000000000{:02x}0000000000000000000000000000000000000000000000000000000000000004746573740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027474000000000000000000000000000000000000000000000000000000000000", new_sudt_id);
    let init_code = format!("{}{}", INVALID_SUDT_ERC20_PROXY_CODE, args);
    block_number += 1;
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id1,
        init_code.as_str(),
        122000,
        0,
        block_producer_id,
        block_number,
    );
    // [Deploy InvalidSudtERC20Proxy] used cycles: 1457382 < 1460K
    helper::check_cycles(
        "Deploy InvalidSudtERC20Proxy",
        run_result.used_cycles,
        1_460_000,
    );
    let contract_account_script =
        _deprecated_new_contract_account_script(&mut state, CREATOR_ACCOUNT_ID, from_id1, false);
    let invalid_proxy_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let is_ethabi = true;
    let eoa1_hex = hex::encode(account_id_to_short_script_hash(&state, from_id1, is_ethabi));
    let eoa2_hex = hex::encode(account_id_to_short_script_hash(&state, from_id2, is_ethabi));
    let eoa3_hex = hex::encode(account_id_to_short_script_hash(&state, from_id3, is_ethabi));
    println!("eoa1_hex: {}", eoa1_hex);
    println!("eoa2_hex: {}", eoa2_hex);
    println!("eoa3_hex: {}", eoa3_hex);
    state
        .mint_sudt(
            new_sudt_id,
            from_short_address1,
            160000000000000000000000000000u128,
        )
        .unwrap();

    assert_eq!(
        state
            .get_sudt_balance(new_sudt_id, from_short_address1)
            .unwrap(),
        160000000000000000000000000000u128
    );
    assert_eq!(
        state
            .get_sudt_balance(new_sudt_id, from_short_address2)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .get_sudt_balance(new_sudt_id, from_short_address3)
            .unwrap(),
        0
    );
    for (_idx, (from_id, args_str, success, return_data_str)) in [
        // balanceOf(eoa1)
        (
            from_id1,
            format!("70a08231{}", eoa1_hex),
            true,
            "000000000000000000000000000000000000000204fce5e3e250261100000000",
        ),
        // balanceOf(eoa2)
        (
            from_id1,
            format!("70a08231{}", eoa2_hex),
            true,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        // transfer("eoa2", 0x22b)
        (
            from_id1,
            format!(
                "a9059cbb{}000000000000000000000000000000000000000000000000000000000000022b",
                eoa2_hex
            ),
            false,
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
    ]
    .iter()
    .enumerate()
    {
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(80000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(invalid_proxy_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let result = generator.execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            &state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
            None,
        );

        if *success {
            let run_result = result.expect("execute");
            // used cycles: 844202 < 870K
            helper::check_cycles(
                "ERC20.{balanceOf|transfer}",
                run_result.used_cycles,
                870_000,
            );
            state.apply_run_result(&run_result).expect("update state");
            assert_eq!(
                run_result.return_data,
                hex::decode(return_data_str).unwrap()
            );
        } else if let Err(err) = result {
            // [contract debug]: The contract is not allowed to call transfer_to_any_sudt
            // ERROR_TRANSFER_TO_ANY_SUDT -31
            // by: revert(0, 0)
            assert_eq!(err, TransactionError::InvalidExitCode(2));
        } else {
            unreachable!();
        }
        // println!(
        //     "result {}",
        //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
        // );
    }
}
