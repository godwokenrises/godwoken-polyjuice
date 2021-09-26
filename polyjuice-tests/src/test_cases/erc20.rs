//! Test ERC20 contract
//!   See ./evm-contracts/ERC20.bin

use crate::helper::{
    self, account_id_to_eth_address, build_eth_l2_script, deploy, new_account_script,
    new_block_info, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::{constants::L2TX_MAX_CYCLES, traits::StateExt};
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/ERC20.bin");

#[test]
fn test_erc20() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script1 = build_eth_l2_script([1u8; 20]);
    let from_script_hash1 = from_script1.hash();
    let from_short_address1 = &from_script_hash1[0..20];
    let from_id1 = state.create_account_from_script(from_script1).unwrap();

    let from_script2 = build_eth_l2_script([2u8; 20]);
    let from_id2 = state.create_account_from_script(from_script2).unwrap();

    let from_script3 = build_eth_l2_script([3u8; 20]);
    let from_script_hash3 = from_script3.hash();
    let from_short_address3 = &from_script_hash3[0..20];
    let from_id3 = state.create_account_from_script(from_script3).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address1, 2000000)
        .unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address3, 80000)
        .unwrap();

    // Deploy ERC20
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id1,
        INIT_CODE,
        122000,
        0,
        block_producer_id,
        1,
    );
    // [Deploy ERC20] used cycles: 1018075 < 1020K
    helper::check_cycles("Deploy ERC20", run_result.used_cycles, 1_020_000);

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id1, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let is_ethabi = true;
    let eoa1_hex = hex::encode(account_id_to_eth_address(&state, from_id1, is_ethabi));
    let eoa2_hex = hex::encode(account_id_to_eth_address(&state, from_id2, is_ethabi));
    let eoa3_hex = hex::encode(account_id_to_eth_address(&state, from_id3, is_ethabi));
    for (idx, (from_id, args_str, return_data_str)) in [
        // balanceOf(eoa1)
        (
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e250261100000000",
        ),
        // balanceOf(eoa2)
        (
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        // transfer("eoa2", 0x22b)
        (
            from_id1,
            format!(
                "a9059cbb{}000000000000000000000000000000000000000000000000000000000000022b",
                eoa2_hex
            ),
            "",
        ),
        // balanceOf(eoa2)
        (
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "000000000000000000000000000000000000000000000000000000000000022b",
        ),
        // transfer("eoa2", 0x219)
        (
            from_id1,
            format!(
                "a9059cbb{}0000000000000000000000000000000000000000000000000000000000000219",
                eoa2_hex
            ),
            "",
        ),
        // balanceOf(eoa2)
        (
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "0000000000000000000000000000000000000000000000000000000000000444",
        ),
        // burn(8908)
        (
            from_id1,
            "42966c6800000000000000000000000000000000000000000000000000000000000022cc".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // balanceOf(eoa1)
        (
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e2502610ffffd8f0",
        ),
        // approve(eoa3, 0x3e8)
        (
            from_id1,
            format!(
                "095ea7b3{}00000000000000000000000000000000000000000000000000000000000003e8",
                eoa3_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // transferFrom(eoa1, eoa2, 0x3e8)
        (
            from_id3,
            format!(
                "23b872dd{}{}00000000000000000000000000000000000000000000000000000000000003e8",
                eoa1_hex, eoa2_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
    ]
    .iter()
    .enumerate()
    {
        let block_number = 2 + idx as u64;
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
        // [ERC20 contract method_x] used cycles: 942107 < 960K
        helper::check_cycles("ERC20 contract method_x", run_result.used_cycles, 960_000);
        state.apply_run_result(&run_result).expect("update state");
        assert_eq!(
            run_result.return_data,
            hex::decode(return_data_str).unwrap()
        );
        // println!(
        //     "result {}",
        //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
        // );
    }
}
