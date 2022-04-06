//! Test ERC20 contract
//!   See ./evm-contracts/ERC20.bin

use crate::helper::{
    self, deploy, eth_addr_to_ethabi_addr, new_block_info, setup, Account, MockContractInfo,
    PolyjuiceArgsBuilder, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/ERC20.bin");

#[test]
fn test_erc20() {
    let (store, mut state, generator) = setup();
    let block_producer_id = crate::helper::create_block_producer(&mut state);

    let from_eth_address1 = [1u8; 20];
    let (from_id1, _from_script_hash1) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address1, 2000000);

    let from_eth_address2 = [2u8; 20];
    let (_from_id2, _from_script_hash2) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address2, 0);

    let from_eth_address3 = [3u8; 20];
    let (from_id3, _from_script_hash3) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address3, 80000);

    // Deploy ERC20
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id1,
        INIT_CODE,
        122000,
        0,
        block_producer_id,
        1,
    );
    // [Deploy ERC20] used cycles: 1018075 < 1020K
    helper::check_cycles("Deploy ERC20", run_result.used_cycles, 1_400_000);

    let erc20_contract = MockContractInfo::create(&from_eth_address1, 0);
    erc20_contract.mapping_registry_address_to_script_hash(&mut state);
    let erc20_contract_id = state
        .get_account_id_by_script_hash(&erc20_contract.script_hash)
        .unwrap()
        .unwrap();
    let eoa1_hex = hex::encode(eth_addr_to_ethabi_addr(&from_eth_address1));
    let eoa2_hex = hex::encode(eth_addr_to_ethabi_addr(&from_eth_address2));
    let eoa3_hex = hex::encode(eth_addr_to_ethabi_addr(&from_eth_address3));
    for (idx, (operation, from_id, args_str, return_data_str)) in [
        (
            "balanceOf(eoa1) 1",
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e250261100000000",
        ),
        (
            "balanceOf(eoa2) 1",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "transfer(eoa2, 0x22b)",
            from_id1,
            format!(
                "a9059cbb{}000000000000000000000000000000000000000000000000000000000000022b",
                eoa2_hex
            ),
            "",
        ),
        (
            "balanceOf(eoa2) 2",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "000000000000000000000000000000000000000000000000000000000000022b",
        ),
        (
            "transfer(eoa2, 0x219)",
            from_id1,
            format!(
                "a9059cbb{}0000000000000000000000000000000000000000000000000000000000000219",
                eoa2_hex
            ),
            "",
        ),
        (
            "balanceOf(eoa2) 3",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "0000000000000000000000000000000000000000000000000000000000000444",
        ),
        (
            "burn(8908)",
            from_id1,
            "42966c6800000000000000000000000000000000000000000000000000000000000022cc".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "balanceOf(eoa1) 2",
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e2502610ffffd8f0",
        ),
        (
            "approve(eoa3, 0x3e8)",
            from_id1,
            format!(
                "095ea7b3{}00000000000000000000000000000000000000000000000000000000000003e8",
                eoa3_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "transferFrom(eoa1, eoa2, 0x3e8)",
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
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, block_number, block_number);
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
            .to_id(erc20_contract_id.pack())
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
            .expect(&operation);
        // [ERC20 contract method_x] used cycles: 942107 < 960K
        helper::check_cycles("ERC20 contract method_x", run_result.used_cycles, 1_400_000);
        state.apply_run_result(&run_result).expect("update state");
        assert_eq!(
            run_result.return_data,
            hex::decode(return_data_str).unwrap(),
            "return data of {}",
            operation
        );
        // println!(
        //     "result {}",
        //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
        // );
    }
}
