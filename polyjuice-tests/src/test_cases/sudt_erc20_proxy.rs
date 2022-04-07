//! Test ERC20 contract
//!   See ./evm-contracts/ERC20.bin

use crate::helper::{
    account_id_to_eth_address, build_eth_l2_script, build_l2_sudt_script, deploy,
    new_account_script, new_block_info, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
    FATAL_PRECOMPILED_CONTRACTS, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::{dummy_state::DummyState, error::TransactionError, traits::StateExt, Generator};
use gw_store::traits::chain_store::ChainStore;
use gw_store::{chain_view::ChainView, Store};
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SUDT_ERC20_PROXY_CODE: &str = include_str!("../../../solidity/erc20/SudtERC20Proxy.bin");
const SUDT_ERC20_PROXY_USER_DEFINED_DECIMALS_CODE: &str =
    include_str!("../../../solidity/erc20/SudtERC20Proxy_UserDefinedDecimals.bin");

fn test_sudt_erc20_proxy_inner(
    generator: &Generator,
    store: &Store,
    state: &mut DummyState,
    creator_account_id: u32,
    new_sudt_id: u32,
    block_producer_id: u32,
    decimals: Option<u8>,
) -> Result<(), TransactionError> {
    let from_script1 = build_eth_l2_script([1u8; 20]);
    let from_script_hash1 = from_script1.hash();
    let from_short_address1 = &from_script_hash1[0..20];
    let from_id1 = state.create_account_from_script(from_script1).unwrap();

    let from_script2 = build_eth_l2_script([2u8; 20]);
    let from_script_hash2 = from_script2.hash();
    let from_short_address2 = &from_script_hash2[0..20];
    let from_id2 = state.create_account_from_script(from_script2).unwrap();

    let from_script3 = build_eth_l2_script([3u8; 20]);
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

    // Deploy sUDT ERC20 Proxy
    match decimals {
        None => {
            // ethabi encode params -v string "test" -v string "tt" -v uint256 000000000000000000000000000000000000000204fce5e3e250261100000000 -v uint256 0000000000000000000000000000000000000000000000000000000000000001
            let args = format!("000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000204fce5e3e25026110000000000000000000000000000000000000000000000000000000000000000000000{:02x}0000000000000000000000000000000000000000000000000000000000000004746573740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027474000000000000000000000000000000000000000000000000000000000000", new_sudt_id);
            let init_code = format!("{}{}", SUDT_ERC20_PROXY_CODE, args);
            let _run_result = deploy(
                &generator,
                &store,
                state,
                creator_account_id,
                from_id1,
                init_code.as_str(),
                122000,
                0,
                block_producer_id,
                1,
            );
            print!("SudtERC20Proxy.ContractCode.hex: 0x");
            for byte in _run_result.return_data {
                print!("{:02x}", byte);
            }
            println!();
        }
        Some(decimals) => {
            // Deploy SudtERC20Proxy_UserDefinedDecimals
            // encodeDeploy(["erc20_decimals", "DEC", BigNumber.from(9876543210), 1, 8])
            // => 0x00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000024cb016ea00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e65726332305f646563696d616c7300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034445430000000000000000000000000000000000000000000000000000000000
            let args = format!("00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000024cb016ea00000000000000000000000000000000000000000000000000000000000000{:02x}00000000000000000000000000000000000000000000000000000000000000{:02x}000000000000000000000000000000000000000000000000000000000000000e65726332305f646563696d616c7300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034445430000000000000000000000000000000000000000000000000000000000", new_sudt_id, decimals);
            let init_code = format!("{}{}", SUDT_ERC20_PROXY_USER_DEFINED_DECIMALS_CODE, args);
            let _run_result = deploy(
                &generator,
                &store,
                state,
                creator_account_id,
                from_id1,
                init_code.as_str(),
                122000,
                0,
                block_producer_id,
                1,
            );
            print!("SudtERC20Proxy_UserDefinedDecimals.ContractCode.hex: 0x");
            for byte in _run_result.return_data {
                print!("{:02x}", byte);
            }
            println!();
        }
    }

    let contract_account_script = new_account_script(state, creator_account_id, from_id1, false);
    let script_hash = contract_account_script.hash().into();
    let new_account_id = state
        .get_account_id_by_script_hash(&script_hash)
        .unwrap()
        .unwrap();
    let is_ethabi = true;
    let eoa1_hex = hex::encode(account_id_to_eth_address(state, from_id1, is_ethabi));
    let eoa2_hex = hex::encode(account_id_to_eth_address(state, from_id2, is_ethabi));
    let eoa3_hex = hex::encode(account_id_to_eth_address(state, from_id3, is_ethabi));
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
    for (idx, (action, from_id, args_str, return_data_str)) in [
        // balanceOf(eoa1)
        (
            "balanceOf(eoa1)",
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e250261100000000",
        ),
        //
        (
            "balanceOf(eoa2)",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        // transfer("eoa2", 0x22b)
        (
            "transfer(eoa2, 0x22b)",
            from_id1,
            format!(
                "a9059cbb{}000000000000000000000000000000000000000000000000000000000000022b",
                eoa2_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // balanceOf(eoa2)
        (
            "balanceOf(eoa2)",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "000000000000000000000000000000000000000000000000000000000000022b",
        ),
        // transfer("eoa2", 0x219)
        (
            "transfer(eoa2, 0x219)",
            from_id1,
            format!(
                "a9059cbb{}0000000000000000000000000000000000000000000000000000000000000219",
                eoa2_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        //// === Transfer to self ====
        // transfer("eoa1", 0x0)
        (
            "transfer(eoa1, 0x0)",
            from_id1,
            format!(
                "a9059cbb{}0000000000000000000000000000000000000000000000000000000000000000",
                eoa1_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // transfer("eoa1", 0x219)
        (
            "transfer(eoa1, 0x219)",
            from_id1,
            format!(
                "a9059cbb{}0000000000000000000000000000000000000000000000000000000000000219",
                eoa1_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // balanceOf(eoa2)
        (
            "balanceOf(eoa2)",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "0000000000000000000000000000000000000000000000000000000000000444",
        ),
        // balanceOf(eoa1)
        (
            "balanceOf(eoa1)",
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e2502610fffffbbc",
        ),
        // approve(eoa3, 0x3e8)
        (
            "approve(eoa3, 0x3e8)",
            from_id1,
            format!(
                "095ea7b3{}00000000000000000000000000000000000000000000000000000000000003e8",
                eoa3_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // transferFrom(eoa1, eoa2, 0x3e8)
        (
            "transferFrom(eoa1, eoa2, 0x3e8)",
            from_id3,
            format!(
                "23b872dd{}{}00000000000000000000000000000000000000000000000000000000000003e8",
                eoa1_hex, eoa2_hex
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // balanceOf(eoa1)
        (
            "balanceOf(eoa1)",
            from_id1,
            format!("70a08231{}", eoa1_hex),
            "000000000000000000000000000000000000000204fce5e3e2502610fffff7d4",
        ),
        // balanceOf(eoa2)
        (
            "balanceOf(eoa2)",
            from_id1,
            format!("70a08231{}", eoa2_hex),
            "000000000000000000000000000000000000000000000000000000000000082c",
        ),
        // decimals()
        (
            "decimals()",
            from_id1,
            "313ce567".to_string(),
            &format!(
                "00000000000000000000000000000000000000000000000000000000000000{:02x}",
                decimals.unwrap_or(18)
            ),
        ),
    ]
    .iter()
    .enumerate()
    {
        let block_number = 2 + idx as u64;
        let block_info = new_block_info(block_producer_id, block_number, block_number);
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
        let t = std::time::Instant::now();
        let run_result = generator.execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
            None,
        )?;
        println!(
            "[execute_transaction] {} {}ms",
            action,
            t.elapsed().as_millis()
        );
        println!("used_cycles: {}", run_result.used_cycles);
        println!("write_values.len: {}", run_result.write_values.len());
        state.apply_run_result(&run_result).expect("update state");
        assert_eq!(
            run_result.return_data,
            hex::decode(return_data_str).unwrap()
        );
    }

    // from_id1 transfer to from_id2, invalid amount value
    {
        let args_str = format!(
            "a9059cbb{}000000000000000000000000fff00000ffffffffffffffffffffffffffffffff",
            eoa2_hex
        );
        let block_number = 80;
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(80000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id1.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let err = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect_err("err");
        // by: `revert(0, 0)`
        assert_eq!(err, TransactionError::InvalidExitCode(2));
    }

    // transfer to self insufficient balance
    {
        let args_str = format!(
            "a9059cbb{}00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
            eoa1_hex
        );
        let block_number = 80;
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(80000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id1.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let err = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect_err("err");
        // by: `revert(0, 0)`
        assert_eq!(err, TransactionError::InvalidExitCode(2));
    }
    Ok(())
}

#[test]
fn test_sudt_erc20_proxy_user_defined_decimals() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();
    let new_sudt_script = build_l2_sudt_script([0xffu8; 32]);
    let new_sudt_id = state.create_account_from_script(new_sudt_script).unwrap();

    assert_eq!(
        test_sudt_erc20_proxy_inner(
            &generator,
            &store,
            &mut state,
            creator_account_id,
            new_sudt_id,
            block_producer_id,
            Some(8)
        ),
        Ok(())
    );
}

#[test]
fn test_sudt_erc20_proxy() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let new_sudt_script = build_l2_sudt_script([0xffu8; 32]);
    let new_sudt_id = state.create_account_from_script(new_sudt_script).unwrap();

    assert_eq!(CKB_SUDT_ACCOUNT_ID, 1);

    assert_eq!(
        test_sudt_erc20_proxy_inner(
            &generator,
            &store,
            &mut state,
            creator_account_id,
            new_sudt_id,
            block_producer_id,
            None
        ),
        Ok(())
    );
}

#[test]
fn test_error_sudt_id_sudt_erc20_proxy() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let error_new_sudt_script = build_eth_l2_script([0xffu8; 20]);
    let error_new_sudt_id = state
        .create_account_from_script(error_new_sudt_script)
        .unwrap();

    assert_eq!(CKB_SUDT_ACCOUNT_ID, 1);
    assert_eq!(
        test_sudt_erc20_proxy_inner(
            &generator,
            &store,
            &mut state,
            creator_account_id,
            error_new_sudt_id,
            block_producer_id,
            None
        ),
        Err(TransactionError::InvalidExitCode(
            FATAL_PRECOMPILED_CONTRACTS
        ))
    );
}
