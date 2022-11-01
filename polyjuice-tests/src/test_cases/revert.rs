//! Test Revert contract
//!   See ./evm-contracts/revert/*

use std::{
    env,
    fs::{self},
};

use crate::helper::{
    self, deploy, new_block_info, print_gas_used, setup, MockContractInfo, PolyjuiceArgsBuilder,
    CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};
use serde_json;

#[test]
fn test_revert_with_try_catch() {
    let (
        mut state,
        store,
        generator,
        from_id,
        _from_eth_address,
        block_producer_id,
        revert_contract,
        revert_contract_id,
        call_revert_with_try_catch_contract,
        call_revert_with_try_catch_contract_id,
        _call_revert_with_try_catch_in_depth_contract,
        call_revert_with_try_catch_in_depth_contract_id,
        _call_revert_without_try_catch_contract,
        _call_revert_without_try_catch_contract_id,
    ) = before_each();

    // call try catch revert method
    {
        let operation = "CallRevertWithTryCatch.test(Revert)";
        let args_str = format!(
            "bb29998e000000000000000000000000{}",
            hex::encode(&revert_contract.eth_addr)
        );
        let block_number = 1 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_with_try_catch_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);

        state
            .apply_run_result(&run_result.write)
            .expect("update state");

        println!("exit code: {}", run_result.exit_code);
        assert_eq!(run_result.exit_code, 0);
    }

    // check if failed try state(Revert.state) is reverted
    {
        let operation = "Revert.state()";
        let args_str = "c19d93fb";
        let block_number = 2 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(revert_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 1);
    }

    // check if try catch state(CallRevertWithTryCatch.state) is updated
    {
        let operation = "CallRevertWithTryCatch.state()";
        let args_str = "c19d93fb";
        let block_number = 2 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_with_try_catch_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 4);
    }

    // call try catch revert in two depth
    {
        let operation = "CallRevertWithTryCatchInDepth.test(CallRevertWithTryCatch, Revert)";
        let args_str = format!(
            "2b6d0ceb000000000000000000000000{}000000000000000000000000{}",
            hex::encode(&call_revert_with_try_catch_contract.eth_addr),
            hex::encode(&revert_contract.eth_addr)
        );
        let block_number = 3 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(200000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_with_try_catch_in_depth_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);

        state
            .apply_run_result(&run_result.write)
            .expect("update state");

        println!("exit code: {}", run_result.exit_code);
        assert_eq!(run_result.exit_code, 0);
    }

    // check if failed try state (Revert.state) is reverted in two depth
    {
        let operation = "Revert.state()";
        let args_str = "c19d93fb";
        let block_number = 4 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(revert_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 1);
    }

    // check if failed try catch state (CallRevertWithTryCatchInDepth.state) is updated
    {
        let operation = "CallRevertWithTryCatchInDepth.state()";
        let args_str = "c19d93fb";
        let block_number = 4 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_with_try_catch_in_depth_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 4);
    }
}

#[test]
fn test_revert_without_try_catch() {
    let (
        mut state,
        store,
        generator,
        from_id,
        _from_eth_address,
        block_producer_id,
        revert_contract,
        revert_contract_id,
        _call_revert_with_try_catch_contract,
        _call_revert_with_try_catch_contract_id,
        _call_revert_with_try_catch_in_depth_contract,
        _call_revert_with_try_catch_in_depth_contract_id,
        _call_revert_without_try_catch_contract,
        call_revert_without_try_catch_contract_id,
    ) = before_each();

    // call normal revert
    {
        let operation = "CallRevertWithoutTryCatch.test(Revert)";
        let args_str = format!(
            "bb29998e000000000000000000000000{}",
            hex::encode(&revert_contract.eth_addr)
        );
        let block_number = 1 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_without_try_catch_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);

        state
            .apply_run_result(&run_result.write)
            .expect("update state");

        println!("exit code: {}", run_result.exit_code);
        assert_eq!(run_result.exit_code, 2);
    }

    // check if failed state(Revert.state) is reverted
    {
        let operation = "Revert.state()";
        let args_str = "c19d93fb";
        let block_number = 2 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(revert_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 1);
    }

    // check if failed state(CallRevertWithoutTryCatch.state) is reverted
    {
        let operation = "CallRevertWithoutTryCatch.state()";
        let args_str = "c19d93fb";
        let block_number = 2 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_without_try_catch_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 1);
    }
}

#[test]
fn test_revert_with_try_catch_in_constructor() {
    let (
        mut state,
        store,
        generator,
        from_id,
        from_eth_address,
        block_producer_id,
        revert_contract,
        revert_contract_id,
        _call_revert_with_try_catch_contract,
        _call_revert_with_try_catch_contract_id,
        _call_revert_with_try_catch_in_depth_contract,
        _call_revert_with_try_catch_in_depth_contract_id,
        _call_revert_without_try_catch_contract,
        _call_revert_without_try_catch_contract_id,
    ) = before_each();

    // try deploy CallRevertWithTryCatchInConstructor contract
    let call_revert_with_try_catch_in_constructor_contract;
    {
        let call_revert_with_try_catch_in_constructor_bytecode: &str =
            &load_bytecode_from_json_file(
                "evm-contracts/revert/CallRevertWithTryCatchInConstructor.json",
            );
        let deploy_args = format!(
            "000000000000000000000000{}",
            hex::encode(revert_contract.eth_addr)
        );
        let contract_bytecode_with_args = format!(
            "{}{}",
            call_revert_with_try_catch_in_constructor_bytecode, deploy_args
        );
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            &contract_bytecode_with_args,
            199694,
            0,
            block_producer_id.clone(),
            2,
        );
        print_gas_used(
            "Deploy callRevertWithTryCatchInConstructor contract: ",
            &run_result.write.logs,
        );

        println!("exit_code: {}", run_result.exit_code);
        assert_eq!(run_result.exit_code, 0);

        call_revert_with_try_catch_in_constructor_contract =
            MockContractInfo::create(&from_eth_address, 4);
    }

    let call_revert_with_try_catch_in_constructor_contract_id = state
        .get_account_id_by_script_hash(
            &call_revert_with_try_catch_in_constructor_contract.script_hash,
        )
        .unwrap()
        .unwrap();

    // check if failed try state(Revert.state) is reverted
    {
        let operation = "Revert.state()";
        let args_str = "c19d93fb";
        let block_number = 2 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(revert_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 1);
    }

    // check if failed try catch state (CallRevertWithTryCatchInConstructor.state) is updated
    {
        let operation = "CallRevertWithTryCatchInConstructor.state()";
        let args_str = "c19d93fb";
        let block_number = 4 as u64;
        let block_info = new_block_info(block_producer_id.clone(), block_number, block_number);
        println!(">> [input]: {}", args_str);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(call_revert_with_try_catch_in_constructor_contract_id.pack())
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
            .expect(operation);
        print_gas_used(&format!("{}: ", operation), &run_result.write.logs);
        let state = hex::encode(run_result.return_data);
        let state = state.parse::<u32>().unwrap();
        println!("{}: {}", operation, state);
        assert_eq!(state, 4);
    }
}

fn before_each() -> (
    gw_generator::dummy_state::DummyState,
    gw_store::Store,
    gw_generator::Generator,
    u32,
    [u8; 20],
    gw_common::registry_address::RegistryAddress,
    MockContractInfo,
    u32,
    MockContractInfo,
    u32,
    MockContractInfo,
    u32,
    MockContractInfo,
    u32,
) {
    let revert_bytecode: &str = &load_bytecode_from_json_file("evm-contracts/revert/Revert.json");
    let call_revert_with_try_catch_bytecode: &str =
        &load_bytecode_from_json_file("evm-contracts/revert/CallRevertWithTryCatch.json");
    let call_revert_with_try_catch_in_depth: &str =
        &load_bytecode_from_json_file("evm-contracts/revert/CallRevertWithTryCatchInDepth.json");
    let call_revert_without_try_catch: &str =
        &load_bytecode_from_json_file("evm-contracts/revert/CallRevertWithoutTryCatch.json");

    let (store, mut state, generator) = setup();
    let block_producer_id = crate::helper::create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address, 2000000u64.into());

    // Deploy all contracts
    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            revert_bytecode,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used("Deploy revert contract: ", &run_result.write.logs);
    }

    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            call_revert_with_try_catch_bytecode,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used(
            "Deploy callRevertWithTryCatch contract: ",
            &run_result.write.logs,
        );
    }

    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            call_revert_with_try_catch_in_depth,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used(
            "Deploy callRevertWithTryCatchInDepth contract: ",
            &run_result.write.logs,
        );
    }

    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            call_revert_without_try_catch,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used(
            "Deploy callRevertWithoutTryCatch contract: ",
            &run_result.write.logs,
        );
    }

    let revert_contract = MockContractInfo::create(&from_eth_address, 0);
    let revert_contract_id = state
        .get_account_id_by_script_hash(&revert_contract.script_hash)
        .unwrap()
        .unwrap();

    let call_revert_with_try_catch_contract = MockContractInfo::create(&from_eth_address, 1);
    let call_revert_with_try_catch_contract_id = state
        .get_account_id_by_script_hash(&call_revert_with_try_catch_contract.script_hash)
        .unwrap()
        .unwrap();

    let call_revert_with_try_catch_in_depth_contract =
        MockContractInfo::create(&from_eth_address, 2);
    let call_revert_with_try_catch_in_depth_contract_id = state
        .get_account_id_by_script_hash(&call_revert_with_try_catch_in_depth_contract.script_hash)
        .unwrap()
        .unwrap();

    let call_revert_without_try_catch_contract = MockContractInfo::create(&from_eth_address, 3);
    let call_revert_without_try_catch_contract_id = state
        .get_account_id_by_script_hash(&call_revert_without_try_catch_contract.script_hash)
        .unwrap()
        .unwrap();

    return (
        state,
        store,
        generator,
        from_id,
        from_eth_address,
        block_producer_id,
        revert_contract,
        revert_contract_id,
        call_revert_with_try_catch_contract,
        call_revert_with_try_catch_contract_id,
        call_revert_with_try_catch_in_depth_contract,
        call_revert_with_try_catch_in_depth_contract_id,
        call_revert_without_try_catch_contract,
        call_revert_without_try_catch_contract_id,
    );
}

// todo move to helper file
fn load_bytecode_from_json_file(path: &str) -> String {
    let mut file_path = env::current_dir().expect("base path");
    file_path.push("src/test_cases/");
    file_path.push(path);

    let data = fs::read_to_string(file_path).expect("Unable to read json file");
    let revert_json: serde_json::Value = serde_json::from_str(&data).expect("json format");
    let bytecode = revert_json["bytecode"]
        .to_string()
        .replace("0x", "")
        .replace('"', "");
    bytecode
}
