//! Test Revert contract
//!   See ./evm-contracts/revert/*

use crate::helper::{
    self, deploy, new_block_info, print_gas_used, setup, MockContractInfo, PolyjuiceArgsBuilder,
    CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const AAA_INIT_CODE: &str = include_str!("./evm-contracts/revert/DebugAAA.bin");
const BBB_INIT_CODE: &str = include_str!("./evm-contracts/revert/DebugBBB.bin");
const CCC_INIT_CODE: &str = include_str!("./evm-contracts/revert/DebugCCC.bin");
const NORMAL_REVERT_INIT_CODE: &str = include_str!("./evm-contracts/revert/NormalRevert.bin");

#[test]
fn test_try_catch_revert() {
    let (
        mut state,
        store,
        generator,
        from_id,
        block_producer_id,
        aaa_contract,
        aaa_contract_id,
        bbb_contract,
        bbb_contract_id,
        _ccc_contract,
        ccc_contract_id,
        _normal_revert_contract,
        _normal_revert_contract_id,
    ) = before_each();

    // call try catch revert method
    {
        let operation = "DebugerBBB.test(DebuggerAAA)";
        let args_str = format!(
            "bb29998e000000000000000000000000{}",
            hex::encode(&aaa_contract.eth_addr)
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
            .to_id(bbb_contract_id.pack())
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

    // check if failed try state(DebugerAAA.state) is reverted
    {
        let operation = "DebugerAAA.state()";
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
            .to_id(aaa_contract_id.pack())
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

    // check if try catch state(DebugerBBB.x) is updated
    {
        let operation = "DebugerBBB.x()";
        let args_str = "0c55699c";
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
            .to_id(bbb_contract_id.pack())
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
        assert_eq!(state, 2);
    }

    // call try catch revert in two depth
    {
        let operation = "DebugerCCC.test(DebugBBB, DebugAAA)";
        let args_str = format!(
            "2b6d0ceb000000000000000000000000{}000000000000000000000000{}",
            hex::encode(&bbb_contract.eth_addr),
            hex::encode(&aaa_contract.eth_addr)
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
            .to_id(ccc_contract_id.pack())
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

    // check if failed try state (DebugerAAA.state) is reverted in two depth
    {
        let operation = "DebugerAAA.state()";
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
            .to_id(aaa_contract_id.pack())
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

    // check if failed try catch state (DebugerCCC.y) is updated
    {
        let operation = "DebugerCCC.y()";
        let args_str = "a56dfe4a";
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
            .to_id(ccc_contract_id.pack())
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
fn test_normal_revert() {
    let (
        mut state,
        store,
        generator,
        from_id,
        block_producer_id,
        aaa_contract,
        aaa_contract_id,
        _bbb_contract,
        _bbb_contract_id,
        _ccc_contract,
        _ccc_contract_id,
        _normal_revert_contract,
        normal_revert_contract_id,
    ) = before_each();

    // call normal revert
    {
        let operation = "NormalRevert.test(DebuggerAAA)";
        let args_str = format!(
            "bb29998e000000000000000000000000{}",
            hex::encode(&aaa_contract.eth_addr)
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
            .to_id(normal_revert_contract_id.pack())
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

    // check if failed state(DebugerAAA.state) is reverted
    {
        let operation = "DebugerAAA.state()";
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
            .to_id(aaa_contract_id.pack())
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

    // check if failed state(NormalRevert.z) is reverted
    {
        let operation = "NormalRevert.z()";
        let args_str = "c5d7802e";
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
            .to_id(normal_revert_contract_id.pack())
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

fn before_each() -> (
    gw_generator::dummy_state::DummyState,
    gw_store::Store,
    gw_generator::Generator,
    u32,
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
            AAA_INIT_CODE,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used("Deploy AAA contract: ", &run_result.write.logs);
    }

    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            BBB_INIT_CODE,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used("Deploy BBB contract: ", &run_result.write.logs);
    }

    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            CCC_INIT_CODE,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used("Deploy CCC contract: ", &run_result.write.logs);
    }

    {
        let run_result = deploy(
            &generator,
            &store,
            &mut state,
            CREATOR_ACCOUNT_ID,
            from_id,
            NORMAL_REVERT_INIT_CODE,
            199694,
            0,
            block_producer_id.clone(),
            1,
        );
        print_gas_used("Deploy NORMAL_REVERT contract: ", &run_result.write.logs);
    }

    let aaa_contract = MockContractInfo::create(&from_eth_address, 0);
    let aaa_contract_id = state
        .get_account_id_by_script_hash(&aaa_contract.script_hash)
        .unwrap()
        .unwrap();

    let bbb_contract = MockContractInfo::create(&from_eth_address, 1);
    let bbb_contract_id = state
        .get_account_id_by_script_hash(&bbb_contract.script_hash)
        .unwrap()
        .unwrap();

    let ccc_contract = MockContractInfo::create(&from_eth_address, 2);
    let ccc_contract_id = state
        .get_account_id_by_script_hash(&ccc_contract.script_hash)
        .unwrap()
        .unwrap();

    let normal_revert_contract = MockContractInfo::create(&from_eth_address, 3);
    let normal_revert_contract_id = state
        .get_account_id_by_script_hash(&normal_revert_contract.script_hash)
        .unwrap()
        .unwrap();

    return (
        state,
        store,
        generator,
        from_id,
        block_producer_id,
        aaa_contract,
        aaa_contract_id,
        bbb_contract,
        bbb_contract_id,
        ccc_contract,
        ccc_contract_id,
        normal_revert_contract,
        normal_revert_contract_id,
    );
}
