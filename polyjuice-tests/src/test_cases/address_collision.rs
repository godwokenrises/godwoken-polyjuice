use std::convert::TryInto;

use anyhow::Result;
use ckb_vm::Bytes;
use gw_common::{
    builtins::ETH_REGISTRY_ACCOUNT_ID, registry_address::RegistryAddress, state::State,
};
use gw_generator::traits::StateExt;
use gw_store::{chain_view::ChainView, traits::chain_store::ChainStore};
use gw_types::{
    packed::RawL2Transaction,
    prelude::{Builder, Entity, Pack},
};

use crate::helper::{
    create_block_producer, create_eth_eoa_account, deploy, new_block_info, setup, MockContractInfo,
    PolyjuiceArgsBuilder, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};

const INIT_CODE: &str = include_str!("./evm-contracts/CreateContract.bin");
const SS_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const CREATE2_IMPL_CODE: &str = include_str!("./evm-contracts/Create2Impl.bin");

#[test]
fn create_address_collision_overwrite() -> Result<()> {
    let (store, mut state, generator) = setup();
    let block_producer_id = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        create_eth_eoa_account(&mut state, &from_eth_address, 200000u64.into());

    let create_eth_addr = hex::decode("808bfd2069b1ca619a55585e7b1ac1b11d392af9")?;
    let create_eth_reg_addr =
        RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, create_eth_addr.clone());
    //create EOA account with create_account address first
    let (eoa_id, _) = create_eth_eoa_account(
        &mut state,
        &create_eth_addr.try_into().unwrap(),
        200000u64.into(),
    );

    assert_eq!(eoa_id, 6);

    let _ = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        INIT_CODE,
        122000,
        0,
        block_producer_id,
        1,
    );

    let script_hash = state.get_script_hash_by_registry_address(&create_eth_reg_addr)?;
    assert!(script_hash.is_some());
    let create_account_id = state.get_account_id_by_script_hash(&script_hash.unwrap())?;
    assert_eq!(create_account_id, Some(8));
    Ok(())
}

#[test]
#[should_panic(expected = "deploy Polyjuice contract")]
fn create_address_collision_duplicate() {
    let (store, mut state, generator) = setup();
    let block_producer_id = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        create_eth_eoa_account(&mut state, &from_eth_address, 200000u64.into());

    let create_eth_addr = hex::decode("808bfd2069b1ca619a55585e7b1ac1b11d392af9").unwrap();
    let create_eth_reg_addr =
        RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, create_eth_addr.clone());
    //create EOA account with create_account address first
    let (eoa_id, _) = create_eth_eoa_account(
        &mut state,
        &create_eth_addr.try_into().unwrap(),
        200000u64.into(),
    );

    assert_eq!(eoa_id, 6);

    let _ = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        eoa_id,
        SS_CODE,
        122000,
        0,
        block_producer_id.clone(),
        1,
    );
    let eoa_nonce = state.get_nonce(eoa_id);
    assert_eq!(eoa_nonce, Ok(1));

    let _ = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        INIT_CODE,
        122000,
        0,
        block_producer_id,
        1,
    );

    let script_hash = state
        .get_script_hash_by_registry_address(&create_eth_reg_addr)
        .unwrap();
    assert!(script_hash.is_some());
    let create_account_id = state
        .get_account_id_by_script_hash(&script_hash.unwrap())
        .unwrap();
    assert_eq!(create_account_id, Some(8));
}

#[test]
fn create2_address_collision_overwrite() -> Result<()> {
    let (store, mut state, generator) = setup();
    let block_producer_id = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        create_eth_eoa_account(&mut state, &from_eth_address, 200000u64.into());

    let create2_eth_addr = hex::decode("d78e81d86aeace84ff6311db7b134c1231a4a402")?;
    let create2_eth_reg_addr =
        RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, create2_eth_addr.clone());
    //create EOA account with create_account address first
    let (eoa_id, _) = create_eth_eoa_account(
        &mut state,
        &create2_eth_addr.try_into().unwrap(),
        200000u64.into(),
    );

    assert_eq!(eoa_id, 6);

    let _ = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        CREATE2_IMPL_CODE,
        122000,
        0,
        block_producer_id.clone(),
        1,
    );

    let create2_contract = MockContractInfo::create(&from_eth_address, 0);
    let create2_contract_script_hash = create2_contract.script_hash;
    let create2_contract_id = state
        .get_account_id_by_script_hash(&create2_contract_script_hash)
        .unwrap()
        .unwrap();
    let input_value_u128: u128 = 0x9a;
    // bytes32 salt
    let input_salt = "1111111111111111111111111111111111111111111111111111111111111111";
    // Create2Impl.deploy(uint256 value, bytes32 salt, bytes memory code)
    let block_number = 2;
    let block_info = new_block_info(block_producer_id, block_number, block_number);
    // uint256 value: 0x000000000000000000000000000000000000000000000000000000000000009a
    let input_value = format!(
        "00000000000000000000000000000000000000000000000000000000000000{:2x}",
        input_value_u128
    );
    let input = hex::decode(format!("66cfa057{}{}00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000101{}00000000000000000000000000000000000000000000000000000000000000", input_value, input_salt, SS_CODE)).unwrap();

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
    state.apply_run_result(&run_result).expect("update state");

    let script_hash = state.get_script_hash_by_registry_address(&create2_eth_reg_addr)?;
    assert!(script_hash.is_some());
    let create_account_id = state.get_account_id_by_script_hash(&script_hash.unwrap())?;
    assert_eq!(create_account_id, Some(8));
    Ok(())
}

#[test]
fn create2_address_collision_duplicate() -> Result<()> {
    let (store, mut state, generator) = setup();
    let block_producer_id = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        create_eth_eoa_account(&mut state, &from_eth_address, 200000u64.into());

    let create2_eth_addr = hex::decode("d78e81d86aeace84ff6311db7b134c1231a4a402")?;
    //create EOA account with create_account address first
    let (eoa_id, _) = create_eth_eoa_account(
        &mut state,
        &create2_eth_addr.try_into().unwrap(),
        200000u64.into(),
    );

    assert_eq!(eoa_id, 6);
    let _ = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        eoa_id,
        SS_CODE,
        122000,
        0,
        block_producer_id.clone(),
        1,
    );
    let eoa_nonce = state.get_nonce(eoa_id);
    assert_eq!(eoa_nonce, Ok(1));

    let _ = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        CREATE2_IMPL_CODE,
        122000,
        0,
        block_producer_id.clone(),
        1,
    );

    let create2_contract = MockContractInfo::create(&from_eth_address, 0);
    let create2_contract_script_hash = create2_contract.script_hash;
    let create2_contract_id = state
        .get_account_id_by_script_hash(&create2_contract_script_hash)?
        .unwrap();
    let input_value_u128: u128 = 0x9a;
    // bytes32 salt
    let input_salt = "1111111111111111111111111111111111111111111111111111111111111111";
    // Create2Impl.deploy(uint256 value, bytes32 salt, bytes memory code)
    let block_number = 2;
    let block_info = new_block_info(block_producer_id, block_number, block_number);
    // uint256 value: 0x000000000000000000000000000000000000000000000000000000000000009a
    let input_value = format!(
        "00000000000000000000000000000000000000000000000000000000000000{:2x}",
        input_value_u128
    );
    let input = hex::decode(format!("66cfa057{}{}00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000101{}00000000000000000000000000000000000000000000000000000000000000", input_value, input_salt, SS_CODE)).unwrap();

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
    let run_result = generator.execute_transaction(
        &ChainView::new(&db, tip_block_hash),
        &state,
        &block_info,
        &raw_tx,
        L2TX_MAX_CYCLES,
        None,
    );
    assert!(run_result.is_err());

    Ok(())
}
