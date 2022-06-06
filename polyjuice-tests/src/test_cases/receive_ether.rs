use std::convert::TryInto;

use ckb_vm::Bytes;
use gw_common::state::State;
use gw_generator::{error::TransactionError, traits::StateExt};
use gw_store::{chain_view::ChainView, traits::chain_store::ChainStore};
use gw_types::{
    packed::RawL2Transaction,
    prelude::{Builder, Entity, Pack},
};

use crate::helper::{
    check_cycles, create_block_producer, deploy, eth_addr_to_ethabi_addr, new_block_info,
    parse_log, setup, MockContractInfo, PolyjuiceArgsBuilder, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};

const INIT_CODE: &str = include_str!("./evm-contracts/EtherReceiverMock.bin");
const REJECT_SS_CODE: &str = include_str!("./evm-contracts/RejectedSimpleStorage.bin");
const ST_CODE: &str = include_str!("./evm-contracts/SimpleTransfer.bin");

#[test]
fn receive_ether_test() -> anyhow::Result<()> {
    let (store, mut state, generator) = setup();
    let block_producer = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000000u64.into());

    // Deploy Contract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        INIT_CODE,
        50000,
        0,
        block_producer.clone(),
        0,
    );

    let contract_account = MockContractInfo::create(&from_eth_address, 0);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account.script_hash)?
        .unwrap();

    //call receive()
    let block_info = new_block_info(block_producer, 1, 0);
    let args = PolyjuiceArgsBuilder::default()
        .gas_limit(21000)
        .gas_price(1)
        .value(1000)
        .input(&[])
        .build();
    let raw_tx = RawL2Transaction::new_builder()
        .from_id(from_id.pack())
        .to_id(new_account_id.pack())
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
        .expect("Call receive()");
    check_cycles("receive()", run_result.used_cycles, 710_100);
    assert!(run_result.return_data.is_empty());
    let log = parse_log(&run_result.logs[1]);
    let receive_data = match log {
        crate::helper::Log::PolyjuiceUser {
            address: _,
            data,
            topics: _,
        } => Some(data.get(63..71).unwrap().to_vec()),
        _ => None,
    };
    let mut expect = [7u8; 8];
    expect[1..].copy_from_slice(b"receive");
    assert_eq!(receive_data, Some(expect.to_vec()));
    state.apply_run_result(&run_result).expect("update state");
    Ok(())
}

#[test]
fn without_receive_fallback_test() -> anyhow::Result<()> {
    let (store, mut state, generator) = setup();
    let block_producer = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000000u64.into());

    // Deploy SimpleTrasfer Contract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        ST_CODE,
        50000,
        0,
        block_producer.clone(),
        0,
    );
    let st_contract_account = MockContractInfo::create(&from_eth_address, 0);
    let st_account_id = state
        .get_account_id_by_script_hash(&st_contract_account.script_hash)?
        .unwrap();

    // Deploy RejectedSimpleStorage Contract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        REJECT_SS_CODE,
        50000,
        0,
        block_producer.clone(),
        0,
    );
    let ss_contract_account = MockContractInfo::create(&from_eth_address, 1);
    let _ss_account_id = state
        .get_account_id_by_script_hash(&ss_contract_account.script_hash)?
        .unwrap();

    // SimpleTransfer.transferToSimpleStorage1();
    let block_info = new_block_info(block_producer, 1, 1);

    let input = hex::decode(format!(
        "f10c7360{}",
        hex::encode(eth_addr_to_ethabi_addr(
            &ss_contract_account.eth_addr.try_into().unwrap()
        )),
    ))
    .unwrap();
    let args = PolyjuiceArgsBuilder::default()
        .gas_limit(80000)
        .gas_price(1)
        .value(0)
        .input(&input)
        .build();
    let raw_tx = RawL2Transaction::new_builder()
        .from_id(from_id.pack())
        .to_id(st_account_id.pack())
        .args(Bytes::from(args).pack())
        .build();
    let db = store.begin_transaction();
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    let run_result = generator.execute_transaction(
        &ChainView::new(&db, tip_block_hash),
        &state,
        &block_info,
        &raw_tx,
        L2TX_MAX_CYCLES,
        None,
    );
    //expect transfer failed
    assert_eq!(
        run_result.unwrap_err(),
        TransactionError::InvalidExitCode(2)
    );

    Ok(())
}

#[test]
fn over_transfer_test() -> anyhow::Result<()> {
    let (store, mut state, generator) = setup();
    let block_producer = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000000u64.into());

    // Deploy SimpleTrasfer Contract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        ST_CODE,
        50000,
        1000,
        block_producer.clone(),
        0,
    );
    let st_contract_account = MockContractInfo::create(&from_eth_address, 0);
    let st_account_id = state
        .get_account_id_by_script_hash(&st_contract_account.script_hash)?
        .unwrap();

    // Deploy RejectedSimpleStorage Contract
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        INIT_CODE,
        40000,
        0,
        block_producer.clone(),
        0,
    );
    let receive_contract_account = MockContractInfo::create(&from_eth_address, 1);
    println!(
        "eth addr: {}",
        hex::encode(&receive_contract_account.eth_addr)
    );
    let _ss_account_id = state
        .get_account_id_by_script_hash(&receive_contract_account.script_hash)?
        .unwrap();

    let block_info = new_block_info(block_producer, 1, 1);

    // SimpleTransfer.justTransfer(to, 1000000000000000);
    let input = hex::decode(format!(
        "d2ea8ea5{}00000000000000000000000000000000000000000000000000038d7ea4c68000",
        hex::encode(eth_addr_to_ethabi_addr(
            &receive_contract_account.eth_addr.try_into().unwrap()
        ))
    ))?;
    let args = PolyjuiceArgsBuilder::default()
        .gas_limit(80000)
        .gas_price(1)
        .value(0)
        .input(&input)
        .build();
    let raw_tx = RawL2Transaction::new_builder()
        .from_id(from_id.pack())
        .to_id(st_account_id.pack())
        .args(Bytes::from(args).pack())
        .build();
    let db = store.begin_transaction();
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    let run_result = generator.execute_transaction(
        &ChainView::new(&db, tip_block_hash),
        &state,
        &block_info,
        &raw_tx,
        L2TX_MAX_CYCLES,
        None,
    );

    // expect transfer failed
    assert_eq!(
        run_result.unwrap_err(),
        TransactionError::InvalidExitCode(2)
    );

    Ok(())
}
