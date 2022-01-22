//! Test parse log
//!   See ./evm-contracts/LogEvents.sol

use crate::helper::{
    build_eth_l2_script, contract_id_to_short_script_hash, deploy, eth_addr_to_ethabi_addr,
    new_block_info, new_contract_account_script, parse_log, register_eoa_account, setup, Log,
    PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};
use std::convert::TryInto;

const INIT_CODE: &str = include_str!("./evm-contracts/LogEvents.bin");

#[test]
fn test_parse_log_event() {
    let (store, mut state, generator) = setup();
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let block_producer_script_hash = block_producer_script.hash();
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .expect("create_block_producer");
    register_eoa_account(&mut state, &[0x99u8; 20], &block_producer_script_hash);

    let from_eth_address = [1u8; 20];
    let (from_id, from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000);
    let from_short_script_hash: &[u8; 20] = &from_script_hash[..20].try_into().unwrap();

    let from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_script_hash)
        .unwrap();
    assert_eq!(from_balance1, 200000);

    let mut block_number = 0;
    let deploy_value = 0xfa;
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        INIT_CODE,
        50000,
        deploy_value,
        block_producer_id,
        block_number,
    );
    let contract_account_script =
        new_contract_account_script(&mut state, from_id, &from_eth_address, false);
    let contract_script_hash = contract_account_script.hash();
    let contract_short_script_hash = &contract_script_hash[0..20];
    let contract_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(run_result.logs.len(), 4);

    // Log::SudtTransfer: EoA transfer to contract
    {
        let log_item = &run_result.logs[0];
        let log_account_id: u32 = log_item.account_id().unpack();
        assert_eq!(log_account_id, CKB_SUDT_ACCOUNT_ID);
        let log = parse_log(&log_item);
        println!("user log: {:?}", log);
        if let Log::SudtTransfer {
            from_addr: the_from_addr,
            to_addr: the_to_addr,
            amount,
            ..
        } = log
        {
            assert_eq!(&the_from_addr, from_short_script_hash);
            assert_eq!(the_to_addr, contract_short_script_hash);
            assert_eq!(amount, deploy_value);
        } else {
            panic!("unexpected polyjuice log");
        }
    }
    // Log::PolyjuiceUser
    {
        let log_item = &run_result.logs[1];
        let log_account_id: u32 = log_item.account_id().unpack();
        assert_eq!(log_account_id, contract_id);
        let log = parse_log(&log_item);
        println!("user log: {:?}", log);
        if let Log::PolyjuiceUser {
            address,
            data,
            topics,
        } = log
        {
            assert_eq!(
                &address[..],
                &contract_id_to_short_script_hash(&state, contract_id, false)[..]
            );
            assert_eq!(data[31], deploy_value as u8);
            assert_eq!(data[63], 1); // true
            assert_eq!(
                topics[1].as_slice(),
                eth_addr_to_ethabi_addr(&from_eth_address)
            );
        } else {
            panic!("unexpected polyjuice log");
        }
    }
    // EVM result log
    {
        let log_item = &run_result.logs[2];
        let log_account_id: u32 = log_item.account_id().unpack();
        assert_eq!(log_account_id, contract_id);
        let log = parse_log(&log_item);
        println!("system log: {:?}", log);
        if let Log::PolyjuiceSystem {
            gas_used,
            cumulative_gas_used,
            created_address,
            status_code,
        } = log
        {
            assert_eq!(gas_used, cumulative_gas_used);
            assert_eq!(created_address, contract_short_script_hash);
            assert_eq!(status_code, 0);
        } else {
            panic!("unexpected polyjuice log");
        }
    }
    // Transaction pay fee log
    {
        let log_item = &run_result.logs[3];
        let log_account_id: u32 = log_item.account_id().unpack();
        assert_eq!(log_account_id, CKB_SUDT_ACCOUNT_ID);
        let log = parse_log(&log_item);
        println!("user log: {:?}", log);
        if let Log::SudtPayFee {
            from_addr: the_from_addr,
            block_producer_addr: the_to_addr,
            amount,
            ..
        } = log
        {
            assert_eq!(&the_from_addr, from_short_script_hash);
            // The block producer id is `0`
            assert_eq!(the_to_addr, block_producer_script_hash[..20]);
            assert_eq!(amount, 1814);
        } else {
            panic!("unexpected polyjuice log");
        }
    }

    block_number += 1;
    {
        // LogEvents.log();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode("51973ec9").unwrap();
        let call_value = 0xac;
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(21000)
            .gas_price(1)
            .value(call_value)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_id.pack())
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
            .expect("construct");
        state.apply_run_result(&run_result).expect("update state");

        assert_eq!(run_result.logs.len(), 4);
        {
            let log_item = &run_result.logs[1];
            let log_account_id: u32 = log_item.account_id().unpack();
            assert_eq!(log_account_id, contract_id);
            let log = parse_log(&log_item);
            println!("user log: {:?}", log);
            if let Log::PolyjuiceUser {
                address,
                data,
                topics,
            } = log
            {
                assert_eq!(
                    &address[..],
                    &contract_id_to_short_script_hash(&state, contract_id, false)[..]
                );
                assert_eq!(data[31], call_value as u8);
                assert_eq!(data[63], 0); // false
                assert_eq!(
                    topics[1].as_slice(),
                    eth_addr_to_ethabi_addr(&from_eth_address)
                );
            } else {
                panic!("unexpected polyjuice log");
            }
        }
        {
            let log_item = &run_result.logs[2];
            let log_account_id: u32 = log_item.account_id().unpack();
            assert_eq!(log_account_id, contract_id);
            let log = parse_log(&log_item);
            println!("system log: {:?}", log);
            if let Log::PolyjuiceSystem {
                gas_used,
                cumulative_gas_used,
                created_address,
                status_code,
            } = log
            {
                assert_eq!(gas_used, cumulative_gas_used);
                assert_eq!(created_address, [0u8; 20]);
                assert_eq!(status_code, 0);
            } else {
                panic!("unexpected polyjuice log");
            }
        }
    }
}
