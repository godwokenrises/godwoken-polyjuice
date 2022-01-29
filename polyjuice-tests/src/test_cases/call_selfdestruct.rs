//! Test call selfdestruct from a contract account
//!   See ./evm-contracts/SelfDestruct.sol

use std::convert::TryInto;

use crate::helper::{
    self, contract_script_to_eth_addr, deploy, eth_addr_to_ethabi_addr, new_block_info,
    new_contract_account_script_with_nonce, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
    CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SD_INIT_CODE: &str = include_str!("./evm-contracts/SelfDestruct.bin");
const CALL_SD_INIT_CODE: &str = include_str!("./evm-contracts/CallSelfDestruct.bin");

#[test]
fn test_selfdestruct() {
    let (store, mut state, generator) = setup();
    let block_producer_id = helper::create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _) = helper::create_eth_eoa_account(&mut state, &from_eth_address, 300000);

    let beneficiary_eth_addr = [2u8; 20];
    let beneficiary_ethabi_addr = eth_addr_to_ethabi_addr(&beneficiary_eth_addr);
    let (_beneficiary_id, beneficiary_script_hash) =
        helper::create_eth_eoa_account(&mut state, &beneficiary_eth_addr, 0);
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &beneficiary_script_hash[..20])
            .unwrap(),
        0
    );

    // deploy SelfDestruct
    let mut block_number = 1;
    let input = format!(
        "{}{}",
        SD_INIT_CODE,
        // constructor(address payable _owner)
        hex::encode(beneficiary_ethabi_addr)
    );
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        input.as_str(),
        122000,
        200,
        block_producer_id,
        block_number,
    );
    // 571282 < 580K
    helper::check_cycles("deploy SelfDestruct", run_result.used_cycles, 580_000);

    let sd_account_script = new_contract_account_script_with_nonce(&from_eth_address, 0);
    let sd_script_hash = sd_account_script.hash();
    let sd_short_script_hash: &[u8; 20] = &sd_script_hash[0..20].try_into().unwrap();
    let sd_ethabi_addr = contract_script_to_eth_addr(&sd_account_script, true);
    let sd_account_id = state
        .get_account_id_by_script_hash(&sd_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, sd_short_script_hash)
            .unwrap(),
        200
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &beneficiary_script_hash[..20])
            .unwrap(),
        0
    );

    // deploy CallSelfDestruct
    block_number += 1;
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        CALL_SD_INIT_CODE,
        122000,
        0,
        block_producer_id,
        block_number,
    );
    // [deploy CallSelfDestruct] used cycles: 551984 < 560K
    helper::check_cycles("deploy CallSelfDestruct", run_result.used_cycles, 560_000);

    let csd_account_script = new_contract_account_script_with_nonce(&from_eth_address, 1);
    let csd_account_id = state
        .get_account_id_by_script_hash(&csd_account_script.hash().into())
        .unwrap()
        .unwrap();

    assert_eq!(state.get_nonce(from_id).unwrap(), 2);
    assert_eq!(state.get_nonce(sd_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(csd_account_id).unwrap(), 0);

    {
        // call CallSelfDestruct.proxyDone(sd_account_id)
        block_number += 1;
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!("9a33d968{}", hex::encode(&sd_ethabi_addr))).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(100000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(csd_account_id.pack())
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
            .expect("call CallSelfDestruct.proxyDone(sd_account_id)");
        state.apply_run_result(&run_result).expect("update state");
        // [call CallSelfDestruct.proxyDone(sd_account_id)] used cycles: 1043108 < 1100K
        helper::check_cycles(
            "CallSelfDestruct.proxyDone(sd_account_id)",
            run_result.used_cycles,
            1100_000,
        );
    }

    assert_eq!(state.get_nonce(from_id).unwrap(), 3);
    assert_eq!(state.get_nonce(sd_account_id).unwrap(), 0);
    assert_eq!(state.get_nonce(csd_account_id).unwrap(), 0);
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, sd_short_script_hash)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &beneficiary_script_hash[..20])
            .unwrap(),
        200
    );

    block_number += 1;

    {
        // call SelfDestruct.done() which was already destructed
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode("ae8421e1").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(sd_account_id.pack())
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
        println!("result {:?}", result);
        assert!(result.is_err(), "check_destructed");
    }

    {
        // call CallSelfDestruct.proxyDone(sd_account_id)
        // target contract of the proxy was already destructed
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!("9a33d968{}", hex::encode(&sd_ethabi_addr))).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(csd_account_id.pack())
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
        println!("result {:?}", result);
        assert!(result.is_err(), "check_destructed");
    }
}
