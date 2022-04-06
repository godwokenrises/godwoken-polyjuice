//! Test SELFDESTRUCT op code
//!   See ./evm-contracts/SelfDestruct.sol

use crate::helper::{
    self, build_eth_l2_script, eth_addr_to_ethabi_addr, new_block_info,
    new_contract_account_script, setup, Account, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
    CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::{
    builtins::ETH_REGISTRY_ACCOUNT_ID, registry_address::RegistryAddress, state::State,
};
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/SelfDestruct.bin");

#[test]
fn test_selfdestruct() {
    let (store, mut state, generator) = setup();
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000);

    let beneficiary_eth_addr = [2u8; 20];
    let beneficiary_ethabi_addr = eth_addr_to_ethabi_addr(&beneficiary_eth_addr);
    let (_beneficiary_id, beneficiary_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &beneficiary_eth_addr, 0);
    let beneficiary_reg_addr =
        RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, beneficiary_eth_addr.to_vec());
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &beneficiary_reg_addr)
            .unwrap(),
        0
    );

    {
        // Deploy SelfDestruct
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, 1, 0);
        let mut input = hex::decode(INIT_CODE).unwrap();
        input.extend(beneficiary_ethabi_addr);
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(200)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(CREATOR_ACCOUNT_ID.pack())
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
                None,
            )
            .expect("construct");
        // [Deploy SelfDestruct] used cycles: 570570 < 580K
        helper::check_cycles("Deploy SelfDestruct", run_result.used_cycles, 580_000);
        state.apply_run_result(&run_result).expect("update state");
    }

    let contract_account_script =
        new_contract_account_script(&mut state, from_id, &from_eth_address, false);
    let new_script_hash = contract_account_script.hash();
    let contract_reg_addr = state
        .get_registry_address_by_script_hash(ETH_REGISTRY_ACCOUNT_ID, &new_script_hash.into())
        .unwrap()
        .unwrap();
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &contract_reg_addr)
            .unwrap(),
        200
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &beneficiary_reg_addr)
            .unwrap(),
        0
    );
    {
        // call SelfDestruct.done();
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, 2, 0);
        let input = hex::decode("ae8421e1").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
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
        // [call SelfDestruct.done()] used cycles: 589657 < 600K
        helper::check_cycles("call SelfDestruct.done()", run_result.used_cycles, 600_000);
        state.apply_run_result(&run_result).expect("update state");
    }
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &contract_reg_addr)
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &beneficiary_reg_addr)
            .unwrap(),
        200
    );

    {
        // call SelfDestruct.done();
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, 2, 0);
        let input = hex::decode("ae8421e1").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(31000)
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
        assert!(result.is_err());
    }
}
