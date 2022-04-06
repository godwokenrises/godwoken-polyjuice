//! Test SimpleStorage
//!   See ./evm-contracts/SimpleStorage.sol

use crate::helper::{
    build_eth_l2_script, new_block_info, new_contract_account_script, setup, Account,
    MockContractInfo, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, COMPATIBLE_CHAIN_ID,
    CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::{builtins::ETH_REGISTRY_ACCOUNT_ID, state::State};
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/GetChainId.bin");

#[test]
fn test_get_chain_id() {
    let (store, mut state, generator) = setup();
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_eth_address = [1u8; 20];
    let (from_id, from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000);
    let address = state
        .get_registry_address_by_script_hash(ETH_REGISTRY_ACCOUNT_ID, &from_script_hash.into())
        .unwrap()
        .unwrap();

    let from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &address)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance1);
    {
        // Deploy GetChainId contract
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, 1, 0);
        let input = hex::decode(INIT_CODE).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(0)
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
        state.apply_run_result(&run_result).expect("update state");
        // println!("result {:?}", run_result);
        println!("return_data: {}", hex::encode(&run_result.return_data[..]));
    }

    let contract_account = MockContractInfo::create(&from_eth_address, 0);
    contract_account.mapping_registry_address_to_script_hash(&mut state);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account.script_hash)
        .unwrap()
        .unwrap();
    let from_balance2 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &address)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance2);

    {
        // call GetChainId.get()
        let (script, block_producer) = Account::build_script(0);
        state
            .mapping_registry_address_to_script_hash(block_producer.clone(), script.hash().into())
            .expect("map reg addr to script hash");
        let block_info = new_block_info(block_producer, 3, 0);
        let input = hex::decode("6d4ce63c").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(21000)
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
        state.apply_run_result(&run_result).expect("update state");

        /* chain_id = compatible_chain_id(u32) | creator_account_id(u32) */
        let mut expected_chain_id = vec![0u8; 32];
        expected_chain_id[28..32].copy_from_slice(&CREATOR_ACCOUNT_ID.to_be_bytes()[..]);
        expected_chain_id[24..28].copy_from_slice(&COMPATIBLE_CHAIN_ID.to_be_bytes()[..]);
        assert_eq!(run_result.return_data, expected_chain_id);
    }
}
