//! Test SimpleStorage
//!   See ./evm-contracts/SimpleStorage.sol

use crate::helper::{
    self, build_eth_l2_script, new_block_info, new_contract_account_script, setup, Account,
    PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::{
    builtins::ETH_REGISTRY_ACCOUNT_ID, registry_address::RegistryAddress, state::State,
};
use gw_generator::traits::StateExt;
use gw_store::{chain_view::ChainView, traits::chain_store::ChainStore};
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");

#[test]
fn test_simple_storage() {
    let (store, mut state, generator) = setup();
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_eth_address = [1u8; 20];
    let (from_id, from_script_hash) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000);
    let from_reg_addr = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, from_eth_address.to_vec());
    let from_balance1 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &from_reg_addr)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance1);
    {
        // Deploy SimpleStorage
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
        println!("return_data: {}", hex::encode(&run_result.return_data[..]));
        // 557534 < 560K
        helper::check_cycles("Deploy SimpleStorage", run_result.used_cycles, 560_000);
    }

    let contract_account_script =
        new_contract_account_script(&mut state, from_id, &from_eth_address, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let from_balance2 = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, &from_reg_addr)
        .unwrap();
    println!("balance of {} = {}", from_id, from_balance2);
    println!(
        "contract account script: {}",
        hex::encode(contract_account_script.as_slice())
    );
    println!(
        "eth address: {}",
        hex::encode(&contract_account_script.args().raw_data().as_ref()[36..])
    );
    {
        // SimpleStorage.set(0x0d10);
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, 2, 0);
        let input =
            hex::decode("60fe47b10000000000000000000000000000000000000000000000000000000000000d10")
                .unwrap();
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
        // 489767 < 500K
        helper::check_cycles("SimpleStorage.set", run_result.used_cycles, 500_000);
    }

    {
        // SimpleStorage.get();
        let (_, block_producer) = Account::build_script(0);
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
        let mut expected_return_data = vec![0u8; 32];
        expected_return_data[30] = 0x0d;
        expected_return_data[31] = 0x10;
        assert_eq!(run_result.return_data, expected_return_data);
    }

    helper::simple_storage_get(&store, &state, &generator, 4, from_id, new_account_id);
}
