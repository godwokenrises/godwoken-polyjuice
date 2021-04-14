//! Test simple transfer
//!   See ./evm-contracts/SimpleTransfer.sol

use crate::helper::{
    account_id_to_eth_address, build_l2_sudt_script, deploy, new_account_script, new_block_info,
    setup, simple_storage_get, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
// use gw_jsonrpc_types::parameter::RunResult;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SS_INIT_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const INIT_CODE: &str = include_str!("./evm-contracts/SimpleTransfer.bin");

#[test]
fn test_simple_transfer() {
    let (store, mut tree, generator, creator_account_id) = setup();

    let from_script = build_l2_sudt_script([1u8; 32]);
    let from_id = tree.create_account_from_script(from_script).unwrap();
    let mint_balance: u128 = 400000;
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, mint_balance)
        .unwrap();
    let target_script = build_l2_sudt_script([2u8; 32]);
    let target_id = tree.create_account_from_script(target_script).unwrap();

    let from_balance = tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_id).unwrap();
    assert_eq!(from_balance, mint_balance);
    let target_balance = tree
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_id)
        .unwrap();
    assert_eq!(target_balance, 0);

    let mut block_number = 0;

    println!("================");
    // Deploy SimpleStorage
    let _run_result = deploy(
        &generator,
        &store,
        &mut tree,
        creator_account_id,
        from_id,
        SS_INIT_CODE,
        50000,
        0,
        block_number,
    );
    block_number += 1;
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );
    let ss_account_script = new_account_script(&mut tree, from_id, false);
    let ss_account_id = tree
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    let ss_balance = tree
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, ss_account_id)
        .unwrap();
    assert_eq!(ss_balance, 0);
    println!("--------");
    let run_result = simple_storage_get(
        &store,
        &tree,
        &generator,
        block_number,
        from_id,
        ss_account_id,
    );
    assert_eq!(
        run_result.return_data,
        hex::decode("000000000000000000000000000000000000000000000000000000000000007b").unwrap()
    );

    println!("================");
    // Deploy SimpleTransfer
    let deploy_value = 200;
    let _run_result = deploy(
        &generator,
        &store,
        &mut tree,
        creator_account_id,
        from_id,
        INIT_CODE,
        50000,
        deploy_value,
        block_number,
    );
    block_number += 1;
    let contract_account_script = new_account_script(&mut tree, from_id, false);
    let new_account_id = tree
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    let new_balance = tree
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_account_id)
        .unwrap();
    assert_eq!(new_balance, deploy_value);

    println!("================");
    {
        // > transfer to EoA
        // SimpleTransfer.transferTo();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "a03fa7e3{}",
            hex::encode(account_id_to_eth_address(target_id, true)),
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(40000)
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
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &tree,
                &block_info,
                &raw_tx,
            )
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");

        let new_balance = tree
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_account_id)
            .unwrap();
        assert_eq!(new_balance, deploy_value - 1);
        let target_balance = tree
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_id)
            .unwrap();
        assert_eq!(target_balance, 1);
    }

    println!("================");
    {
        // SimpleTransfer.transferToSimpleStorage1();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "f10c7360{}",
            hex::encode(account_id_to_eth_address(ss_account_id, true)),
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
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &tree,
                &block_info,
                &raw_tx,
            )
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");

        let new_balance = tree
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_account_id)
            .unwrap();
        assert_eq!(new_balance, deploy_value - 2);
        let ss_balance = tree
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, ss_account_id)
            .unwrap();
        assert_eq!(ss_balance, 1);
        println!("================");
        let run_result = simple_storage_get(
            &store,
            &tree,
            &generator,
            block_number,
            from_id,
            ss_account_id,
        );
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap()
        );
    }

    println!("================");
    {
        // SimpleTransfer.transferToSimpleStorage2();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode(format!(
            "2a5eb963{}",
            hex::encode(account_id_to_eth_address(ss_account_id, true)),
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
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &tree,
                &block_info,
                &raw_tx,
            )
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");

        let new_balance = tree
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_account_id)
            .unwrap();
        assert_eq!(new_balance, deploy_value - 3);
        let ss_balance = tree
            .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, ss_account_id)
            .unwrap();
        assert_eq!(ss_balance, 2);
        let run_result = simple_storage_get(
            &store,
            &tree,
            &generator,
            block_number,
            from_id,
            ss_account_id,
        );
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap()
        );
    }
}
