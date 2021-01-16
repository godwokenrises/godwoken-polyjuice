//! Test SELFDESTRUCT op code
//!   See ./evm-contracts/SelfDestruct.sol

use crate::helper::{
    account_id_to_eth_address, new_account_script, new_block_info, setup, PolyjuiceArgsBuilder,
    CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_common::traits::StateExt;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/SelfDestruct.bin");

#[test]
fn test_selfdestruct() {
    let (store, mut tree, generator, creator_account_id) = setup();

    let from_script = gw_common::sudt::build_l2_sudt_script([1u8; 32].into());
    let from_id = tree.create_account_from_script(from_script).unwrap();
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 200000)
        .unwrap();

    let beneficiary_script = gw_common::sudt::build_l2_sudt_script([2u8; 32].into());
    let beneficiary_id = tree.create_account_from_script(beneficiary_script).unwrap();
    assert_eq!(
        tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_id)
            .unwrap(),
        0
    );

    {
        // Deploy SelfDestruct
        let block_info = new_block_info(0, 1, 0);
        let mut input = hex::decode(INIT_CODE).unwrap();
        input.extend(account_id_to_eth_address(beneficiary_id, true));
        let args = PolyjuiceArgsBuilder::default()
            .is_create(true)
            .gas_limit(22000)
            .gas_price(1)
            .value(200)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(creator_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = generator
            .execute(&store, &tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");
        // println!("result {:?}", run_result);
    }

    let contract_account_script = new_account_script(&mut tree, from_id, false);
    let new_account_id = tree
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(
        tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_account_id)
            .unwrap(),
        200
    );
    assert_eq!(
        tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_id)
            .unwrap(),
        0
    );
    {
        // call SelfDestruct.done();
        let block_info = new_block_info(0, 2, 0);
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
        let run_result = generator
            .execute(&store, &tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");
        // println!("result {:?}", run_result);
    }
    assert_eq!(
        tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, new_account_id)
            .unwrap(),
        0
    );
    assert_eq!(
        tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, beneficiary_id)
            .unwrap(),
        200
    );

    {
        // call SelfDestruct.done();
        let block_info = new_block_info(0, 2, 0);
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
        let result = generator.execute(&store, &tree, &block_info, &raw_tx);
        println!("result {:?}", result);
        assert!(result.is_err());
    }
}
