//! Test contract create contract
//!   See ./evm-contracts/CreateContract.sol

use crate::helper::{
    deploy, get_chain_view, new_account_script, new_account_script_with_nonce, new_block_info,
    setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
// use gw_jsonrpc_types::parameter::RunResult;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/CreateContract.bin");

#[test]
fn test_contract_create_contract() {
    let (store, mut tree, generator, creator_account_id) = setup();

    let from_script = gw_generator::sudt::build_l2_sudt_script([1u8; 32]);
    let from_id = tree.create_account_from_script(from_script).unwrap();
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 200000)
        .unwrap();

    // Deploy CreateContract
    let _run_result = deploy(
        &generator,
        &store,
        &mut tree,
        creator_account_id,
        from_id,
        INIT_CODE,
        122000,
        0,
        1,
    );
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );

    let contract_account_script = new_account_script(&mut tree, from_id, false);
    let new_account_id = tree
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(new_account_id, 4);
    let contract_account_nonce = tree.get_nonce(new_account_id).unwrap();
    // 1 => new SimpleStorage()
    assert_eq!(contract_account_nonce, 1);
    let ss_account_script = new_account_script_with_nonce(new_account_id, 0);
    let ss_account_id = tree
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(ss_account_id, 5);

    {
        // SimpleStorage.get();
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode("6d4ce63c").unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .static_call(true)
            .gas_limit(21000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(ss_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = generator
            .execute_transaction(&get_chain_view(&store), &tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");
        let mut expected_return_data = vec![0u8; 32];
        expected_return_data[31] = 0xff;
        assert_eq!(run_result.return_data, expected_return_data);
    }
}
