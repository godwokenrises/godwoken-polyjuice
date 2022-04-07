//! Test contract create contract
//!   See ./evm-contracts/CreateContract.sol

use crate::helper::{
    self, build_eth_l2_script, deploy, new_account_script, new_account_script_with_nonce,
    new_block_info, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/CreateContract.bin");

#[test]
fn test_contract_create_contract() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 200000)
        .unwrap();

    // Deploy CreateContract
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        from_id,
        INIT_CODE,
        122000,
        0,
        block_producer_id,
        1,
    );
    // [Deploy CreateContract] used cycles: 2109521 < 2120K
    helper::check_cycles("Deploy CreateContract", run_result.used_cycles, 2120_000);
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(new_account_id, 5);
    let contract_account_nonce = state.get_nonce(new_account_id).unwrap();
    // 1 => new SimpleStorage()
    assert_eq!(contract_account_nonce, 1);
    let ss_account_script =
        new_account_script_with_nonce(&state, creator_account_id, new_account_id, 0);
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(ss_account_id, 6);

    {
        // SimpleStorage.get();
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode("6d4ce63c").unwrap();
        let args = PolyjuiceArgsBuilder::default()
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
        expected_return_data[31] = 0xff;
        assert_eq!(run_result.return_data, expected_return_data);
    }
}
