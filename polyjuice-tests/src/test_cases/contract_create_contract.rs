//! Test contract create contract
//!   See ./evm-contracts/CreateContract.sol

use crate::helper::{
    self, deploy, new_block_info, new_contract_account_script,
    new_contract_account_script_with_nonce, setup, PolyjuiceArgsBuilder, CREATOR_ACCOUNT_ID,
    L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::{chain_view::ChainView, traits::chain_store::ChainStore};
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};
use std::convert::TryInto;

const INIT_CODE: &str = include_str!("./evm-contracts/CreateContract.bin");

#[test]
fn test_contract_create_contract() {
    let (store, mut state, generator) = setup();
    let block_producer_id = helper::create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000);

    // Deploy CreateContract
    let run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
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

    let mom_contract_script =
        new_contract_account_script(&state, from_id, &from_eth_address, false);
    let mom_contract_script_hash = mom_contract_script.hash();
    let mom_contract_id = state
        .get_account_id_by_script_hash(&mom_contract_script_hash.into())
        .unwrap()
        .unwrap(); // mom_contract_id = 6
    let mom_contract_nonce = state.get_nonce(mom_contract_id).unwrap();
    assert_eq!(mom_contract_nonce, 1); // 1 => new SimpleStorage()

    let ss_contract_script = new_contract_account_script_with_nonce(
        &mom_contract_script_hash[..20].try_into().unwrap(),
        0,
    );
    let ss_account_id = state
        .get_account_id_by_script_hash(&ss_contract_script.hash().into())
        .unwrap()
        .unwrap(); // ss_account_id = 7

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
            .expect("SimpleStorage.get()");
        state.apply_run_result(&run_result).expect("update state");
        let mut expected_return_data = vec![0u8; 32];
        expected_return_data[31] = 0xff;
        assert_eq!(run_result.return_data, expected_return_data);
    }
}
