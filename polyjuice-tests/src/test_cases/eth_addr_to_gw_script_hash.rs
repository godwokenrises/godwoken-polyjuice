//! See ./evm-contracts/EthToGodwokenAddr.sol

use crate::helper::{
    self, deploy, new_block_info, new_contract_account_script, setup, Account, MockContractInfo,
    PolyjuiceArgsBuilder, CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES, POLYJUICE_PROGRAM_CODE_HASH,
    ROLLUP_SCRIPT_HASH,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::{chain_view::ChainView, traits::chain_store::ChainStore};
use gw_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{RawL2Transaction, Script},
    prelude::*,
};

const INIT_CODE: &str = include_str!("./evm-contracts/EthToGodwokenAddr.bin");

#[test]
fn test_eth_addr_to_gw_script_hash() {
    let (store, mut state, generator) = setup();
    let block_producer_id = crate::helper::create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, from_script_hash) =
        helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000);
    let _fromt_short_script_hash = &from_script_hash[0..20];

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
        0,
    );
    // [Deploy EthToGodwokenAddr Contract] used cycles: 593775 < 600K
    helper::check_cycles(
        "Deploy EthToGodwokenAddr Contract",
        run_result.used_cycles,
        950_000,
    );

    let contract_account = MockContractInfo::create(&from_eth_address, 0);
    contract_account.mapping_registry_address_to_script_hash(&mut state);
    let contract_id = state
        .get_account_id_by_script_hash(&contract_account.script_hash)
        .unwrap()
        .unwrap();

    {
        // EthToGodwokenAddr.convert(addr);
        let (_, block_producer) = Account::build_script(0);
        let block_info = new_block_info(block_producer, 2, 0);
        let hex_eth_address = "fffffffffffffff333333333333fffffffffffff";
        let input = hex::decode(format!(
            "def2489b000000000000000000000000{}",
            hex_eth_address
        ))
        .unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(21000)
            .gas_price(1)
            .value(0)
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
        // [EthToGodwokenAddr.convert(addr)] used cycles: 573228 < 580K
        helper::check_cycles(
            "EthToGodwokenAddr.convert(addr)",
            run_result.used_cycles,
            710_000,
        );
        state.apply_run_result(&run_result).expect("update state");

        let mut script_args = vec![0u8; 32 + 4 + 20];
        script_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
        script_args[32..36].copy_from_slice(&CREATOR_ACCOUNT_ID.to_le_bytes()[..]);
        script_args[36..56].copy_from_slice(&hex::decode(hex_eth_address).unwrap());
        let script_hash = Script::new_builder()
            .code_hash(POLYJUICE_PROGRAM_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(script_args).pack())
            .build()
            .hash();
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&script_hash);
        // assert_eq!(run_result.return_data, addr);
    }
}
