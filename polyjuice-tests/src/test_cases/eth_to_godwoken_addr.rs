//! See ./evm-contracts/EthToGodwokenAddr.sol

use crate::helper::{
    self, build_eth_l2_script, deploy, new_account_script, new_block_info, setup,
    PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES, PROGRAM_CODE_HASH,
    ROLLUP_SCRIPT_HASH,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{RawL2Transaction, Script},
    prelude::*,
};

const INIT_CODE: &str = include_str!("./evm-contracts/EthToGodwokenAddr.bin");

#[test]
fn test_eth_to_godwoken_addr() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_args = [1u8; 20];
    let from_script = build_eth_l2_script(from_args.clone());
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, 200000)
        .unwrap();

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
        0,
    );
    // [Deploy EthToGodwokenAddr Contract] used cycles: 593775 < 600K
    helper::check_cycles(
        "Deploy EthToGodwokenAddr Contract",
        run_result.used_cycles,
        600_000,
    );

    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();

    {
        // EthToGodwokenAddr.convert(addr);
        let block_info = new_block_info(0, 2, 0);
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
            )
            .expect("construct");
        // [EthToGodwokenAddr.convert(addr)] used cycles: 573228 < 580K
        helper::check_cycles(
            "EthToGodwokenAddr.convert(addr)",
            run_result.used_cycles,
            580_000,
        );
        state.apply_run_result(&run_result).expect("update state");
        let mut script_args = vec![0u8; 32 + 4 + 20];
        script_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
        script_args[32..36].copy_from_slice(&creator_account_id.to_le_bytes()[..]);
        script_args[36..56].copy_from_slice(&hex::decode(hex_eth_address).unwrap());
        let script_hash = Script::new_builder()
            .code_hash(PROGRAM_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(script_args).pack())
            .build()
            .hash();
        let mut addr = [0u8; 32];
        addr[12..32].copy_from_slice(&script_hash[0..20]);
        assert_eq!(run_result.return_data, addr);
    }
}
