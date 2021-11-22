//! Test RecoverAccount
//!   See ./evm-contracts/RecoverAccount.sol

use crate::helper::{
    self, build_eth_l2_script, deploy, new_account_script, new_block_info, setup,
    simple_storage_get, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, FATAL_PRECOMPILED_CONTRACTS,
    L2TX_MAX_CYCLES, ROLLUP_SCRIPT_HASH, SECP_LOCK_CODE_HASH,
};
use gw_common::state::State;
use gw_generator::{error::TransactionError, traits::StateExt};
use gw_store::chain_view::ChainView;
use gw_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{RawL2Transaction, Script},
    prelude::*,
};

const INIT_CODE: &str = include_str!("./evm-contracts/RecoverAccount.bin");

#[test]
fn test_recover_account() {
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

    // Deploy RecoverAccount Contract
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
    // Deploy RecoverAccount Contract used cycles = 690541 < 700K
    helper::check_cycles(
        "Deploy RecoverAccount Contract",
        run_result.used_cycles,
        700_000,
    );
    let contract_account_script =
        new_account_script(&mut state, creator_account_id, from_id, false);
    let new_account_id = state
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();

    // For see the format of returned `bytes`
    let run_result = simple_storage_get(&store, &state, &generator, 0, from_id, new_account_id);
    println!("return bytes: {}", hex::encode(run_result.return_data));

    let lock_args_hex = "404f90829ec0e5821aeba9bce7d5e841ce9f7fa5";
    let message_hex = "1cdeae55a5768fe14b628001c6247ae84c70310a7ddcfdc73ac68494251e46ec";
    let signature_hex = "28aa0c394487edf2211f445c47fb5f4fb5e3023920f62124d309f5bdf70d95045a934f278cec717300a5417313d1cdc390e761e37c0964b940c0a6f07b7361ed01";
    {
        // RecoverAccount.recover(message, signature, code_hash);
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode(format!(
            "7d7b0255{}0000000000000000000000000000000000000000000000000000000000000060{}0000000000000000000000000000000000000000000000000000000000000041{}00000000000000000000000000000000000000000000000000000000000000",
            message_hex,
            hex::encode(&SECP_LOCK_CODE_HASH),
            signature_hex,
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
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        // [RecoverAccount.recover(message, signature, code_hash)] used cycles: 648630 < 670K
        helper::check_cycles(
            "RecoverAccount.recover(message, signature, code_hash)",
            run_result.used_cycles,
            670_000,
        );
        state.apply_run_result(&run_result).expect("update state");
        let mut script_args = vec![0u8; 32 + 20];
        script_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
        script_args[32..32 + 20].copy_from_slice(&hex::decode(lock_args_hex).unwrap());
        let script_hash = Script::new_builder()
            .code_hash(SECP_LOCK_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(script_args).pack())
            .build()
            .hash();
        assert_eq!(run_result.return_data, script_hash);
    }

    // Wrong signature
    let message_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let signature_hex = "22222222222222222222222222225f4fb5e3023920f62124d309f5bdf70d95045a934f278cec717300a5417313d1cdc390e761e37c0964b940c0a6f07b7361ed01";
    {
        // RecoverAccount.recover(message, signature, code_hash);
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode(format!(
            "7d7b0255{}0000000000000000000000000000000000000000000000000000000000000060{}0000000000000000000000000000000000000000000000000000000000000041{}00000000000000000000000000000000000000000000000000000000000000",
            message_hex,
            hex::encode(&SECP_LOCK_CODE_HASH),
            signature_hex,
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
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect("construct");
        state.apply_run_result(&run_result).expect("update state");
        assert_eq!(run_result.return_data, [0u8; 32]);
    }

    // Wrong code_hash
    let message_hex = "1cdeae55a5768fe14b628001c6247ae84c70310a7ddcfdc73ac68494251e46ec";
    let signature_hex = "28aa0c394487edf2211f445c47fb5f4fb5e3023920f62124d309f5bdf70d95045a934f278cec717300a5417313d1cdc390e761e37c0964b940c0a6f07b7361ed01";
    {
        // RecoverAccount.recover(message, signature, code_hash);
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode(format!(
            "7d7b0255{}0000000000000000000000000000000000000000000000000000000000000060{}0000000000000000000000000000000000000000000000000000000000000041{}00000000000000000000000000000000000000000000000000000000000000",
            message_hex,
            hex::encode(&[1u8; 32]),
            signature_hex,
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
        let tip_block_hash = store.get_tip_block_hash().unwrap();
        let err = generator
            .execute_transaction(
                &ChainView::new(&db, tip_block_hash),
                &state,
                &block_info,
                &raw_tx,
                L2TX_MAX_CYCLES,
            )
            .expect_err("construct");
        assert_eq!(
            err,
            TransactionError::InvalidExitCode(FATAL_PRECOMPILED_CONTRACTS)
        );
    }
}
