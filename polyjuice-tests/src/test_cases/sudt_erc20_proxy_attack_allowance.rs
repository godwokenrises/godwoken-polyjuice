//! Test ERC20 contract
//!   See ./evm-contracts/ERC20.bin

use crate::helper::{
    account_id_to_eth_address, build_eth_l2_script, deploy, new_account_script, new_block_info,
    setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const SUDT_ERC20_PROXY_CODE: &str = include_str!("../../../solidity/erc20/SudtERC20Proxy.bin");
const SUDT_ERC20_PROXY_ATTACK_CODE: &str = include_str!("./evm-contracts/AttackSudtERC20Proxy.bin");

#[test]
fn test_attack_allowance() {
    let (store, mut state, generator, creator_account_id) = setup();
    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();

    let from_script = build_eth_l2_script([1u8; 20]);
    let from_script_hash = from_script.hash();
    let from_short_address = &from_script_hash[0..20];
    let from_id = state.create_account_from_script(from_script).unwrap();
    let mint_balance: u128 = 400000;
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address, mint_balance)
        .unwrap();
    let target_script = build_eth_l2_script([2u8; 20]);
    let target_script_hash = target_script.hash();
    let target_short_address = &target_script_hash[0..20];
    let target_id = state.create_account_from_script(target_script).unwrap();

    let from_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_short_address)
        .unwrap();
    assert_eq!(from_balance, mint_balance);
    let target_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_address)
        .unwrap();
    assert_eq!(target_balance, 0);

    let mut block_number = 0;

    println!("================");
    // Deploy SudtERC20Proxy
    {
        // ethabi encode params -v string "test" -v string "tt" -v uint256 000000000000000000000000000000000000000204fce5e3e250261100000000 -v uint256 0000000000000000000000000000000000000000000000000000000000000001
        let args = format!("000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000204fce5e3e25026110000000000000000000000000000000000000000000000000000000000000000000000{:02x}0000000000000000000000000000000000000000000000000000000000000004746573740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000027474000000000000000000000000000000000000000000000000000000000000", CKB_SUDT_ACCOUNT_ID);
        let init_code = format!("{}{}", SUDT_ERC20_PROXY_CODE, args);
        let _run_result = deploy(
            &generator,
            &store,
            &mut state,
            creator_account_id,
            from_id,
            init_code.as_str(),
            150000,
            0,
            block_producer_id,
            block_number,
        );
    }
    let proxy_account_script = new_account_script(&mut state, creator_account_id, from_id, false);
    let proxy_account_id = state
        .get_account_id_by_script_hash(&proxy_account_script.hash().into())
        .unwrap()
        .unwrap();
    println!("================");

    // Deploy AttackSudtERC20Proxy
    {
        let args = format!(
            "00000000000000000000000000000000000000000000000000000000000000{:02x}",
            CKB_SUDT_ACCOUNT_ID,
        );
        let init_code = format!("{}{}", SUDT_ERC20_PROXY_ATTACK_CODE, args);
        let _run_result = deploy(
            &generator,
            &store,
            &mut state,
            creator_account_id,
            from_id,
            init_code.as_str(),
            50000,
            0,
            block_producer_id,
            block_number,
        );
    }
    block_number += 1;
    let attack_account_script = new_account_script(&mut state, creator_account_id, from_id, false);
    let attack_account_id = state
        .get_account_id_by_script_hash(&attack_account_script.hash().into())
        .unwrap()
        .unwrap();
    println!("================");

    block_number += 1;

    {
        // AttackSudtERC20Proxy.sol => setAllowance(from_id, target_id, 3e8)
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        let input = hex::decode(format!(
            "da46098c{}{}{}",
            hex::encode(account_id_to_eth_address(&state, from_id, true)),
            hex::encode(account_id_to_eth_address(&state, target_id, true)),
            "00000000000000000000000000000000000000000000000000000000000003e8",
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
            .to_id(attack_account_id.pack())
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
    }

    let target_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_address)
        .unwrap();
    assert_eq!(target_balance, 0);

    {
        // AttackSudtERC20Proxy.sol => attack1(from_id, target_id, 100000)
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        let input = hex::decode(format!(
            "7483118f{}{}{}{}",
            hex::encode(account_id_to_eth_address(&state, proxy_account_id, true)),
            hex::encode(account_id_to_eth_address(&state, from_id, true)),
            hex::encode(account_id_to_eth_address(&state, target_id, true)),
            "00000000000000000000000000000000000000000000000000000000000003e8",
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
            .to_id(attack_account_id.pack())
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
        // 0 means the delegate call failed
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        state.apply_run_result(&run_result).expect("update state");
    }

    let target_balance = state
        .get_sudt_balance(CKB_SUDT_ACCOUNT_ID, target_short_address)
        .unwrap();
    assert_eq!(target_balance, 0);
}
