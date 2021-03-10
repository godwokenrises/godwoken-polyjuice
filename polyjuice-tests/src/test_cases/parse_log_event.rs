//! Test parse log
//!   See ./evm-contracts/LogEvents.sol

use crate::helper::{
    account_id_to_eth_address, build_l2_sudt_script, deploy, get_chain_view, new_account_script,
    new_block_info, parse_log, setup, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

const INIT_CODE: &str = include_str!("./evm-contracts/LogEvents.bin");

#[test]
fn test_parse_log_event() {
    let (store, mut tree, generator, creator_account_id) = setup();

    let from_script = build_l2_sudt_script([1u8; 32]);
    let from_id = tree.create_account_from_script(from_script).unwrap();
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 200000)
        .unwrap();

    let from_balance1 = tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_id).unwrap();
    println!("balance of {} = {}", from_id, from_balance1);

    let mut block_number = 0;
    let deploy_value = 0xfa;
    let run_result = deploy(
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
    let contract_account_script = new_account_script(&mut tree, from_id, false);
    let new_account_id = tree
        .get_account_id_by_script_hash(&contract_account_script.hash().into())
        .unwrap()
        .unwrap();
    assert_eq!(run_result.logs.len(), 1);
    let log_item = &run_result.logs[0];
    let log_account_id: u32 = log_item.account_id().unpack();
    assert_eq!(log_account_id, new_account_id);
    let log_data: Bytes = log_item.data().raw_data();
    let polyjuice_log = parse_log(log_data.as_ref());
    println!("polyjuice_log: {:?}", polyjuice_log);
    assert_eq!(
        &polyjuice_log.address[..],
        &account_id_to_eth_address(new_account_id, false)[..]
    );
    assert_eq!(polyjuice_log.data[31], deploy_value as u8);
    assert_eq!(polyjuice_log.data[63], 1); // true
    assert_eq!(
        polyjuice_log.topics[1].as_slice(),
        account_id_to_eth_address(from_id, true)
    );

    block_number += 1;
    {
        // LogEvents.log();
        let block_info = new_block_info(0, block_number, block_number);
        let input = hex::decode("51973ec9").unwrap();
        let call_value = 0xac;
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(21000)
            .gas_price(1)
            .value(call_value)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = generator
            .execute_transaction(&get_chain_view(&store), &tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");

        assert_eq!(run_result.logs.len(), 1);
        let log_item = &run_result.logs[0];
        let log_account_id: u32 = log_item.account_id().unpack();
        assert_eq!(log_account_id, new_account_id);
        let log_data: Bytes = log_item.data().raw_data();
        let polyjuice_log = parse_log(log_data.as_ref());
        println!("polyjuice_log: {:?}", polyjuice_log);
        assert_eq!(
            &polyjuice_log.address[..],
            &account_id_to_eth_address(new_account_id, false)[..]
        );
        assert_eq!(polyjuice_log.data[31], call_value as u8);
        assert_eq!(polyjuice_log.data[63], 0); // false
        assert_eq!(
            polyjuice_log.topics[1].as_slice(),
            account_id_to_eth_address(from_id, true)
        );
    }
}
