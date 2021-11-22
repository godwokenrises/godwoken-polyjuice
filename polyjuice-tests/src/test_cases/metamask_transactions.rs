//! Test transfer from EoA to EoA using Metamask

use crate::helper::{
    build_eth_l2_script, deploy, new_account_script, new_block_info, setup,
    update_eth_address_registry, PolyjuiceArgsBuilder, CKB_SUDT_ACCOUNT_ID, L2TX_MAX_CYCLES,
    SUDT_ERC20_PROXY_USER_DEFINED_DECIMALS_CODE,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_store::chain_view::ChainView;
use gw_types::{bytes::Bytes, packed::RawL2Transaction, prelude::*};

#[test]
fn test_transfer_by_metamask() {
    let (store, mut state, generator, creator_account_id) = setup();

    let block_producer_script = build_eth_l2_script([0x99u8; 20]);
    let block_producer_script_hash = block_producer_script.hash();
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .unwrap();
    state
        .mint_sudt(
            CKB_SUDT_ACCOUNT_ID,
            &block_producer_script_hash[..20],
            2000000,
        )
        .unwrap();

    let eth_address1 = [1u8; 20];
    let from_script1 = build_eth_l2_script(eth_address1.clone());
    let from_script_hash1 = from_script1.hash();
    let from_id1 = state.create_account_from_script(from_script1).unwrap();
    update_eth_address_registry(&mut state, &eth_address1, &from_script_hash1);

    let eth_address2 = [2u8; 20];
    let from_script2 = build_eth_l2_script(eth_address2.clone());
    let from_script_hash2 = from_script2.hash();
    let _from_id2 = state.create_account_from_script(from_script2).unwrap();
    update_eth_address_registry(&mut state, &eth_address2, &from_script_hash2);

    let eth_address3 = [3u8; 20];
    let from_script3 = build_eth_l2_script(eth_address3.clone());
    let from_script_hash3 = from_script3.hash();
    let _from_short_address3 = &from_script_hash3[0..20];
    let _from_id3 = state.create_account_from_script(from_script3).unwrap();
    update_eth_address_registry(&mut state, &eth_address3, &from_script_hash3);

    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, &from_script_hash1[..20], 2000000)
        .unwrap();
    // state
    //     .mint_sudt(CKB_SUDT_ACCOUNT_ID, from_short_address3, 80000)
    //     .unwrap();

    // deploy SudtERC20Proxy contract
    let block_number = 1;
    let args = format!("00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000024cb016ea00000000000000000000000000000000000000000000000000000000000000{:02x}00000000000000000000000000000000000000000000000000000000000000{:02x}000000000000000000000000000000000000000000000000000000000000000e65726332305f646563696d616c7300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034445430000000000000000000000000000000000000000000000000000000000", CKB_SUDT_ACCOUNT_ID, 8);
    let init_code = format!("{}{}", SUDT_ERC20_PROXY_USER_DEFINED_DECIMALS_CODE, args);
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        creator_account_id,
        block_producer_id,
        init_code.as_str(),
        122000,
        0,
        block_producer_id,
        block_number,
    );
    let ckb_proxy_contract_script =
        new_account_script(&state, creator_account_id, block_producer_id, false);
    let script_hash = ckb_proxy_contract_script.hash();
    let ckb_proxy_contract_account_id = state
        .get_account_id_by_script_hash(&script_hash.into())
        .unwrap()
        .unwrap();
    let mut eth_address_of_ckb_proxy_contract = [0u8; 20];
    eth_address_of_ckb_proxy_contract[..20].copy_from_slice(&script_hash[0..20]);
    update_eth_address_registry(&mut state, &eth_address_of_ckb_proxy_contract, &script_hash);

    // assume that Ethereum JSON RPC request sent by Metamask is:
    // ```JSON
    // {
    //   method: 'eth_sendTransaction',
    //   params: [
    //     {
    //       from: eth_address1,
    //       to: eth_address3,
    //       value: '0x29a2241af62c0000',
    //       gasPrice: '0x09184e72a000',
    //       gas: '0x2710',
    //     },
    //   ],
    // }
    // ```
    //
    // if tx.data is null && to_address is EoA or notExistEoA,
    // then handle it as a simple pETH transfer, using ERC20_Proxy(sUDT_ID = 1)
    //
    // The RawL2Transaction from Web3 RPC to Godwoken RPC:
    // {
    //     from_id: from_id1,
    //     to_id: ckb_proxy_contract_account_id,
    //     nonce: Uint32,
    //     args: Bytes,
    // }
    // the args above:
    //     header     : [u8; 8]   (header[0..7] = "ETHPOLY",
    //                             header[7]    = call_kind { 0: CALL, 3: CREATE })
    //     gas_limit  : u64      (little endian)
    //     gas_price  : u128     (little endian)
    //     value      : u128     (little endian)
    //     input_size : u32      (little endian)
    //     input_data : [u8; input_size]   (input data)
    // the input_data contains native eth_addresses:
    println!("eth_address1: {}", hex::encode(eth_address1));
    println!("eth_address2: {}", hex::encode(eth_address2));
    println!("eth_address3: {}", hex::encode(eth_address3));
    for (idx, (from_id, args_str, return_data_str)) in [
        // balanceOf(eoa1)
        (
            from_id1,
            format!("70a08231000000000000000000000000{}", hex::encode(eth_address1)),
            "00000000000000000000000000000000000000000000000000000000001E8480",
        ),
        // balanceOf(eoa2)
        (
            from_id1,
            format!("70a08231000000000000000000000000{}", hex::encode(eth_address2)),
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        // transfer("eoa2", 0x480)
        (
            from_id1,
            format!(
                "a9059cbb000000000000000000000000{}0000000000000000000000000000000000000000000000000000000000000480",
                hex::encode(eth_address2)
            ),
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        // balanceOf(eoa2)
        (
            from_id1,
            format!("70a08231000000000000000000000000{}", hex::encode(eth_address2)),
            "0000000000000000000000000000000000000000000000000000000000000480",
        ),
    ]
    .iter()
    .enumerate()
    {
        println!("test index: {}", idx);
        let block_number = 2 + idx as u64;
        let block_info = new_block_info(block_producer_id, block_number, block_number);
        let input = hex::decode(args_str).unwrap();
        let args = PolyjuiceArgsBuilder::default()
            .using_native_eth_address(true) // use new L2TX format
            .gas_limit(80000)
            .gas_price(1)
            .value(0)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(ckb_proxy_contract_account_id.pack())
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
            .expect("transfer from EoA to EoA, using native_eth_address");
        state.apply_run_result(&run_result).expect("update state");
        assert_eq!(
            run_result.return_data,
            hex::decode(return_data_str).unwrap()
        );
    }
    // println!(
    //     "result {}",
    //     serde_json::to_string_pretty(&RunResult::from(run_result)).unwrap()
    // );
}
