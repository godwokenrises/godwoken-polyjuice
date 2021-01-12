//! Test SimpleStorage
//!   See ./evm-contracts/SimpleStorage.sol

use crate::helper::{
    new_block_info,
    encode_polyjuice_args,
    setup,
    CKB_SUDT_ACCOUNT_ID,
    PROGRAM_CODE_HASH,
};
use gw_common::state::State;
use gw_generator::traits::StateExt;
use gw_types::{
    bytes::Bytes,
    packed::{RawL2Transaction, Script},
    prelude::*,
};


#[test]
fn test_simple_storage() {
    let (mut tree, generator, creator_contract_id) = setup();

    let from_script = gw_generator::sudt::build_l2_sudt_script([1u8; 32].into());
    let from_id = tree.create_account_from_script(from_script).unwrap();
    tree.mint_sudt(CKB_SUDT_ACCOUNT_ID, from_id, 200000).unwrap();


    let from_balance1 = tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_id).unwrap();
    println!("balance of {} = {}", from_id, from_balance1);
    let from_nonce = tree.get_nonce(from_id).unwrap();
    let mut new_account_args = [0u8; 12];
    new_account_args[0..4].copy_from_slice(&CKB_SUDT_ACCOUNT_ID.to_le_bytes()[..]);
    new_account_args[4..8].copy_from_slice(&from_id.to_le_bytes()[..]);
    new_account_args[8..12].copy_from_slice(&from_nonce.to_le_bytes()[..]);
    let new_account_script = Script::new_builder()
        .code_hash(PROGRAM_CODE_HASH.pack())
        .args(Bytes::from(new_account_args.to_vec()).pack())
        .build();
    {
        // Deploy SimpleStorage
        let block_info = new_block_info(0, 1, 0);
        let input = hex::decode("60806040525b607b60006000508190909055505b610018565b60db806100266000396000f3fe60806040526004361060295760003560e01c806360fe47b114602f5780636d4ce63c14605b576029565b60006000fd5b60596004803603602081101560445760006000fd5b81019080803590602001909291905050506084565b005b34801560675760006000fd5b50606e6094565b6040518082815260200191505060405180910390f35b8060006000508190909055505b50565b6000600060005054905060a2565b9056fea2646970667358221220044daf4e34adffc61c3bb9e8f40061731972d32db5b8c2bc975123da9e988c3e64736f6c63430006060033").unwrap();
        let args = encode_polyjuice_args(true, false, 21000, 1, 0, &input[..]);
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(creator_contract_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = generator
            .execute(&tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");
        println!("result {:?}", run_result);
        println!("return_data: {}", hex::encode(&run_result.return_data[..]));
    }

    let new_account_id = tree.get_account_id_by_script_hash(&new_account_script.hash().into()).unwrap().unwrap();
    let from_balance2 = tree.get_sudt_balance(CKB_SUDT_ACCOUNT_ID, from_id).unwrap();
    println!("balance of {} = {}", from_id, from_balance2);
    {
        // SimpleStorage.set(0x0d10);
        let block_info = new_block_info(0, 2, 0);
        let input = hex::decode("60fe47b10000000000000000000000000000000000000000000000000000000000000d10").unwrap();
        let args = encode_polyjuice_args(false, false, 21000, 1, 0, &input[..]);
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = generator
            .execute(&tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");
        println!("result {:?}", run_result);
    }

    {
        // SimpleStorage.get();
        let block_info = new_block_info(0, 3, 0);
        let input = hex::decode("6d4ce63c").unwrap();
        let args = encode_polyjuice_args(false, true, 21000, 1, 0, &input[..]);
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(new_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = generator
            .execute(&tree, &block_info, &raw_tx)
            .expect("construct");
        tree.apply_run_result(&run_result).expect("update state");
        let mut expected_return_data = vec![0u8; 32];
        expected_return_data[30] = 0x0d;
        expected_return_data[31] = 0x10;
        assert_eq!(run_result.return_data, expected_return_data);
        println!("result {:?}", run_result);
    }
}
