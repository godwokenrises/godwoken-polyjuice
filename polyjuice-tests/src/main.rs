use gw_generator::{
    account_lock_manage::{always_success::AlwaysSuccess, AccountLockManage},
    backend_manage::{Backend, BackendManage},
    dummy_state::DummyState,
    traits::StateExt,
    Generator,
};
use gw_common::{H256, blake2b::new_blake2b};
use gw_types::{
    bytes::Bytes,
    packed::{RawL2Transaction, Script, BlockInfo},
    prelude::*,
};
use std::{fs, io::Read, path::PathBuf};

const BIN_DIR: &'static str = "../build";
const GENERATOR_NAME: &'static str = "generator";
const VALIDATOR_NAME: &'static str = "validator";

lazy_static::lazy_static! {
    static ref GENERATOR_PROGRAM: Bytes = {
        let mut buf = Vec::new();
        let mut path = PathBuf::new();
        path.push(&BIN_DIR);
        path.push(&GENERATOR_NAME);
        let mut f = fs::File::open(&path).expect("load program");
        f.read_to_end(&mut buf).expect("read program");
        Bytes::from(buf.to_vec())
    };
    static ref VALIDATOR_PROGRAM: Bytes = {
        let mut buf = Vec::new();
        let mut path = PathBuf::new();
        path.push(&BIN_DIR);
        path.push(&VALIDATOR_NAME);
        let mut f = fs::File::open(&path).expect("load program");
        f.read_to_end(&mut buf).expect("read program");
        Bytes::from(buf.to_vec())
    };
    static ref PROGRAM_CODE_HASH: [u8; 32] = {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&VALIDATOR_PROGRAM);
        hasher.finalize(&mut buf);
        buf
    };
}

pub fn new_block_info(aggregator_id: u32, number: u64, timestamp: u64) -> BlockInfo {
    BlockInfo::new_builder()
        .aggregator_id(aggregator_id.pack())
        .number(number.pack())
        .timestamp(timestamp.pack())
        .build()
}

#[test]
fn test_example_sum() {
    let mut tree = DummyState::default();
    let from_id: u32 = 2;
    let init_value: u64 = 0;

    let contract_id = tree
        .create_account_from_script(
            Script::new_builder()
                .code_hash(PROGRAM_CODE_HASH.pack())
                .args([0u8; 20].to_vec().pack())
                .build(),
        )
        .expect("create account");

    // run handle message
    {
        let mut backend_manage = BackendManage::default();
        // NOTICE in this test we won't need SUM validator
        backend_manage.register_backend(Backend::from_binaries(
            VALIDATOR_PROGRAM.clone(),
            GENERATOR_PROGRAM.clone(),
        ));
        let mut account_lock_manage = AccountLockManage::default();
        account_lock_manage
            .register_lock_algorithm(H256::zero(), Box::new(AlwaysSuccess::default()));
        let generator = Generator::new(backend_manage, account_lock_manage, Default::default());
        let mut sum_value = init_value;
        for (number, add_value) in &[(1u64, 7u64), (2u64, 16u64)] {
            let block_info = new_block_info(0, *number, 0);
            let raw_tx = RawL2Transaction::new_builder()
                .from_id(from_id.pack())
                .to_id(contract_id.pack())
                .args(Bytes::from(add_value.to_le_bytes().to_vec()).pack())
                .build();
            let run_result = generator
                .execute(&tree, &block_info, &raw_tx)
                .expect("construct");
            let return_value = {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&run_result.return_data);
                u64::from_le_bytes(buf)
            };
            sum_value += add_value;
            assert_eq!(return_value, sum_value);
            tree.apply_run_result(&run_result).expect("update state");
            println!("result {:?}", run_result);
        }
    }
}

fn main() {
    println!("Hello, world!");
}
