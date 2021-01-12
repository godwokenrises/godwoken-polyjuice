pub use gw_generator::{
    account_lock_manage::{always_success::AlwaysSuccess, AccountLockManage},
    backend_manage::{Backend, BackendManage, META_CONTRACT_VALIDATOR_CODE_HASH},
    dummy_state::DummyState,
    traits::StateExt,
    Generator,
};
pub use gw_common::{
    state::State,
    H256, blake2b::new_blake2b,
    builtins::{CKB_SUDT_ACCOUNT_ID, RESERVED_ACCOUNT_ID},
    CKB_SUDT_SCRIPT_ARGS, CKB_SUDT_SCRIPT_HASH,
};
use gw_types::{
    bytes::Bytes,
    packed::{Script, BlockInfo},
    prelude::*,
};
use std::{fs, io::Read, path::PathBuf};

pub const BIN_DIR: &'static str = "../build";
pub const GENERATOR_NAME: &'static str = "generator";
pub const VALIDATOR_NAME: &'static str = "validator";

lazy_static::lazy_static! {
    pub static ref GENERATOR_PROGRAM: Bytes = {
        let mut buf = Vec::new();
        let mut path = PathBuf::new();
        path.push(&BIN_DIR);
        path.push(&GENERATOR_NAME);
        let mut f = fs::File::open(&path).expect("load program");
        f.read_to_end(&mut buf).expect("read program");
        Bytes::from(buf.to_vec())
    };
    pub static ref VALIDATOR_PROGRAM: Bytes = {
        let mut buf = Vec::new();
        let mut path = PathBuf::new();
        path.push(&BIN_DIR);
        path.push(&VALIDATOR_NAME);
        let mut f = fs::File::open(&path).expect("load program");
        f.read_to_end(&mut buf).expect("read program");
        Bytes::from(buf.to_vec())
    };
    pub static ref PROGRAM_CODE_HASH: [u8; 32] = {
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

pub fn encode_polyjuice_args(
    is_create: bool,
    is_static: bool,
    gas_limit: u64,
    gas_price: u128,
    value: u128,
    input: &[u8],
) -> Vec<u8> {
    let mut output: Vec<u8> = vec![0u8; 62];
    if is_create {
        output[0] = 3;
    }
    if is_static {
        output[1] = 1;
    }
    output[2..10].copy_from_slice(&gas_limit.to_le_bytes()[..]);
    output[10..26].copy_from_slice(&gas_price.to_le_bytes()[..]);
    output[26..42].copy_from_slice(&[0u8; 16][..]);
    output[42..58].copy_from_slice(&value.to_be_bytes()[..]);
    output[58..62].copy_from_slice(&(input.len() as u32).to_le_bytes()[..]);
    output.extend(input);
    output
}

pub fn setup() -> (DummyState, Generator, u32) {
    let mut tree = DummyState::default();
    let reserved_id = tree.create_account_from_script(
        Script::new_builder()
            .code_hash({
                let code_hash: [u8; 32] = (*META_CONTRACT_VALIDATOR_CODE_HASH).into();
                code_hash.pack()
            })
            .build(),
    ).unwrap();
    assert_eq!(
        reserved_id, RESERVED_ACCOUNT_ID,
        "reserved account id must be zero"
    );

    // setup CKB simple UDT contract
    let ckb_sudt_script = gw_generator::sudt::build_l2_sudt_script(CKB_SUDT_SCRIPT_ARGS.into());
    assert_eq!(
        ckb_sudt_script.hash(),
        CKB_SUDT_SCRIPT_HASH,
        "ckb simple UDT script hash"
    );
    let ckb_sudt_id = tree.create_account_from_script(ckb_sudt_script).unwrap();
    assert_eq!(
        ckb_sudt_id, CKB_SUDT_ACCOUNT_ID,
        "ckb simple UDT account id"
    );

    let creator_contract_id = tree
        .create_account_from_script(
            Script::new_builder()
                .code_hash(PROGRAM_CODE_HASH.pack())
                .args(ckb_sudt_id.to_le_bytes().to_vec().pack())
                .build(),
        )
        .expect("create account");

    // ==== Build generator
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

    (tree, generator, creator_contract_id)
}
