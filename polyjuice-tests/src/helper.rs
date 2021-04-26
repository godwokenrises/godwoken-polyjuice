pub use gw_common::{
    blake2b::new_blake2b,
    builtins::{CKB_SUDT_ACCOUNT_ID, RESERVED_ACCOUNT_ID},
    state::State,
    CKB_SUDT_SCRIPT_ARGS, H256,
};
use gw_config::BackendConfig;
use gw_db::schema::{COLUMN_INDEX, COLUMN_META, META_TIP_BLOCK_HASH_KEY};
pub use gw_generator::{
    account_lock_manage::{always_success::AlwaysSuccess, AccountLockManage},
    backend_manage::{Backend, BackendManage},
    dummy_state::DummyState,
    traits::StateExt,
    types::RollupContext,
    Generator, RunResult,
};
use gw_store::traits::KVStore;
pub use gw_store::{chain_view::ChainView, Store};
use gw_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{BlockInfo, LogItem, RawL2Transaction, RollupConfig, Script, Uint64},
    prelude::*,
};
use std::{fs, io::Read, path::PathBuf};

// meta contract
pub const META_VALIDATOR_PATH: &str =
    "../integration-test/godwoken/godwoken-scripts/c/build/meta-contract-validator";
pub const META_GENERATOR_PATH: &str =
    "../integration-test/godwoken/godwoken-scripts/c/build/meta-contract-generator";
pub const META_VALIDATOR_SCRIPT_TYPE_HASH: [u8; 32] = [0xa1u8; 32];
// simple UDT
pub const SUDT_VALIDATOR_PATH: &str =
    "../integration-test/godwoken/godwoken-scripts/c/build/sudt-validator";
pub const SUDT_GENERATOR_PATH: &str =
    "../integration-test/godwoken/godwoken-scripts/c/build/sudt-generator";
pub const SUDT_VALIDATOR_SCRIPT_TYPE_HASH: [u8; 32] = [0xa2u8; 32];
// polyjuice
pub const BIN_DIR: &str = "../build";
pub const GENERATOR_NAME: &str = "generator_log";
pub const VALIDATOR_NAME: &str = "validator_log";

pub const ROLLUP_SCRIPT_HASH: [u8; 32] = [0xa9u8; 32];
pub const ETH_ACCOUNT_LOCK_CODE_HASH: [u8; 32] = [0xaau8; 32];

pub const GW_LOG_SUDT_OPERATION: u8 = 0x0;
pub const GW_LOG_POLYJUICE_SYSTEM: u8 = 0x1;
pub const GW_LOG_POLYJUICE_USER: u8 = 0x2;
pub const SUDT_OPERATION_TRANSFER: u8 = 0x0;

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

#[derive(Debug, Clone)]
pub enum Log {
    SudtTransfer {
        sudt_id: u32,
        from_id: u32,
        to_id: u32,
        amount: u128,
    },
    PolyjuiceSystem {
        gas_used: u64,
        cumulative_gas_used: u64,
        created_id: u32,
        status_code: u32,
    },
    PolyjuiceUser {
        address: [u8; 20],
        data: Vec<u8>,
        topics: Vec<H256>,
    },
}

pub fn new_block_info(block_producer_id: u32, number: u64, timestamp: u64) -> BlockInfo {
    BlockInfo::new_builder()
        .block_producer_id(block_producer_id.pack())
        .number(number.pack())
        .timestamp(timestamp.pack())
        .build()
}

pub fn account_id_to_eth_address(state: &DummyState, id: u32, ethabi: bool) -> Vec<u8> {
    let offset = if ethabi { 12 } else { 0 };
    let mut data = vec![0u8; offset + 20];
    let account_script_hash = state.get_script_hash(id).unwrap();
    data[offset..offset+16].copy_from_slice(&account_script_hash.as_slice()[0..16]);
    data[offset+16..offset+20].copy_from_slice(&id.to_le_bytes()[..]);
    data
}

#[allow(dead_code)]
pub fn eth_address_to_account_id(state: &DummyState, data: &[u8]) -> Result<u32, String> {
    if data.len() != 20 {
        return Err(format!("Invalid eth address length: {}", data.len()));
    }
    let mut id_data = [0u8; 4];
    id_data.copy_from_slice(&data[16..20]);
    let account_id = u32::from_le_bytes(id_data);
    let account_script_hash = state.get_script_hash(account_id).map_err(|err.to_string()|)?;
    if data[0..16] != &account_script_hash.as_slice()[0..16] {
        return Err(format!(
            "eth address first 16 bytes not match account script hash: expected={:?}, got={:?}",
            &account_script_hash.as_slice()[0..16],
            data[0..16],
        ));
    }
    Ok(account_id)
}

pub fn new_account_script_with_nonce(from_id: u32, from_nonce: u32) -> Script {
    let mut new_account_args = [0u8; 44];
    new_account_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
    new_account_args[32..36].copy_from_slice(&CKB_SUDT_ACCOUNT_ID.to_le_bytes()[..]);
    new_account_args[36..40].copy_from_slice(&from_id.to_le_bytes()[..]);
    new_account_args[40..44].copy_from_slice(&from_nonce.to_le_bytes()[..]);
    Script::new_builder()
        .code_hash(PROGRAM_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(new_account_args.to_vec()).pack())
        .build()
}
pub fn new_account_script(state: &mut DummyState, from_id: u32, current_nonce: bool) -> Script {
    let mut from_nonce = state.get_nonce(from_id).unwrap();
    if !current_nonce {
        from_nonce -= 1;
    }
    new_account_script_with_nonce(from_id, from_nonce)
}

#[derive(Default, Debug)]
pub struct PolyjuiceArgsBuilder {
    is_create: bool,
    is_static: bool,
    gas_limit: u64,
    gas_price: u128,
    value: u128,
    input: Vec<u8>,
}

impl PolyjuiceArgsBuilder {
    pub fn do_create(mut self, value: bool) -> Self {
        self.is_create = value;
        self
    }
    pub fn static_call(mut self, value: bool) -> Self {
        self.is_static = value;
        self
    }
    pub fn gas_limit(mut self, value: u64) -> Self {
        self.gas_limit = value;
        self
    }
    pub fn gas_price(mut self, value: u128) -> Self {
        self.gas_price = value;
        self
    }
    pub fn value(mut self, new_value: u128) -> Self {
        self.value = new_value;
        self
    }
    pub fn input(mut self, value: &[u8]) -> Self {
        self.input = value.to_vec();
        self
    }
    pub fn build(self) -> Vec<u8> {
        let mut output: Vec<u8> = vec![0u8; 62];
        if self.is_create {
            output[0] = 3;
        }
        if self.is_static {
            output[1] = 1;
        }
        output[2..10].copy_from_slice(&self.gas_limit.to_le_bytes()[..]);
        output[10..26].copy_from_slice(&self.gas_price.to_le_bytes()[..]);
        output[26..42].copy_from_slice(&[0u8; 16][..]);
        output[42..58].copy_from_slice(&self.value.to_be_bytes()[..]);
        output[58..62].copy_from_slice(&(self.input.len() as u32).to_le_bytes()[..]);
        output.extend(self.input);
        output
    }
}

pub fn setup() -> (Store, DummyState, Generator, u32) {
    let store = Store::open_tmp().unwrap();
    let mut state = DummyState::default();
    let reserved_id = state
        .create_account_from_script(
            Script::new_builder()
                .code_hash(META_VALIDATOR_SCRIPT_TYPE_HASH.clone().pack())
                .hash_type(ScriptHashType::Type.into())
                .build(),
        )
        .unwrap();
    assert_eq!(
        reserved_id, RESERVED_ACCOUNT_ID,
        "reserved account id must be zero"
    );

    // setup CKB simple UDT contract
    let ckb_sudt_script = build_l2_sudt_script(CKB_SUDT_SCRIPT_ARGS);
    // assert_eq!(
    //     ckb_sudt_script.hash(),
    //     CKB_SUDT_SCRIPT_HASH,
    //     "ckb simple UDT script hash"
    // );
    let ckb_sudt_id = state.create_account_from_script(ckb_sudt_script).unwrap();
    assert_eq!(
        ckb_sudt_id, CKB_SUDT_ACCOUNT_ID,
        "ckb simple UDT account id"
    );

    let mut args = [0u8; 36];
    args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
    args[32..36].copy_from_slice(&ckb_sudt_id.to_le_bytes()[..]);
    let creator_account_id = state
        .create_account_from_script(
            Script::new_builder()
                .code_hash(PROGRAM_CODE_HASH.pack())
                .hash_type(ScriptHashType::Type.into())
                .args(args.to_vec().pack())
                .build(),
        )
        .expect("create account");

    // ==== Build generator
    let configs = vec![
        BackendConfig {
            validator_path: META_VALIDATOR_PATH.into(),
            generator_path: META_GENERATOR_PATH.into(),
            validator_script_type_hash: META_VALIDATOR_SCRIPT_TYPE_HASH.into(),
        },
        BackendConfig {
            validator_path: SUDT_VALIDATOR_PATH.into(),
            generator_path: SUDT_GENERATOR_PATH.into(),
            validator_script_type_hash: SUDT_VALIDATOR_SCRIPT_TYPE_HASH.into(),
        },
    ];
    let mut backend_manage = BackendManage::from_config(configs).expect("default backend");
    // NOTICE in this test we won't need SUM validator
    backend_manage.register_backend(Backend {
        validator: VALIDATOR_PROGRAM.clone(),
        generator: GENERATOR_PROGRAM.clone(),
        validator_script_type_hash: PROGRAM_CODE_HASH.clone().into(),
    });
    let mut account_lock_manage = AccountLockManage::default();
    account_lock_manage.register_lock_algorithm(H256::zero(), Box::new(AlwaysSuccess::default()));
    let rollup_config = RollupConfig::new_builder()
        .allowed_contract_type_hashes(
            vec![
                META_VALIDATOR_SCRIPT_TYPE_HASH.clone().pack(),
                SUDT_VALIDATOR_SCRIPT_TYPE_HASH.clone().pack(),
                PROGRAM_CODE_HASH.clone().pack(),
            ]
            .pack(),
        )
        .build();
    let rollup_context = RollupContext {
        rollup_script_hash: ROLLUP_SCRIPT_HASH.clone().into(),
        rollup_config,
    };
    let generator = Generator::new(backend_manage, account_lock_manage, rollup_context);

    let tx = store.begin_transaction();
    let tip_block_number: Uint64 = 8.pack();
    let tip_block_hash = [8u8; 32];
    tx.insert_raw(COLUMN_META, META_TIP_BLOCK_HASH_KEY, &tip_block_hash[..])
        .unwrap();
    tx.insert_raw(
        COLUMN_INDEX,
        tip_block_number.as_slice(),
        &tip_block_hash[..],
    )
    .unwrap();
    tx.insert_raw(
        COLUMN_INDEX,
        &tip_block_hash[..],
        tip_block_number.as_slice(),
    )
    .unwrap();
    tx.commit().unwrap();
    (store, state, generator, creator_account_id)
}

pub fn deploy(
    generator: &Generator,
    store: &Store,
    state: &mut DummyState,
    creator_account_id: u32,
    from_id: u32,
    init_code: &str,
    gas_limit: u64,
    value: u128,
    block_number: u64,
) -> RunResult {
    let block_info = new_block_info(0, block_number, block_number);
    let input = hex::decode(init_code).unwrap();
    let args = PolyjuiceArgsBuilder::default()
        .do_create(true)
        .gas_limit(gas_limit)
        .gas_price(1)
        .value(value)
        .input(&input)
        .build();
    let raw_tx = RawL2Transaction::new_builder()
        .from_id(from_id.pack())
        .to_id(creator_account_id.pack())
        .args(Bytes::from(args).pack())
        .build();
    let db = store.begin_transaction();
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    let run_result = generator
        .execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            state,
            &block_info,
            &raw_tx,
        )
        .expect("construct");
    state.apply_run_result(&run_result).expect("update state");
    run_result
}

pub fn compute_create2_script(
    sudt_id: u32,
    sender_account_id: u32,
    create2_salt: &[u8],
    init_code: &[u8],
) -> Script {
    assert_eq!(create2_salt.len(), 32);

    let init_code_hash = tiny_keccak::keccak256(init_code);
    let mut script_args = vec![0u8; 32 + 4 + 1 + 4 + 32 + 32];
    script_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH[..]);
    script_args[32..(32 + 4)].copy_from_slice(&sudt_id.to_le_bytes()[..]);
    script_args[(32 + 4)] = 0xff;
    script_args[(32 + 4 + 1)..(32 + 4 + 1 + 4)]
        .copy_from_slice(&sender_account_id.to_le_bytes()[..]);
    script_args[(32 + 4 + 1 + 4)..(32 + 4 + 1 + 4 + 32)].copy_from_slice(&create2_salt[..]);
    script_args[(32 + 4 + 1 + 4 + 32)..(32 + 4 + 1 + 4 + 32 + 32)]
        .copy_from_slice(&init_code_hash[..]);
    println!("init_code: {}", hex::encode(init_code));
    println!("create2_script_args: {}", hex::encode(&script_args[..]));
    Script::new_builder()
        .code_hash(PROGRAM_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(script_args.pack())
        .build()
}

pub fn parse_log(item: &LogItem) -> Log {
    let service_flag: u8 = item.service_flag().into();
    let raw_data = item.data().raw_data();
    let data = raw_data.as_ref();
    match service_flag {
        GW_LOG_SUDT_OPERATION => {
            if data[0] != SUDT_OPERATION_TRANSFER {
                panic!("Not a sudt transfer prefix: {}", data[1]);
            }
            let sudt_id: u32 = item.account_id().unpack();
            if data.len() != (1 + 4 + 4 + 16) {
                panic!("Invalid data length: {}", data.len());
            }
            let data = &data[1..];

            let mut u32_bytes = [0u8; 4];
            u32_bytes.copy_from_slice(&data[0..4]);
            let from_id = u32::from_le_bytes(u32_bytes.clone());

            u32_bytes.copy_from_slice(&data[4..8]);
            let to_id = u32::from_le_bytes(u32_bytes);

            let mut u128_bytes = [0u8; 16];
            u128_bytes.copy_from_slice(&data[8..24]);
            let amount = u128::from_le_bytes(u128_bytes);
            Log::SudtTransfer {
                sudt_id,
                from_id,
                to_id,
                amount,
            }
        }
        GW_LOG_POLYJUICE_SYSTEM => {
            if data.len() != (8 + 8 + 4 + 4 + 4) {
                panic!("invalid system log raw data length: {}", data.len());
            }

            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&data[0..8]);
            let gas_used = u64::from_le_bytes(u64_bytes.clone());
            u64_bytes.copy_from_slice(&data[8..16]);
            let cumulative_gas_used = u64::from_le_bytes(u64_bytes.clone());

            let mut u32_bytes = [0u8; 4];
            u32_bytes.copy_from_slice(&data[16..20]);
            let created_id = u32::from_le_bytes(u32_bytes.clone());
            u32_bytes.copy_from_slice(&data[20..24]);
            let status_code = u32::from_le_bytes(u32_bytes.clone());
            Log::PolyjuiceSystem {
                gas_used,
                cumulative_gas_used,
                created_id,
                status_code,
            }
        }
        GW_LOG_POLYJUICE_USER => {
            let mut offset: usize = 0;
            let mut address = [0u8; 20];
            address.copy_from_slice(&data[offset..offset + 20]);
            offset += 20;
            let mut data_size_bytes = [0u8; 4];
            data_size_bytes.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
            let data_size: u32 = u32::from_le_bytes(data_size_bytes);
            let mut log_data = vec![0u8; data_size as usize];
            log_data.copy_from_slice(&data[offset..offset + (data_size as usize)]);
            offset += data_size as usize;
            println!("data_size: {}", data_size);

            let mut topics_count_bytes = [0u8; 4];
            topics_count_bytes.copy_from_slice(&data[offset..offset + 4]);
            offset += 4;
            let topics_count: u32 = u32::from_le_bytes(topics_count_bytes);
            let mut topics = Vec::new();
            println!("topics_count: {}", topics_count);
            for _ in 0..topics_count {
                let mut topic = [0u8; 32];
                topic.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                topics.push(topic.into());
            }
            if offset != data.len() {
                panic!(
                    "Too many bytes for polyjuice user log data: offset={}, data.len()={}",
                    offset,
                    data.len()
                );
            }
            Log::PolyjuiceUser {
                address,
                data: log_data,
                topics,
            }
        }
        _ => {
            panic!("invalid log service flag: {}", service_flag);
        }
    }
}

pub fn simple_storage_get(
    store: &Store,
    state: &DummyState,
    generator: &Generator,
    block_number: u64,
    from_id: u32,
    ss_account_id: u32,
) -> RunResult {
    let block_info = new_block_info(0, block_number, block_number);
    let input = hex::decode("6d4ce63c").unwrap();
    let args = PolyjuiceArgsBuilder::default()
        .static_call(true)
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
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    generator
        .execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            state,
            &block_info,
            &raw_tx,
        )
        .expect("construct")
}

pub fn build_l2_sudt_script(args: [u8; 32]) -> Script {
    let mut script_args = Vec::with_capacity(64);
    script_args.extend(&ROLLUP_SCRIPT_HASH);
    script_args.extend(&args[..]);
    Script::new_builder()
        .args(Bytes::from(script_args).pack())
        .code_hash(SUDT_VALIDATOR_SCRIPT_TYPE_HASH.clone().pack())
        .hash_type(ScriptHashType::Type.into())
        .build()
}

pub fn build_eth_l2_script(args: [u8; 20]) -> Script {
    let mut script_args = Vec::with_capacity(32 + 20);
    script_args.extend(&ROLLUP_SCRIPT_HASH);
    script_args.extend(&args[..]);
    Script::new_builder()
        .args(Bytes::from(script_args).pack())
        .code_hash(ETH_ACCOUNT_LOCK_CODE_HASH.clone().pack())
        .hash_type(ScriptHashType::Type.into())
        .build()
}
