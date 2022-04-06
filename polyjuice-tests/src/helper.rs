pub use gw_common::{
    blake2b::new_blake2b,
    h256_ext::H256Ext,
    state::{build_data_hash_key, State},
    CKB_SUDT_SCRIPT_ARGS, H256,
};
use gw_common::{builtins::ETH_REGISTRY_ACCOUNT_ID, registry_address::RegistryAddress};
use gw_config::{BackendConfig, BackendType};
use gw_db::schema::{COLUMN_INDEX, COLUMN_META, META_TIP_BLOCK_HASH_KEY};
use gw_generator::error::TransactionError;
pub use gw_generator::{
    account_lock_manage::{secp256k1::Secp256k1, AccountLockManage},
    backend_manage::{Backend, BackendManage},
    dummy_state::DummyState,
    traits::StateExt,
    Generator,
};
use gw_store::traits::chain_store::ChainStore;
use gw_store::traits::kv_store::KVStoreWrite;
pub use gw_store::{chain_view::ChainView, Store};
use gw_traits::CodeStore;
use gw_types::{
    bytes::Bytes,
    core::{AllowedContractType, AllowedEoaType, ScriptHashType},
    offchain::RunResult,
    packed::{
        AllowedTypeHash, BatchSetMapping, BlockInfo, Fee, LogItem, RawL2Transaction, RollupConfig,
        Script, Uint64,
    },
    prelude::*,
};
use gw_types::{
    offchain::RollupContext,
    packed::{ETHAddrRegArgs, ETHAddrRegArgsUnion},
};
use rlp::RlpStream;
use std::{fs, io::Read, path::PathBuf};

pub use gw_common::builtins::{CKB_SUDT_ACCOUNT_ID, RESERVED_ACCOUNT_ID};
pub const ETH_ADDRESS_REGISTRY_ACCOUNT_ID: u32 = 2;
pub const CREATOR_ACCOUNT_ID: u32 = 3;
pub const COMPATIBLE_CHAIN_ID: u32 = 202203;

pub const L2TX_MAX_CYCLES: u64 = 7000_0000;

// meta contract
pub const META_VALIDATOR_PATH: &str = "../build/godwoken-scripts/meta-contract-validator";
pub const META_GENERATOR_PATH: &str = "../build/godwoken-scripts/meta-contract-generator";
pub const META_VALIDATOR_SCRIPT_TYPE_HASH: [u8; 32] = [0xa1u8; 32];
// simple UDT
pub const SUDT_VALIDATOR_PATH: &str = "../build/godwoken-scripts/sudt-validator";
pub const SUDT_GENERATOR_PATH: &str = "../build/godwoken-scripts/sudt-generator";
pub const SUDT_VALIDATOR_SCRIPT_TYPE_HASH: [u8; 32] = [0xa2u8; 32];
pub const SECP_DATA: &[u8] = include_bytes!("../../build/secp256k1_data");

// polyjuice
pub const POLYJUICE_GENERATOR_NAME: &str = "../build/generator_log.aot";
pub const POLYJUICE_VALIDATOR_NAME: &str = "../build/validator";
// ETH Address Registry
pub const ETH_ADDRESS_REGISTRY_GENERATOR_NAME: &str =
    "../build/godwoken-scripts/eth-addr-reg-generator";
pub const ETH_ADDRESS_REGISTRY_VALIDATOR_NAME: &str =
    "../build/godwoken-scripts/eth-addr-reg-validator";
// Key type for ETH Address Registry
const GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDR: u8 = 200;
const ETH_ADDR_TO_GW_ACCOUNT_SCRIPT_HASH: u8 = 201;

pub const ROLLUP_SCRIPT_HASH: [u8; 32] = [0xa9u8; 32];
pub const ETH_ACCOUNT_LOCK_CODE_HASH: [u8; 32] = [0xaau8; 32];
pub const SECP_LOCK_CODE_HASH: [u8; 32] = [0xbbu8; 32];

pub const GW_LOG_SUDT_TRANSFER: u8 = 0x0;
pub const GW_LOG_SUDT_PAY_FEE: u8 = 0x1;
pub const GW_LOG_POLYJUICE_SYSTEM: u8 = 0x2;
pub const GW_LOG_POLYJUICE_USER: u8 = 0x3;

// pub const FATAL_POLYJUICE: i8 = -50;
pub const FATAL_PRECOMPILED_CONTRACTS: i8 = -51;

pub(crate) const SUDT_ERC20_PROXY_USER_DEFINED_DECIMALS_CODE: &str =
    include_str!("../../solidity/erc20/SudtERC20Proxy_UserDefinedDecimals.bin");

fn load_program(program_name: &str) -> Bytes {
    let mut buf = Vec::new();
    let mut path = PathBuf::new();
    path.push(program_name);
    let mut f = fs::File::open(&path).expect(&format!("load program {}", program_name));
    f.read_to_end(&mut buf).expect("read program");
    Bytes::from(buf.to_vec())
}

lazy_static::lazy_static! {
    pub static ref SECP_DATA_HASH: H256 = {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&SECP_DATA);
        hasher.finalize(&mut buf);
        buf.into()
    };

    pub static ref POLYJUICE_GENERATOR_PROGRAM: Bytes
        = load_program(&POLYJUICE_GENERATOR_NAME);
    pub static ref POLYJUICE_VALIDATOR_PROGRAM: Bytes
        = load_program(&POLYJUICE_VALIDATOR_NAME);
    pub static ref POLYJUICE_PROGRAM_CODE_HASH: [u8; 32] = {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&POLYJUICE_VALIDATOR_PROGRAM);
        hasher.finalize(&mut buf);
        buf
    };

    pub static ref ETH_ADDRESS_REGISTRY_GENERATOR_PROGRAM: Bytes
        = load_program(&ETH_ADDRESS_REGISTRY_GENERATOR_NAME);
    pub static ref ETH_ADDRESS_REGISTRY_VALIDATOR_PROGRAM: Bytes
        = load_program(&ETH_ADDRESS_REGISTRY_VALIDATOR_NAME);
    pub static ref ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH: [u8; 32] = {
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(&ETH_ADDRESS_REGISTRY_VALIDATOR_PROGRAM);
        hasher.finalize(&mut buf);
        buf
    };
}

#[derive(Debug, Clone)]
pub enum Log {
    SudtTransfer {
        sudt_id: u32,
        from_addr: [u8; 20],
        to_addr: [u8; 20],
        amount: u128,
    },
    SudtPayFee {
        sudt_id: u32,
        from_addr: [u8; 20],
        block_producer_addr: [u8; 20],
        amount: u128,
    },
    PolyjuiceSystem {
        gas_used: u64,
        cumulative_gas_used: u64,
        created_address: [u8; 20],
        status_code: u32,
    },
    PolyjuiceUser {
        address: [u8; 20],
        data: Vec<u8>,
        topics: Vec<H256>,
    },
}

fn parse_sudt_log_data(data: &[u8]) -> ([u8; 20], [u8; 20], u128) {
    assert_eq!(data[0], 20);
    let mut from_addr = [0u8; 20];
    from_addr.copy_from_slice(&data[1..21]);
    let mut to_addr = [0u8; 20];
    to_addr.copy_from_slice(&data[21..41]);

    let mut u128_bytes = [0u8; 16];
    u128_bytes.copy_from_slice(&data[41..41 + 16]);
    let amount = u128::from_le_bytes(u128_bytes);
    (from_addr, to_addr, amount)
}

pub fn parse_log(item: &LogItem) -> Log {
    let service_flag: u8 = item.service_flag().into();
    let raw_data = item.data().raw_data();
    let data = raw_data.as_ref();
    match service_flag {
        GW_LOG_SUDT_TRANSFER => {
            let sudt_id: u32 = item.account_id().unpack();
            if data.len() != (1 + 20 + 20 + 16) {
                panic!("Invalid data length: {}", data.len());
            }
            let (from_addr, to_addr, amount) = parse_sudt_log_data(data);
            Log::SudtTransfer {
                sudt_id,
                from_addr,
                to_addr,
                amount,
            }
        }
        GW_LOG_SUDT_PAY_FEE => {
            let sudt_id: u32 = item.account_id().unpack();
            if data.len() != (1 + 20 + 20 + 16) {
                panic!("Invalid data length: {}", data.len());
            }
            let (from_addr, block_producer_addr, amount) = parse_sudt_log_data(data);
            Log::SudtPayFee {
                sudt_id,
                from_addr,
                block_producer_addr,
                amount,
            }
        }
        GW_LOG_POLYJUICE_SYSTEM => {
            if data.len() != (8 + 8 + 20 + 4) {
                panic!("invalid system log raw data length: {}", data.len());
            }

            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&data[0..8]);
            let gas_used = u64::from_le_bytes(u64_bytes);
            u64_bytes.copy_from_slice(&data[8..16]);
            let cumulative_gas_used = u64::from_le_bytes(u64_bytes);

            let mut created_address = [0u8; 20];
            created_address.copy_from_slice(&data[16..36]);
            let mut u32_bytes = [0u8; 4];
            u32_bytes.copy_from_slice(&data[36..40]);
            let status_code = u32::from_le_bytes(u32_bytes);
            Log::PolyjuiceSystem {
                gas_used,
                cumulative_gas_used,
                created_address,
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

pub fn new_block_info(block_producer: RegistryAddress, number: u64, timestamp: u64) -> BlockInfo {
    BlockInfo::new_builder()
        .block_producer(Bytes::from(block_producer.to_bytes()).pack())
        .number(number.pack())
        .timestamp(timestamp.pack())
        .build()
}

// pub(crate) fn contract_id_to_short_script_hash(
//     state: &DummyState,
//     id: u32,
//     ethabi: bool,
// ) -> Vec<u8> {
//     let offset = if ethabi { 12 } else { 0 };
//     let mut data = vec![0u8; offset + 20];
//     let account_script_hash = state.get_script_hash(id).unwrap();
//     data[offset..offset + 20].copy_from_slice(&account_script_hash.as_slice()[0..20]);
//     data
// }

pub(crate) fn eth_addr_to_ethabi_addr(eth_addr: &[u8; 20]) -> [u8; 32] {
    let mut ethabi_addr = [0; 32];
    ethabi_addr[12..32].copy_from_slice(eth_addr);
    ethabi_addr
}

pub fn new_contract_account_script_with_nonce(from_addr: &[u8; 20], from_nonce: u32) -> Script {
    let mut stream = RlpStream::new_list(2);
    stream.append(&from_addr.to_vec());
    stream.append(&from_nonce);
    println!(
        "rlp data of (eoa_address + nonce): {}",
        hex::encode(stream.as_raw())
    );
    let data_hash = tiny_keccak::keccak256(stream.as_raw());

    let mut new_script_args = vec![0u8; 32 + 4 + 20];
    new_script_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
    new_script_args[32..36].copy_from_slice(&CREATOR_ACCOUNT_ID.to_le_bytes()[..]);
    new_script_args[36..36 + 20].copy_from_slice(&data_hash[12..]);
    // println!("eth_address: {:?}", &data_hash[12..32]);

    Script::new_builder()
        .code_hash(POLYJUICE_PROGRAM_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(new_script_args.pack())
        .build()
}
pub fn new_contract_account_script(
    state: &DummyState,
    from_id: u32,
    from_eth_address: &[u8; 20],
    current_nonce: bool,
) -> Script {
    let mut from_nonce = state.get_nonce(from_id).unwrap();
    if !current_nonce {
        from_nonce -= 1;
    }
    new_contract_account_script_with_nonce(from_eth_address, from_nonce)
}

pub(crate) fn contract_script_to_eth_addr(script: &Script, ethabi: bool) -> Vec<u8> {
    let offset = if ethabi { 12 } else { 0 };
    let mut eth_addr = vec![0u8; offset + 20];
    eth_addr[offset..].copy_from_slice(&script.args().raw_data().as_ref()[36..56]);
    eth_addr
}

#[derive(Default, Debug)]
pub struct PolyjuiceArgsBuilder {
    is_create: bool,
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
        let mut output: Vec<u8> = vec![0u8; 52];
        let call_kind: u8 = if self.is_create { 3 } else { 0 };
        output[0..8].copy_from_slice(&[0xff, 0xff, 0xff, b'P', b'O', b'L', b'Y', call_kind][..]);
        output[8..16].copy_from_slice(&self.gas_limit.to_le_bytes()[..]);
        output[16..32].copy_from_slice(&self.gas_price.to_le_bytes()[..]);
        output[32..48].copy_from_slice(&self.value.to_le_bytes()[..]);
        output[48..52].copy_from_slice(&(self.input.len() as u32).to_le_bytes()[..]);
        output.extend(self.input);
        output
    }
}

pub fn setup() -> (Store, DummyState, Generator) {
    let _ = env_logger::try_init();
    let store = Store::open_tmp().unwrap();
    let mut state = DummyState::default();

    let meta_script = Script::new_builder()
        .code_hash(META_VALIDATOR_SCRIPT_TYPE_HASH.clone().pack())
        .hash_type(ScriptHashType::Type.into())
        .build();
    let reserved_id = state
        .create_account_from_script(meta_script)
        .expect("create meta_account");
    assert_eq!(
        reserved_id, RESERVED_ACCOUNT_ID,
        "reserved account id must be zero"
    );

    // setup CKB simple UDT contract
    let ckb_sudt_script = build_l2_sudt_script(CKB_SUDT_SCRIPT_ARGS);
    let ckb_sudt_id = state
        .create_account_from_script(ckb_sudt_script)
        .expect("create CKB simple UDT contract account");
    assert_eq!(
        ckb_sudt_id, CKB_SUDT_ACCOUNT_ID,
        "ckb simple UDT account id"
    );

    // create `ETH Address Registry` layer2 contract account
    let eth_addr_reg_script = Script::new_builder()
        .code_hash(ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(ROLLUP_SCRIPT_HASH.to_vec().pack())
        .build();
    let eth_addr_reg_account_id = state
        .create_account_from_script(eth_addr_reg_script)
        .expect("create `ETH Address Registry` layer2 contract");
    assert_eq!(eth_addr_reg_account_id, ETH_ADDRESS_REGISTRY_ACCOUNT_ID);

    let mut args = [0u8; 40];
    args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
    args[32..36].copy_from_slice(&ckb_sudt_id.to_le_bytes()[..]);
    args[36..40].copy_from_slice(&eth_addr_reg_account_id.to_le_bytes()[..]);
    let creator_script = Script::new_builder()
        .code_hash(POLYJUICE_PROGRAM_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(args.to_vec().pack())
        .build();
    let creator_account_id = state
        .create_account_from_script(creator_script)
        .expect("create creator_account");
    assert_eq!(creator_account_id, CREATOR_ACCOUNT_ID);

    state.insert_data(*SECP_DATA_HASH, Bytes::from(SECP_DATA));
    state
        .update_raw(build_data_hash_key(SECP_DATA_HASH.as_slice()), H256::one())
        .expect("update secp data key");

    // ==== Build generator
    let configs = vec![
        BackendConfig {
            backend_type: BackendType::Meta,
            validator_path: META_VALIDATOR_PATH.into(),
            generator_path: META_GENERATOR_PATH.into(),
            validator_script_type_hash: META_VALIDATOR_SCRIPT_TYPE_HASH.into(),
        },
        BackendConfig {
            backend_type: BackendType::Sudt,
            validator_path: SUDT_VALIDATOR_PATH.into(),
            generator_path: SUDT_GENERATOR_PATH.into(),
            validator_script_type_hash: SUDT_VALIDATOR_SCRIPT_TYPE_HASH.into(),
        },
    ];
    let mut backend_manage = BackendManage::from_config(configs).expect("default backend");
    // NOTICE in this test we won't need SUM validator
    backend_manage.register_backend(Backend {
        backend_type: BackendType::Polyjuice,
        validator: POLYJUICE_VALIDATOR_PROGRAM.clone(),
        generator: POLYJUICE_GENERATOR_PROGRAM.clone(),
        validator_script_type_hash: POLYJUICE_PROGRAM_CODE_HASH.clone().into(),
    });
    backend_manage.register_backend(Backend {
        backend_type: BackendType::EthAddrReg,
        validator: ETH_ADDRESS_REGISTRY_VALIDATOR_PROGRAM.clone(),
        generator: ETH_ADDRESS_REGISTRY_GENERATOR_PROGRAM.clone(),
        validator_script_type_hash: ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH.clone().into(),
    });
    let mut account_lock_manage = AccountLockManage::default();
    account_lock_manage
        .register_lock_algorithm(SECP_LOCK_CODE_HASH.into(), Box::new(Secp256k1::default()));
    let rollup_config = RollupConfig::new_builder()
        .compatible_chain_id(COMPATIBLE_CHAIN_ID.pack())
        .l2_sudt_validator_script_type_hash(SUDT_VALIDATOR_SCRIPT_TYPE_HASH.pack())
        .allowed_contract_type_hashes(
            vec![
                AllowedTypeHash::new(AllowedContractType::Meta, META_VALIDATOR_SCRIPT_TYPE_HASH),
                AllowedTypeHash::new(AllowedContractType::Sudt, SUDT_VALIDATOR_SCRIPT_TYPE_HASH),
                AllowedTypeHash::new(AllowedContractType::Polyjuice, *POLYJUICE_PROGRAM_CODE_HASH),
                AllowedTypeHash::new(
                    AllowedContractType::EthAddrReg,
                    *ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH,
                ),
            ]
            .pack(),
        )
        .allowed_eoa_type_hashes(
            vec![AllowedTypeHash::new(
                AllowedEoaType::Eth,
                ETH_ACCOUNT_LOCK_CODE_HASH,
            )]
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

    (store, state, generator)
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
    block_producer: RegistryAddress,
    block_number: u64,
) -> RunResult {
    let block_info = new_block_info(block_producer, block_number, block_number);
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
    let tip_block_hash = db.get_tip_block_hash().unwrap();
    let run_result = generator
        .execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
            None,
        )
        .expect("deploy Polyjuice contract");
    state.apply_run_result(&run_result).expect("update state");
    // println!("[deploy contract] used cycles: {}", run_result.used_cycles);
    run_result
}

/// https://eips.ethereum.org/EIPS/eip-1014#specification
pub fn compute_create2_script(
    sender_contract_addr: &[u8],
    create2_salt: &[u8],
    init_code: &[u8],
) -> Script {
    assert_eq!(create2_salt.len(), 32);

    let init_code_hash = tiny_keccak::keccak256(init_code);
    let mut data = [0u8; 1 + 20 + 32 + 32];
    data[0] = 0xff;
    data[1..1 + 20].copy_from_slice(sender_contract_addr);
    data[1 + 20..1 + 20 + 32].copy_from_slice(create2_salt);
    data[1 + 20 + 32..1 + 20 + 32 + 32].copy_from_slice(&init_code_hash[..]);
    let data_hash = tiny_keccak::keccak256(&data);

    let mut script_args = vec![0u8; 32 + 4 + 20];
    script_args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH[..]);
    script_args[32..32 + 4].copy_from_slice(&CREATOR_ACCOUNT_ID.to_le_bytes()[..]);
    script_args[32 + 4..32 + 4 + 20].copy_from_slice(&data_hash[12..]);

    println!(
        "[compute_create2_script] init_code: {}",
        hex::encode(init_code)
    );
    println!("create2_script_args: {}", hex::encode(&script_args[..]));
    Script::new_builder()
        .code_hash(POLYJUICE_PROGRAM_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(script_args.pack())
        .build()
}

pub struct Account {
    id: u32,
}

impl Account {
    pub fn build_script(n: u32) -> (Script, RegistryAddress) {
        let mut addr = [0u8; 20];
        addr[..4].copy_from_slice(&n.to_le_bytes());
        let mut args = vec![42u8; 32];
        args.extend(&addr);
        let code_hash = [3u8; 32];
        let script = Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(args.pack())
            .build();
        let addr = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, addr.to_vec());
        (script, addr)
    }
}

#[derive(Debug, Clone)]
pub struct MockContractInfo {
    pub eth_addr: Vec<u8>,
    pub eth_abi_addr: Vec<u8>,
    pub script_hash: H256,
    pub reg_addr: RegistryAddress,
}

impl MockContractInfo {
    pub fn create(eth_addr: &[u8; 20], nonce: u32) -> Self {
        let contract_script = new_contract_account_script_with_nonce(eth_addr, nonce);
        let contract_eth_addr = contract_script_to_eth_addr(&contract_script, false);
        let contract_eth_abi_addr = contract_script_to_eth_addr(&contract_script, true);
        let reg_addr = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, contract_eth_addr.clone());
        Self {
            eth_addr: contract_eth_addr,
            eth_abi_addr: contract_eth_abi_addr,
            script_hash: contract_script.hash().into(),
            reg_addr,
        }
    }

    pub fn mapping_registry_address_to_script_hash(&self, state: &mut DummyState) {
        state
            .mapping_registry_address_to_script_hash(self.reg_addr.clone(), self.script_hash)
            .expect("map reg addr to script hash");
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
    let (_, addr) = Account::build_script(0);
    let block_info = new_block_info(addr, block_number, block_number);
    let input = hex::decode("6d4ce63c").unwrap();
    let args = PolyjuiceArgsBuilder::default()
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
    let tip_block_hash = db.get_tip_block_hash().unwrap();
    let run_result = generator
        .execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
            None,
        )
        .expect("execute_transaction");
    // 491894, 571661 -> 586360 < 587K
    check_cycles("simple_storage_get", run_result.used_cycles, 637_000);
    run_result
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

pub fn build_eth_l2_script(args: &[u8; 20]) -> Script {
    let mut script_args = Vec::with_capacity(32 + 20);
    script_args.extend(&ROLLUP_SCRIPT_HASH);
    script_args.extend(&args[..]);
    Script::new_builder()
        .args(Bytes::from(script_args).pack())
        .code_hash(ETH_ACCOUNT_LOCK_CODE_HASH.clone().pack())
        .hash_type(ScriptHashType::Type.into())
        .build()
}

pub(crate) fn create_block_producer(state: &mut DummyState) -> RegistryAddress {
    let block_producer_script = build_eth_l2_script(&[0x99u8; 20]);
    let block_producer_script_hash = block_producer_script.hash();
    let block_producer_id = state
        .create_account_from_script(block_producer_script)
        .expect("create_block_producer");
    let eth_addr = [0x99u8; 20];
    register_eoa_account(state, &eth_addr, &block_producer_script_hash);
    RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, eth_addr.to_vec())
}

pub(crate) fn create_eth_eoa_account(
    state: &mut DummyState,
    eth_address: &[u8; 20],
    mint_ckb: u128,
) -> (u32, [u8; 32]) {
    let script = build_eth_l2_script(eth_address);
    let script_hash = script.hash();
    let account_id = state.create_account_from_script(script).unwrap();
    register_eoa_account(state, eth_address, &script_hash);
    let address = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, eth_address.to_vec());
    state
        .mint_sudt(CKB_SUDT_ACCOUNT_ID, &address, mint_ckb)
        .unwrap();
    (account_id, script_hash)
}

pub(crate) fn check_cycles(l2_tx_label: &str, used_cycles: u64, warning_cycles: u64) {
    if POLYJUICE_GENERATOR_NAME == "generator_log.aot" {
        return; // disable cycles check
    }

    if used_cycles > warning_cycles {
        let overflow_cycles = used_cycles - warning_cycles;
        println!(
            "[{}] overflow_cycles: {}({}%)",
            l2_tx_label,
            overflow_cycles,
            overflow_cycles * 100 / warning_cycles
        );
    }

    println!("[check_cycles] used_cycles: {}", used_cycles);
    assert!(
        used_cycles < warning_cycles,
        "[Warning: {} used too many cycles({})]",
        l2_tx_label,
        used_cycles
    );
}

fn build_eth_address_to_script_hash_key(eth_address: &[u8; 20]) -> H256 {
    let mut key: [u8; 32] = H256::zero().into();
    let mut hasher = new_blake2b();
    hasher.update(&ETH_ADDRESS_REGISTRY_ACCOUNT_ID.to_le_bytes());
    hasher.update(&[ETH_ADDR_TO_GW_ACCOUNT_SCRIPT_HASH]);
    hasher.update(eth_address);
    hasher.finalize(&mut key);
    key.into()
}

fn build_script_hash_to_eth_address_key(script_hash: &[u8; 32]) -> H256 {
    let mut key: [u8; 32] = H256::zero().into();
    let mut hasher = new_blake2b();
    hasher.update(&ETH_ADDRESS_REGISTRY_ACCOUNT_ID.to_le_bytes());
    hasher.update(&[GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDR]);
    hasher.update(script_hash);
    hasher.finalize(&mut key);
    key.into()
}

/// update eth_address_registry by state.update_raw(...)
pub(crate) fn register_eoa_account(
    state: &mut DummyState,
    eth_address: &[u8; 20],
    script_hash: &[u8; 32],
) {
    state
        .update_raw(
            build_eth_address_to_script_hash_key(eth_address),
            (*script_hash).into(),
        )
        .expect("add GW_ETH_ADDRESS_TO_SCRIPT_HASH mapping into state");

    let mut eth_address_abi_format = [0u8; 32];
    eth_address_abi_format[12..].copy_from_slice(eth_address);
    state
        .update_raw(
            build_script_hash_to_eth_address_key(script_hash),
            eth_address_abi_format.into(),
        )
        .expect("add GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDR mapping into state");
    let address = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, eth_address.to_vec());
    state
        .mapping_registry_address_to_script_hash(address, (*script_hash).into())
        .expect("map reg addr to script hash");
}

#[derive(Default)]
struct SetMappingArgsBuilder {
    method: u32,
    gw_script_hash: [u8; 32],
    fee: u64,
}
impl SetMappingArgsBuilder {
    /// Set the SetMappingArgs builder's method.
    fn method(mut self, method: u32) -> Self {
        self.method = method;
        self
    }
    /// Set the SetMappingArgs builder's gw script hash.
    fn gw_script_hash(mut self, gw_script_hash: [u8; 32]) -> Self {
        self.gw_script_hash = gw_script_hash;
        self
    }
    /// Set the set mapping args‘s fee.
    fn set_fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }
    fn build(self) -> Vec<u8> {
        let mut output: Vec<u8> = vec![0u8; 4];
        output[0..4].copy_from_slice(&self.method.to_le_bytes()[..]);
        output.extend(self.gw_script_hash);
        output.extend(&self.fee.to_le_bytes()[..]);
        output
    }
}

pub enum SetMappingArgs {
    One(H256),
    Batch(Vec<H256>),
}

/// Set two-ways mappings between `eth_address` and `gw_script_hash`
/// by `ETH Address Registry` layer2 contract
pub(crate) fn eth_address_regiser(
    store: &Store,
    state: &mut DummyState,
    generator: &Generator,
    from_id: u32,
    block_info: BlockInfo,
    set_mapping_args: SetMappingArgs,
) -> Result<RunResult, TransactionError> {
    let args = match set_mapping_args {
        SetMappingArgs::One(gw_script_hash) => SetMappingArgsBuilder::default()
            .method(2u32)
            .gw_script_hash(gw_script_hash.into())
            .set_fee(1000)
            .build()
            .pack(),
        SetMappingArgs::Batch(gw_script_hashes) => {
            let fee = Fee::new_builder()
                .registry_id(ETH_REGISTRY_ACCOUNT_ID.pack())
                .amount(1000u64.pack())
                .build();
            let batch_set_mapping = BatchSetMapping::new_builder()
                .fee(fee)
                .gw_script_hashes(gw_script_hashes.pack())
                .build();
            let args = ETHAddrRegArgs::new_builder()
                .set(ETHAddrRegArgsUnion::BatchSetMapping(batch_set_mapping))
                .build();
            args.as_bytes().pack()
        }
    };

    let raw_l2tx = RawL2Transaction::new_builder()
        .from_id(from_id.pack())
        .to_id(ETH_ADDRESS_REGISTRY_ACCOUNT_ID.pack())
        .args(args)
        .build();
    let db = store.begin_transaction();
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    generator.execute_transaction(
        &ChainView::new(&db, tip_block_hash),
        state,
        &block_info,
        &raw_l2tx,
        L2TX_MAX_CYCLES,
        None,
    )
}
