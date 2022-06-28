use std::{
    convert::TryInto,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub use gw_common::builtins::{CKB_SUDT_ACCOUNT_ID, ETH_REGISTRY_ACCOUNT_ID, RESERVED_ACCOUNT_ID};
use gw_common::{
    blake2b::new_blake2b,
    h256_ext::H256Ext,
    registry_address::RegistryAddress,
    state::{build_data_hash_key, State},
    CKB_SUDT_SCRIPT_ARGS, H256,
};
use gw_config::{BackendConfig, BackendSwitchConfig, BackendType};
use gw_db::schema::{COLUMN_INDEX, COLUMN_META, META_TIP_BLOCK_HASH_KEY};
use gw_generator::{
    account_lock_manage::{secp256k1::Secp256k1, AccountLockManage},
    backend_manage::BackendManage,
    dummy_state::DummyState,
    traits::StateExt,
    Generator,
};
use gw_store::{
    chain_view::ChainView,
    traits::{chain_store::ChainStore, kv_store::KVStoreWrite},
    Store,
};
use gw_traits::CodeStore;
use gw_types::{
    bytes::Bytes,
    core::{AllowedContractType, AllowedEoaType, ScriptHashType},
    offchain::{RollupContext, RunResult},
    packed::{AllowedTypeHash, BlockInfo, RawL2Transaction, RollupConfig, Script, Uint64},
    prelude::*,
    U256,
};

use crate::helper::PolyjuiceArgsBuilder;
pub const CREATOR_ACCOUNT_ID: u32 = 3;
pub const CHAIN_ID: u64 = 202204;

pub const L2TX_MAX_CYCLES: u64 = 7000_0000;

// meta contract
pub const META_VALIDATOR_PATH: &str = "build/godwoken-scripts/meta-contract-validator";
pub const META_GENERATOR_PATH: &str = "build/godwoken-scripts/meta-contract-generator";
pub const META_VALIDATOR_SCRIPT_TYPE_HASH: [u8; 32] = [0xa1u8; 32];
// simple UDT
pub const SUDT_VALIDATOR_PATH: &str = "build/godwoken-scripts/sudt-validator";
pub const SUDT_GENERATOR_PATH: &str = "build/godwoken-scripts/sudt-generator";
pub const SUDT_VALIDATOR_SCRIPT_TYPE_HASH: [u8; 32] = [0xa2u8; 32];
pub const SECP_DATA_PATH: &str = "build/secp256k1_data";
// pub const SECP_DATA: &[u8] = include_bytes!("../../build/secp256k1_data");

// polyjuice
pub const POLYJUICE_GENERATOR_NAME: &str = "build/generator_log.aot";
pub const POLYJUICE_VALIDATOR_NAME: &str = "build/validator";
// ETH Address Registry
pub const ETH_ADDRESS_REGISTRY_GENERATOR_NAME: &str =
    "build/godwoken-scripts/eth-addr-reg-generator";
pub const ETH_ADDRESS_REGISTRY_VALIDATOR_NAME: &str =
    "build/godwoken-scripts/eth-addr-reg-validator";

pub const ROLLUP_SCRIPT_HASH: [u8; 32] = [0xa9u8; 32];
pub const ETH_ACCOUNT_LOCK_CODE_HASH: [u8; 32] = [0xaau8; 32];
pub const SECP_LOCK_CODE_HASH: [u8; 32] = [0xbbu8; 32];

pub const GW_LOG_SUDT_TRANSFER: u8 = 0x0;
pub const GW_LOG_SUDT_PAY_FEE: u8 = 0x1;
pub const GW_LOG_POLYJUICE_SYSTEM: u8 = 0x2;
pub const GW_LOG_POLYJUICE_USER: u8 = 0x3;

// pub const FATAL_POLYJUICE: i8 = -50;
pub const FATAL_PRECOMPILED_CONTRACTS: i8 = -51;

fn load_program(program_name: &str) -> Bytes {
    let mut buf = Vec::new();
    let mut path = PathBuf::new();
    path.push(program_name);
    let mut f = fs::File::open(&path).unwrap_or_else(|_| panic!("load program {}", program_name));
    f.read_to_end(&mut buf).expect("read program");
    Bytes::from(buf.to_vec())
}

fn load_code_hash(path: &Path) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(&load_program(path.to_str().unwrap()));
    hasher.finalize(&mut buf);
    buf
}

fn register_eoa_account(state: &mut DummyState, eth_address: &[u8; 20], script_hash: &[u8; 32]) {
    let address = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, eth_address.to_vec());
    state
        .mapping_registry_address_to_script_hash(address, (*script_hash).into())
        .expect("map reg addr to script hash");
}

fn create_block_producer(state: &mut DummyState) -> anyhow::Result<RegistryAddress> {
    // This eth_address is hardcoded in src/test_cases/evm-contracts/BlockInfo.sol
    let eth_address: [u8; 20] = hex::decode("a1ad227Ad369f593B5f3d0Cc934A681a50811CB2")?
        .try_into()
        .expect("decode");
    let block_producer_script = build_eth_l2_script(&eth_address);
    let block_producer_script_hash = block_producer_script.hash();
    let _block_producer_id = state
        .create_account_from_script(block_producer_script)
        .expect("create_block_producer");
    register_eoa_account(state, &eth_address, &block_producer_script_hash);
    Ok(RegistryAddress::new(
        ETH_REGISTRY_ACCOUNT_ID,
        eth_address.to_vec(),
    ))
}

pub struct MockChain {
    ctx: Context,
    block_producer: RegistryAddress,
    block_number: u64,
    timestamp: SystemTime,
}

impl MockChain {
    /**
     * Setup with a base path. The base path is where we can find the **build**
     * directory.
     */
    pub fn setup(base_path: &str) -> anyhow::Result<Self> {
        let mut ctx = Context::setup(base_path)?;
        let block_producer = create_block_producer(&mut ctx.state)?;
        let timestamp = SystemTime::now();
        Ok(Self {
            ctx,
            block_producer,
            block_number: 0u64,
            timestamp,
        })
    }

    fn new_block_info(&self) -> anyhow::Result<BlockInfo> {
        let timestamp = self
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let block_info = BlockInfo::new_builder()
            .block_producer(Bytes::from(self.block_producer.to_bytes()).pack())
            .number(self.block_number.pack())
            .timestamp(timestamp.pack())
            .build();
        Ok(block_info)
    }

    pub fn create_eoa_account(
        &mut self,
        eth_address: &[u8; 20],
        mint_ckb: U256,
    ) -> anyhow::Result<u32> {
        let script = build_eth_l2_script(eth_address);
        let script_hash = script.hash();
        let account_id = self.ctx.state.create_account_from_script(script).unwrap();
        register_eoa_account(&mut self.ctx.state, eth_address, &script_hash);
        let address = RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, eth_address.to_vec());
        self.ctx
            .state
            .mint_sudt(CKB_SUDT_ACCOUNT_ID, &address, mint_ckb)?;
        Ok(account_id)
    }

    pub fn deploy(
        &mut self,
        from_id: u32,
        code: &[u8],
        gas_limit: u64,
        gas_price: u128,
        value: u128,
    ) -> anyhow::Result<RunResult> {
        let args = PolyjuiceArgsBuilder::default()
            .do_create(true)
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .value(value)
            .input(code)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(CREATOR_ACCOUNT_ID.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = self.execute(raw_tx)?;
        self.ctx.state.apply_run_result(&run_result.write)?;
        Ok(run_result)
    }

    pub fn call(
        &mut self,
        from_id: u32,
        to_id: u32,
        code: &[u8],
        gas_limit: u64,
        gas_price: u128,
        value: u128,
    ) -> anyhow::Result<RunResult> {
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .value(value)
            .input(code)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(to_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let run_result = self.execute(raw_tx)?;
        self.ctx.state.apply_run_result(&run_result.write)?;
        Ok(run_result)
    }

    pub fn execute(&mut self, raw_tx: RawL2Transaction) -> anyhow::Result<RunResult> {
        let db = self.ctx.store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash()?;
        let chain = ChainView::new(&db, tip_block_hash);
        let block_info = self.new_block_info()?;

        let run_result = self.ctx.generator.execute_transaction(
            &chain,
            &self.ctx.state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
        )?;

        self.block_number += 1;
        self.timestamp = SystemTime::now();
        Ok(run_result)
    }

    pub fn get_script_hash_by_registry_address(
        &self,
        registry_address: &RegistryAddress,
    ) -> anyhow::Result<Option<H256>> {
        let script_hash = self
            .ctx
            .state
            .get_script_hash_by_registry_address(registry_address)?;
        Ok(script_hash)
    }

    pub fn get_account_id_by_script_hash(&self, script_hash: &H256) -> anyhow::Result<Option<u32>> {
        let id = self.ctx.state.get_account_id_by_script_hash(script_hash)?;
        Ok(id)
    }

    pub fn get_nonce(&self, account_id: u32) -> anyhow::Result<u32> {
        let nonce = self.ctx.state.get_nonce(account_id)?;
        Ok(nonce)
    }
}
pub struct Context {
    state: DummyState,
    store: Store,
    generator: Generator,
}

impl Context {
    pub fn setup(base_path: &str) -> anyhow::Result<Self> {
        let _ = env_logger::try_init();
        let config = Config::new(base_path);

        let store = Store::open_tmp()?;
        let mut state = DummyState::default();

        let meta_script = Script::new_builder()
            .code_hash(META_VALIDATOR_SCRIPT_TYPE_HASH.clone().pack())
            .hash_type(ScriptHashType::Type.into())
            .build();
        let reserved_id = state.create_account_from_script(meta_script)?;
        assert_eq!(
            reserved_id, RESERVED_ACCOUNT_ID,
            "reserved account id must be zero"
        );

        // setup CKB simple UDT contract
        let ckb_sudt_script = build_l2_sudt_script(CKB_SUDT_SCRIPT_ARGS);
        let ckb_sudt_id = state.create_account_from_script(ckb_sudt_script)?;
        assert_eq!(
            ckb_sudt_id, CKB_SUDT_ACCOUNT_ID,
            "ckb simple UDT account id"
        );

        // create `ETH Address Registry` layer2 contract account
        let eth_addr_reg_script = Script::new_builder()
            .code_hash(config.eth_addr_reg_code_hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(ROLLUP_SCRIPT_HASH.to_vec().pack())
            .build();
        let eth_addr_reg_account_id = state.create_account_from_script(eth_addr_reg_script)?;
        assert_eq!(eth_addr_reg_account_id, ETH_REGISTRY_ACCOUNT_ID);

        let mut args = [0u8; 36];
        args[0..32].copy_from_slice(&ROLLUP_SCRIPT_HASH);
        args[32..36].copy_from_slice(&ckb_sudt_id.to_le_bytes()[..]);
        let creator_script = Script::new_builder()
            .code_hash(config.polyjuice_validator_code_hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(args.to_vec().pack())
            .build();
        let creator_account_id = state
            .create_account_from_script(creator_script)
            .expect("create creator_account");
        assert_eq!(creator_account_id, CREATOR_ACCOUNT_ID);

        state.insert_data(config.secp_data_hash.into(), config.secp_data.clone());
        state
            .update_raw(
                build_data_hash_key(config.secp_data_hash.as_slice()),
                H256::one(),
            )
            .expect("update secp data key");

        let backend_manage =
            BackendManage::from_config(vec![config.backends.clone()]).expect("default backend");
        // NOTICE in this test we won't need SUM validator
        let mut account_lock_manage = AccountLockManage::default();
        account_lock_manage
            .register_lock_algorithm(SECP_LOCK_CODE_HASH.into(), Box::new(Secp256k1::default()));
        let rollup_context = RollupContext {
            rollup_script_hash: ROLLUP_SCRIPT_HASH.into(),
            rollup_config: config.rollup,
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
        Ok(Self {
            store,
            state,
            generator,
        })
    }
}

struct Config {
    backends: BackendSwitchConfig,
    rollup: RollupConfig,
    polyjuice_validator_code_hash: [u8; 32],
    eth_addr_reg_code_hash: [u8; 32],
    secp_data: Bytes,
    secp_data_hash: [u8; 32],
}

impl Config {
    fn new(base_path: &str) -> Self {
        let path: PathBuf = [base_path, POLYJUICE_VALIDATOR_NAME].iter().collect();
        let polyjuice_validator_code_hash = load_code_hash(&path);

        let path: PathBuf = [base_path, ETH_ADDRESS_REGISTRY_VALIDATOR_NAME]
            .iter()
            .collect();
        let eth_addr_reg_code_hash = load_code_hash(&path);
        let path: PathBuf = [base_path, SECP_DATA_PATH].iter().collect();
        let secp_data = load_program(path.to_str().unwrap());
        let secp_data_hash = load_code_hash(&path);
        let backends = BackendSwitchConfig {
            switch_height: 0,
            backends: vec![
                BackendConfig {
                    backend_type: BackendType::Meta,
                    validator_path: [base_path, META_VALIDATOR_PATH].iter().collect(),
                    generator_path: [base_path, META_GENERATOR_PATH].iter().collect(),
                    validator_script_type_hash: META_VALIDATOR_SCRIPT_TYPE_HASH.into(),
                },
                BackendConfig {
                    backend_type: BackendType::Sudt,
                    validator_path: [base_path, SUDT_VALIDATOR_PATH].iter().collect(),
                    generator_path: [base_path, SUDT_GENERATOR_PATH].iter().collect(),
                    validator_script_type_hash: SUDT_VALIDATOR_SCRIPT_TYPE_HASH.into(),
                },
                BackendConfig {
                    backend_type: BackendType::Polyjuice,
                    validator_path: [base_path, POLYJUICE_VALIDATOR_NAME].iter().collect(),
                    generator_path: [base_path, POLYJUICE_GENERATOR_NAME].iter().collect(),
                    validator_script_type_hash: polyjuice_validator_code_hash.into(),
                },
                BackendConfig {
                    backend_type: BackendType::EthAddrReg,
                    validator_path: [base_path, ETH_ADDRESS_REGISTRY_VALIDATOR_NAME]
                        .iter()
                        .collect(),
                    generator_path: [base_path, ETH_ADDRESS_REGISTRY_GENERATOR_NAME]
                        .iter()
                        .collect(),
                    validator_script_type_hash: eth_addr_reg_code_hash.into(),
                },
            ],
        };
        let rollup = RollupConfig::new_builder()
            .chain_id(CHAIN_ID.pack())
            .l2_sudt_validator_script_type_hash(SUDT_VALIDATOR_SCRIPT_TYPE_HASH.pack())
            .allowed_contract_type_hashes(
                vec![
                    AllowedTypeHash::new(
                        AllowedContractType::Meta,
                        META_VALIDATOR_SCRIPT_TYPE_HASH,
                    ),
                    AllowedTypeHash::new(
                        AllowedContractType::Sudt,
                        SUDT_VALIDATOR_SCRIPT_TYPE_HASH,
                    ),
                    AllowedTypeHash::new(
                        AllowedContractType::Polyjuice,
                        polyjuice_validator_code_hash,
                    ),
                    AllowedTypeHash::new(AllowedContractType::EthAddrReg, eth_addr_reg_code_hash),
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
        Self {
            backends,
            rollup,
            polyjuice_validator_code_hash,
            eth_addr_reg_code_hash,
            secp_data,
            secp_data_hash,
        }
    }
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
