use crate::helper::{new_block_info, setup, ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH};
use gw_common::{blake2b::new_blake2b, state::State, H256};
use gw_generator::{constants::L2TX_MAX_CYCLES, traits::StateExt};
use gw_store::chain_view::ChainView;
use gw_types::{
    bytes::Bytes,
    core::ScriptHashType,
    packed::{RawL2Transaction, Script},
    prelude::*,
};
use hex::FromHex;

const GW_ETH_ADDRESS_TO_ACCOUNT_SCRIPT_HASH: u8 = 6;
const GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDRESS: u8 = 7;

#[derive(Debug, Default)]
pub struct EthToGwArgsBuilder {
    pub(crate) method: u32,
    pub(crate) eth_address: [u8; 20],
}
impl EthToGwArgsBuilder {
    pub fn method(mut self, v: u32) -> Self {
        self.method = v;
        self
    }
    pub fn eth_address(mut self, v: [u8; 20]) -> Self {
        self.eth_address = v;
        self
    }
    pub fn build(self) -> Vec<u8> {
        let mut output: Vec<u8> = vec![0u8; 4];
        output[0..4].copy_from_slice(&self.method.to_le_bytes()[..]);
        output.extend(self.eth_address.to_vec());
        output
    }
}

#[derive(Debug, Default)]
pub struct GwToEthArgsBuilder {
    pub(crate) method: u32,
    pub(crate) gw_script_hash: [u8; 32],
}
impl GwToEthArgsBuilder {
    pub fn method(mut self, v: u32) -> Self {
        self.method = v;
        self
    }
    pub fn gw_script_hash(mut self, v: [u8; 32]) -> Self {
        self.gw_script_hash = v;
        self
    }
    pub fn build(self) -> Vec<u8> {
        let mut output: Vec<u8> = vec![0u8; 4];
        output[0..4].copy_from_slice(&self.method.to_le_bytes()[..]);
        output.extend(self.gw_script_hash.to_vec());
        output
    }
}

fn build_eth_address_to_script_hash_key(eth_address: &[u8; 20]) -> H256 {
    let mut key: [u8; 32] = H256::zero().into();
    let mut hasher = new_blake2b();
    hasher.update(&gw_common::state::GW_NON_ACCOUNT_PLACEHOLDER);
    hasher.update(&[GW_ETH_ADDRESS_TO_ACCOUNT_SCRIPT_HASH]);
    hasher.update(eth_address);
    hasher.finalize(&mut key);
    key.into()
}

#[test]
fn test_eth_to_gw() {
    let (store, mut state, generator, _creator_account_id) = setup();

    // init accounts
    let eth_addr_reg_account_id = state
        .create_account_from_script(
            Script::new_builder()
                .code_hash(ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH.clone().pack())
                .args([0u8; 32].to_vec().pack())
                .hash_type(ScriptHashType::Type.into())
                .build(),
        )
        .expect("create eth_addr_reg_account");
    let a_id = state
        .create_account_from_script(
            Script::new_builder()
                .code_hash([0u8; 32].pack())
                .args([0u8; 20].to_vec().pack())
                .hash_type(ScriptHashType::Type.into())
                .build(),
        )
        .expect("create account a");

    let eth_address = <[u8; 20]>::from_hex("D1667CBf1cc60da94c1cf6C9cfb261e71b6047f7")
        .expect("eth_address hex_string to u8_vec");
    let key = build_eth_address_to_script_hash_key(&eth_address);
    // println!("{:?}", key);
    state
        .update_raw(
            key,
            [
                92, 80, 32, 52, 234, 89, 14, 59, 217, 115, 180, 122, 92, 128, 255, 41, 87, 208,
                136, 49, 126, 66, 188, 93, 72, 74, 109, 211, 242, 49, 50, 217,
            ]
            .into(),
        )
        .expect("add GW_ETH_ADDRESS_TO_SCRIPT_HASH mapping into state");

    let args = EthToGwArgsBuilder::default()
        .method(0u32)
        .eth_address(eth_address)
        .build();
    let raw_tx = RawL2Transaction::new_builder()
        .from_id(a_id.pack())
        .to_id(eth_addr_reg_account_id.pack())
        .args(Bytes::from(args).pack())
        .build();
    let block_info = new_block_info(a_id, 1, 0);
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    let db = store.begin_transaction();
    let run_result = generator
        .execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            &state,
            &block_info,
            &raw_tx,
            L2TX_MAX_CYCLES,
        )
        .expect("execute Godwoken contract");
    state.apply_run_result(&run_result).expect("update state");
    assert_eq!(
        run_result.return_data,
        [
            92, 80, 32, 52, 234, 89, 14, 59, 217, 115, 180, 122, 92, 128, 255, 41, 87, 208, 136,
            49, 126, 66, 188, 93, 72, 74, 109, 211, 242, 49, 50, 217
        ]
    );
}

fn build_script_hash_to_eth_address_key(script_hash: &[u8; 32]) -> H256 {
    let mut key: [u8; 32] = H256::zero().into();
    let mut hasher = new_blake2b();
    hasher.update(&gw_common::state::GW_NON_ACCOUNT_PLACEHOLDER);
    hasher.update(&[GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDRESS]);
    hasher.update(script_hash);
    hasher.finalize(&mut key);
    key.into()
}

#[test]
fn test_gw_to_eth() {
    let (store, mut state, generator, _creator_account_id) = setup();

    // init accounts
    let eth_addr_reg_account_id = state
        .create_account_from_script(
            Script::new_builder()
                .code_hash(ETH_ADDRESS_REGISTRY_PROGRAM_CODE_HASH.clone().pack())
                .args([0u8; 32].to_vec().pack())
                .hash_type(ScriptHashType::Type.into())
                .build(),
        )
        .expect("create eth_addr_reg_account");
    let a_id = state
        .create_account_from_script(
            Script::new_builder()
                .code_hash([0u8; 32].pack())
                .args([0u8; 20].to_vec().pack())
                .hash_type(ScriptHashType::Type.into())
                .build(),
        )
        .expect("create account a");

    let gw_account_script_hash = [8u8; 32];
    let key = build_script_hash_to_eth_address_key(&gw_account_script_hash);
    let eth_address = <[u8; 20]>::from_hex("D1667CBf1cc60da94c1cf6C9cfb261e71b6047f7")
        .expect("eth_address hex_string to u8_vec");
    let mut value = [0u8; 32];
    value[12..].copy_from_slice(&eth_address);
    // println!("eth_address ethabi format: {:?}", value);
    state
        .update_raw(key, value.into())
        .expect("add GW_ACCOUNT_SCRIPT_HASH_TO_ETH_ADDRESS mapping into state");

    let args = GwToEthArgsBuilder::default()
        .method(1u32)
        .gw_script_hash(gw_account_script_hash)
        .build();
    let raw_l2tx = RawL2Transaction::new_builder()
        .from_id(a_id.pack())
        .to_id(eth_addr_reg_account_id.pack())
        .args(Bytes::from(args).pack())
        .build();
    let db = store.begin_transaction();
    let tip_block_hash = store.get_tip_block_hash().unwrap();
    let block_info = new_block_info(a_id, 1, 0);

    let run_result = generator
        .execute_transaction(
            &ChainView::new(&db, tip_block_hash),
            &state,
            &block_info,
            &raw_l2tx,
            L2TX_MAX_CYCLES,
        )
        .expect("execute Godwoken contract");
    assert_eq!(run_result.return_data, eth_address);
}
