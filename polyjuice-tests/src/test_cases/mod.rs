pub(crate) mod call_multiple_times;
pub(crate) mod call_selfdestruct;
pub(crate) mod contract_call_contract;
pub(crate) mod contract_create_contract;
pub(crate) mod create2;
pub(crate) mod delegatecall;
pub(crate) mod erc20;
pub(crate) mod fallback_function;
pub(crate) mod get_block_info;
pub(crate) mod get_chain_id;
pub(crate) mod heap_memory;
pub(crate) mod parse_log_event;
pub(crate) mod selfdestruct;
pub(crate) mod simple_storage;
pub(crate) mod simple_transfer;
pub(crate) mod simple_wallet;
//  The account polyjuice want to create already created by meta_contract
pub(crate) mod account_already_exists;

pub(crate) mod ecrecover;
pub(crate) mod eth_to_godwoken_addr;
pub(crate) mod pre_compiled_contracts;
pub(crate) mod recover_account;
pub(crate) mod rlp;

//  Special pre-compiled contract to support transfer to any sudt
pub(crate) mod invalid_sudt_erc20_proxy;
pub(crate) mod sudt_erc20_proxy;
