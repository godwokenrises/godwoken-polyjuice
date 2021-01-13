pub(crate) mod contract_call_contract;
pub(crate) mod contract_create_contract;
pub(crate) mod erc20;
pub(crate) mod selfdestruct;
pub(crate) mod simple_storage;
pub(crate) mod call_multiple_times;

pub(crate) mod call_selfdestruct;
pub(crate) mod delegatecall;
pub(crate) mod get_block_info;
pub(crate) mod parse_log_event;
pub(crate) mod pre_compiled_contracts;
pub(crate) mod simple_transfer;
//  Special pre-compiled contract to support transfer to any sudt
pub(crate) mod any_sudt_erc20;
//  The account polyjuice want to create already created by meta_contract
pub(crate) mod account_already_exists;
