use std::convert::TryInto;

use anyhow::Result;
use gw_common::{builtins::ETH_REGISTRY_ACCOUNT_ID, registry_address::RegistryAddress};

use crate::{
    ctx,
    helper::{compute_create2_script, contract_script_to_eth_addr, MockContractInfo},
};

const INIT_CODE: &str = include_str!("./evm-contracts/CreateContract.bin");
const SS_CODE: &str = include_str!("./evm-contracts/SimpleStorage.bin");
const CREATE2_IMPL_CODE: &str = include_str!("./evm-contracts/Create2Impl.bin");

#[test]
fn create_address_collision_overwrite() -> Result<()> {
    let mut chain = ctx::MockChain::setup("..")?;
    let from_eth_address = [1u8; 20];
    let from_id = chain.create_eoa_account(&from_eth_address, 200000u64.into())?;

    let create_eth_addr = hex::decode("808bfd2069b1ca619a55585e7b1ac1b11d392af9")?;
    let create_eth_reg_addr =
        RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, create_eth_addr.clone());
    //create EOA account with create_account address first
    let eoa_id =
        chain.create_eoa_account(&create_eth_addr.try_into().unwrap(), 200000u64.into())?;

    assert_eq!(eoa_id, 6);

    let code = hex::decode(INIT_CODE)?;
    let _ = chain.deploy(from_id, &code, 170000, 1, 0)?;

    let script_hash = chain.get_script_hash_by_registry_address(&create_eth_reg_addr)?;
    assert!(script_hash.is_some());
    let create_account_id = chain.get_account_id_by_script_hash(&script_hash.unwrap())?;
    assert_eq!(create_account_id, Some(8));
    Ok(())
}

#[test]
fn create_address_collision_duplicate() -> Result<()> {
    let mut chain = ctx::MockChain::setup("..")?;

    let from_eth_address = [1u8; 20];
    let from_id = chain.create_eoa_account(&from_eth_address, 200000u64.into())?;

    let create_eth_addr = hex::decode("808bfd2069b1ca619a55585e7b1ac1b11d392af9")?;
    //create EOA account with create_account address first
    let eoa_id =
        chain.create_eoa_account(&create_eth_addr.try_into().unwrap(), 200000u64.into())?;
    assert_eq!(eoa_id, 6);

    let code = hex::decode(SS_CODE)?;
    let _ = chain.deploy(eoa_id, &code, 130000, 1, 0)?;
    let eoa_nonce = chain.get_nonce(eoa_id)?;
    assert_eq!(eoa_nonce, 1);

    let code = hex::decode(INIT_CODE)?;
    let run_result = chain.deploy(from_id, &code, 170000, 1, 0)?;
    assert_eq!(run_result.exit_code, 2);
    Ok(())
}

#[test]
fn create2_address_collision_overwrite() -> Result<()> {
    let mut chain = ctx::MockChain::setup("..")?;

    let from_eth_address = [1u8; 20];
    let from_id = chain.create_eoa_account(&from_eth_address, 200000u64.into())?;

    let create2_eth_addr = hex::decode("d78e81d86aeace84ff6311db7b134c1231a4a402")?;
    let create2_eth_reg_addr =
        RegistryAddress::new(ETH_REGISTRY_ACCOUNT_ID, create2_eth_addr.clone());
    //create EOA account with create_account address first
    let eoa_id =
        chain.create_eoa_account(&create2_eth_addr.try_into().unwrap(), 200000u64.into())?;

    assert_eq!(eoa_id, 6);

    let code = hex::decode(CREATE2_IMPL_CODE)?;
    let _ = chain.deploy(from_id, &code, 122000, 1, 0)?;

    let create2_contract = MockContractInfo::create(&from_eth_address, 0);
    let create2_contract_script_hash = create2_contract.script_hash;
    let create2_contract_id = chain
        .get_account_id_by_script_hash(&create2_contract_script_hash)?
        .unwrap();
    let input_value_u128: u128 = 0x9a;
    // bytes32 salt
    let input_salt = "1111111111111111111111111111111111111111111111111111111111111111";
    // Create2Impl.deploy(uint256 value, bytes32 salt, bytes memory code)
    //consturct input:
    //0x9a
    //input_salt
    //SS_INIT_CODE
    let input = hex::decode("66cfa057000000000000000000000000000000000000000000000000000000000000009a1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000ea6080604052607b60008190555060d08061001a6000396000f3fe60806040526004361060295760003560e01c806360fe47b11460345780636d4ce63c14605f57602f565b36602f57005b600080fd5b605d60048036036020811015604857600080fd5b81019080803590602001909291905050506087565b005b348015606a57600080fd5b5060716091565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea2646970667358221220b796688cdcda21059332f8ef75088337063fcf7a8ab96bb23bc06ec8623d679064736f6c6343000602003300000000000000000000000000000000000000000000")?;
    let run_result = chain.call(
        from_id,
        create2_contract_id,
        &input,
        91000,
        1,
        input_value_u128,
    )?;

    let create2_script = compute_create2_script(
        create2_contract.eth_addr.as_slice(),
        &hex::decode(input_salt).unwrap()[..],
        &hex::decode(SS_CODE).unwrap()[..],
    );
    let create2_script_hash = create2_script.hash();
    let create2_ethabi_addr = contract_script_to_eth_addr(&create2_script, true);
    println!(
        "computed create2_ethabi_addr: {}",
        hex::encode(&create2_ethabi_addr)
    );
    println!(
        "create2_address: 0x{}",
        hex::encode(&run_result.return_data)
    );
    assert_eq!(run_result.return_data, create2_ethabi_addr);

    let script_hash = chain.get_script_hash_by_registry_address(&create2_eth_reg_addr)?;
    assert!(script_hash.is_some());
    let create_account_id = chain.get_account_id_by_script_hash(&create2_script_hash.into())?;
    assert_eq!(create_account_id, Some(8));
    Ok(())
}

#[test]
fn create2_address_collision_duplicate() -> Result<()> {
    let mut chain = ctx::MockChain::setup("..")?;

    let from_eth_address = [1u8; 20];
    let from_id = chain.create_eoa_account(&from_eth_address, 200000u64.into())?;

    let create2_eth_addr = hex::decode("9267e505e0af739a9c434744d14a442792be98ef")?;
    //create EOA account with create_account address first
    let eoa_id =
        chain.create_eoa_account(&create2_eth_addr.try_into().unwrap(), 200000u64.into())?;

    assert_eq!(eoa_id, 6);
    let code = hex::decode(SS_CODE)?;
    let _ = chain.deploy(eoa_id, &code, 122000, 1, 0)?;
    let eoa_nonce = chain.get_nonce(eoa_id)?;
    assert_eq!(eoa_nonce, 1);

    let code = hex::decode(CREATE2_IMPL_CODE)?;
    let _ = chain.deploy(from_id, &code, 122000, 1, 0)?;

    let create2_contract = MockContractInfo::create(&from_eth_address, 0);
    let create2_contract_script_hash = create2_contract.script_hash;
    let create2_contract_id = chain
        .get_account_id_by_script_hash(&create2_contract_script_hash)?
        .unwrap();
    let input_value_u128: u128 = 0x9a;

    //consturct input:
    //0x9a
    //input_salt "1111111111111111111111111111111111111111111111111111111111111111"
    //SS_INIT_CODE
    // Create2Impl.deploy(uint256 value, bytes32 salt, bytes memory code)
    let input = hex::decode("66cfa057000000000000000000000000000000000000000000000000000000000000009a1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000ea6080604052607b60008190555060d08061001a6000396000f3fe60806040526004361060295760003560e01c806360fe47b11460345780636d4ce63c14605f57602f565b36602f57005b600080fd5b605d60048036036020811015604857600080fd5b81019080803590602001909291905050506087565b005b348015606a57600080fd5b5060716091565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea2646970667358221220b796688cdcda21059332f8ef75088337063fcf7a8ab96bb23bc06ec8623d679064736f6c6343000602003300000000000000000000000000000000000000000000").unwrap();
    let run_result = chain.call(
        from_id,
        create2_contract_id,
        &input,
        91000,
        1,
        input_value_u128,
    )?;
    assert_eq!(run_result.exit_code, 2);

    Ok(())
}
