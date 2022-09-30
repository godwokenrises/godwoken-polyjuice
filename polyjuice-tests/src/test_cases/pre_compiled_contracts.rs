use crate::helper::{
    create_block_producer, deploy, new_block_info, setup, MockContractInfo, PolyjuiceArgsBuilder,
    CREATOR_ACCOUNT_ID, L2TX_MAX_CYCLES, SECP_DATA, SECP_DATA_HASH,
};
use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    memory::Memory,
    registers::{A0, A1, A3, A7},
    DefaultMachineBuilder, Error as VMError, Register, SupportMachine, Syscalls,
};
use gw_common::{
    h256_ext::H256Ext,
    state::{build_data_hash_key, State},
    H256,
};
use gw_generator::syscalls::store_data;
use gw_store::traits::chain_store::ChainStore;
use gw_types::{
    bytes::Bytes,
    packed::RawL2Transaction,
    prelude::{Builder, Entity, Pack},
};
use std::collections::HashMap;

const BINARY: &[u8] = include_bytes!("../../../build/test_contracts");
const SUCCESS: u8 = 0;
const SYS_LOAD: u64 = 3102;
const SYS_LOAD_DATA: u64 = 3302;
const DEBUG_PRINT_SYSCALL_NUMBER: u64 = 2177;

const PRECOMPILED_CONTRACT_CODE: &str = include_str!("./evm-contracts/PreCompiledContracts.bin");

pub struct L2Syscalls {
    data: HashMap<H256, Bytes>,
    tree: HashMap<H256, H256>,
}

fn load_data_h256<Mac: SupportMachine>(machine: &mut Mac, addr: u64) -> Result<H256, VMError> {
    let mut data = [0u8; 32];
    for (i, c) in data.iter_mut().enumerate() {
        *c = machine
            .memory_mut()
            .load8(&Mac::REG::from_u64(addr).overflowing_add(&Mac::REG::from_u64(i as u64)))?
            .to_u8();
    }
    Ok(H256::from(data))
}

impl<Mac: SupportMachine> Syscalls<Mac> for L2Syscalls {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();

        if code != DEBUG_PRINT_SYSCALL_NUMBER {
            println!("code: {}", code);
        }
        match code {
            SYS_LOAD => {
                let key_addr = machine.registers()[A0].to_u64();
                let key = load_data_h256(machine, key_addr)?;
                let value_addr = machine.registers()[A1].to_u64();
                let value = self.tree.get(&key).ok_or_else(|| {
                    println!("can not found key: {:?}", key);
                    VMError::Unexpected("Cannot find key".to_string())
                })?;
                machine
                    .memory_mut()
                    .store_bytes(value_addr, value.as_slice())?;
                machine.set_register(A0, Mac::REG::from_u8(SUCCESS));
                Ok(true)
            }
            SYS_LOAD_DATA => {
                let data_hash_addr = machine.registers()[A3].to_u64();
                let data_hash = load_data_h256(machine, data_hash_addr)?;
                println!("data_hash: {:?}", data_hash);
                let data = self.data.get(&data_hash).unwrap();
                store_data(machine, data.as_ref())?;
                machine.set_register(A0, Mac::REG::from_u8(SUCCESS));
                Ok(true)
            }
            DEBUG_PRINT_SYSCALL_NUMBER => {
                self.output_debug(machine)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

impl L2Syscalls {
    fn output_debug<Mac: SupportMachine>(&self, machine: &mut Mac) -> Result<(), VMError> {
        let mut addr = machine.registers()[A0].to_u64();
        let mut buffer = Vec::new();

        loop {
            let byte = machine
                .memory_mut()
                .load8(&Mac::REG::from_u64(addr))?
                .to_u8();
            if byte == 0 {
                break;
            }
            buffer.push(byte);
            addr += 1;
        }

        let s = String::from_utf8(buffer)
            .map_err(|_| VMError::Unexpected("Cannot convert to utf8".to_string()))?;
        println!("[contract debug]: {}", s);
        Ok(())
    }
}

struct AsmCoreMachineParams {
    pub vm_isa: u8,
    pub vm_version: u32,
}

impl AsmCoreMachineParams {
    pub fn with_version(vm_version: u32) -> Result<AsmCoreMachineParams, VMError> {
        if vm_version == 0 {
            Ok(AsmCoreMachineParams {
                vm_isa: ckb_vm::ISA_IMC,
                vm_version: ckb_vm::machine::VERSION0,
            })
        } else if vm_version == 1 {
            Ok(AsmCoreMachineParams {
                vm_isa: ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
                vm_version: ckb_vm::machine::VERSION1,
            })
        } else {
            Err(VMError::InvalidVersion)
        }
    }
}

#[test]
fn test_contracts() {
    let binary: Bytes = BINARY.to_vec().into();
    println!(
        "secp_data_hash: {:?}, data.len(): {}",
        *SECP_DATA_HASH,
        SECP_DATA.len()
    );
    let mut data = HashMap::default();
    data.insert(*SECP_DATA_HASH, Bytes::from(SECP_DATA.to_vec()));
    let mut tree = HashMap::default();
    tree.insert(build_data_hash_key(SECP_DATA_HASH.as_slice()), H256::one());

    let params = AsmCoreMachineParams::with_version(1).unwrap();
    let core_machine = AsmCoreMachine::new(params.vm_isa, params.vm_version, L2TX_MAX_CYCLES);

    let machine_builder =
        DefaultMachineBuilder::new(core_machine).syscall(Box::new(L2Syscalls { data, tree }));
    let mut machine = AsmMachine::new(machine_builder.build(), None);
    machine.load_program(&binary, &[]).unwrap();
    let code = machine.run().unwrap();
    assert_eq!(code, 0);
}

#[test]
fn test_elliptic_curve_calc() -> anyhow::Result<()> {
    // const L2TX_MAX_CYCLES: u64 = 1000_000_000; // TODO: check cycles of add, mul and pairing

    let (store, mut state, generator) = setup();
    let block_producer = create_block_producer(&mut state);

    let from_eth_address = [1u8; 20];
    let (from_id, _from_script_hash) =
        crate::helper::create_eth_eoa_account(&mut state, &from_eth_address, 200000000u64.into());

    // Deploy PreCompiledContracts.sol
    let mut block_number = 0;
    let _run_result = deploy(
        &generator,
        &store,
        &mut state,
        CREATOR_ACCOUNT_ID,
        from_id,
        PRECOMPILED_CONTRACT_CODE,
        1284600,
        0,
        block_producer.clone(),
        block_number,
    );
    let contract_account = MockContractInfo::create(&from_eth_address, 0);
    let contract_account_id = state
        .get_account_id_by_script_hash(&contract_account.script_hash)?
        .unwrap();

    // call callBn256Add
    // Input	Output
    // 1	    0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3
    // 2	    0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4
    // 1
    // 2
    {
        block_number += 1;
        let input = hex::decode("4849f2790000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002")?;
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(30000)
            .gas_price(1u128)
            .value(0u128)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &gw_store::chain_view::ChainView::new(&db, tip_block_hash),
                &state,
                &new_block_info(block_producer.clone(), block_number, 0),
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("callBn256Add");
        assert_eq!(run_result.exit_code, crate::constant::EVMC_SUCCESS);
        assert_eq!(
            run_result.return_data.as_ref(),
            hex::decode("030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4")
                .unwrap()
        );
        // TODO: check used_cycles
    }

    // call callBn256ScalarMul
    // Input	Output
    // 1	    0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3
    // 2	    0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4
    // 2
    {
        block_number += 1;
        let input = hex::decode("ec8b466a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002")?;
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(30299)
            .gas_price(1u128)
            .value(0u128)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &gw_store::chain_view::ChainView::new(&db, tip_block_hash),
                &state,
                &new_block_info(block_producer.clone(), block_number, 0),
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("callBn256ScalarMul");
        assert_eq!(run_result.exit_code, crate::constant::EVMC_SUCCESS);
        assert_eq!(
            run_result.return_data.as_ref(),
            hex::decode("030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4")
                .unwrap()
        );
    }

    // call Bn256PairingIstanbul
    {
        block_number += 1;
        let input = hex::decode("e840916c")?;
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(146049)
            .gas_price(1u128)
            .value(0u128)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &gw_store::chain_view::ChainView::new(&db, tip_block_hash),
                &state,
                &new_block_info(block_producer.clone(), block_number, 0),
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("Call Bn256PairingIstanbul");
        assert_eq!(run_result.exit_code, crate::constant::EVMC_SUCCESS);
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
        );
        crate::helper::check_cycles("Call Bn256PairingIstanbul", run_result.cycles.execution, 1);
    }

    // callBn256Pairing with input
    {
        block_number += 1;
        let input = hex::decode("b2acd509000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001801c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")?;
        let args = PolyjuiceArgsBuilder::default()
            .gas_limit(152078)
            .gas_price(1u128)
            .value(0u128)
            .input(&input)
            .build();
        let raw_tx = RawL2Transaction::new_builder()
            .from_id(from_id.pack())
            .to_id(contract_account_id.pack())
            .args(Bytes::from(args).pack())
            .build();
        let db = store.begin_transaction();
        let tip_block_hash = db.get_tip_block_hash().unwrap();
        let run_result = generator
            .execute_transaction(
                &gw_store::chain_view::ChainView::new(&db, tip_block_hash),
                &state,
                &new_block_info(block_producer.clone(), block_number, 0),
                &raw_tx,
                L2TX_MAX_CYCLES,
                None,
            )
            .expect("Call Bn256Pairing with input");
        assert_eq!(run_result.exit_code, crate::constant::EVMC_SUCCESS);
        assert_eq!(
            run_result.return_data,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
        );
    }
    Ok(())
}
