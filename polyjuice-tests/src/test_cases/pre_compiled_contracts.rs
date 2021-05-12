use crate::helper::{SECP_DATA_HASH, SECP_DATA};
use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    memory::Memory,
    registers::{A0, A3, A7},
    DefaultMachineBuilder, Error as VMError, Register, SupportMachine, Syscalls,
};
use gw_common::H256;
use gw_generator::syscalls::store_data;
use gw_types::bytes::Bytes;
use std::collections::HashMap;

const BINARY: &[u8] = include_bytes!("../../../build/test_contracts");
const SUCCESS: u8 = 0;
const DEBUG_PRINT_SYSCALL_NUMBER: u64 = 2177;

pub struct L2Syscalls {
    data: HashMap<H256, Bytes>,
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
            4057 => {
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

        let s = String::from_utf8(buffer).map_err(|_| VMError::ParseError)?;
        println!("[contract debug]: {}", s);
        Ok(())
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
    data.insert(SECP_DATA_HASH.clone(), Bytes::from(SECP_DATA.to_vec()));

    let core_machine = Box::<AsmCoreMachine>::default();
    let machine_builder =
        DefaultMachineBuilder::new(core_machine).syscall(Box::new(L2Syscalls { data }));
    let mut machine = AsmMachine::new(machine_builder.build(), None);
    machine.load_program(&binary, &[]).unwrap();
    let code = machine.run().unwrap();
    assert_eq!(code, 0);
}
