use ckb_vm::{
    memory::Memory,
    DefaultMachineBuilder,
    machine::asm::{AsmCoreMachine, AsmMachine},
    registers::{A0, A1, A2, A3, A7},
    Error as VMError, Register, SupportMachine, Syscalls,
};
use gw_types::{bytes::Bytes, prelude::*};

const BINARY: &[u8] = include_bytes!("../../../build/test_contracts");

pub struct L2Syscalls {
}

impl<Mac: SupportMachine> Syscalls<Mac> for L2Syscalls {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();
        match code {
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
    let core_machine = Box::<AsmCoreMachine>::default();
    let machine_builder = DefaultMachineBuilder::new(core_machine).syscall(Box::new(L2Syscalls {}));
    let mut machine = AsmMachine::new(machine_builder.build(), None);
    machine.load_program(&binary, &[]).unwrap();
    let code = machine.run().unwrap();
    assert_eq!(code, 0);
}
