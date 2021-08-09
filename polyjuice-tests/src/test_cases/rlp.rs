use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    memory::Memory,
    registers::{A0, A7},
    DefaultMachineBuilder, Error as VMError, Register, SupportMachine, Syscalls,
};
// use gw_types::bytes::Bytes;

const BINARY: &[u8] = include_bytes!("../../../build/test_rlp");
const DEBUG_PRINT_SYSCALL_NUMBER: u64 = 2177;

pub struct L2Syscalls;

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
fn test_rlp() {
    let core_machine = AsmCoreMachine::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
        ckb_vm::machine::VERSION1,
        1,
    ); //TODO: test MAX_CYCLES_EXCEEDED
    let machine_builder = DefaultMachineBuilder::new(core_machine).syscall(Box::new(L2Syscalls));
    let mut machine = AsmMachine::new(machine_builder.build(), None);
    machine
        .load_program(&ckb_vm::Bytes::from_static(BINARY), &[])
        .unwrap();
    let code = machine.run().unwrap();
    assert_eq!(code, 0);
}
