use criterion::{black_box, criterion_group, Criterion};

use ckb_vm::{
    machine::asm::{AsmCoreMachine, AsmMachine},
    memory::Memory,
    registers::{A0, A7},
    DefaultMachineBuilder, Error as VMError, Register, SupportMachine, Syscalls,
};
use gw_types::bytes::Bytes;

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

fn test_rlp() {
    let binary: Bytes = BINARY.to_vec().into();
    let core_machine = Box::<AsmCoreMachine>::default();
    let machine_builder = DefaultMachineBuilder::new(core_machine).syscall(Box::new(L2Syscalls));
    let mut machine = AsmMachine::new(machine_builder.build(), None);
    machine.load_program(&binary, &[]).unwrap();
    let code = machine.run().unwrap();
    assert_eq!(code, 0);
}

pub fn bench(c: &mut Criterion) {
    c.bench_function("rlp", |b| b.iter(|| test_rlp()));
}

criterion_group!{
    name = bench_rlp;
    config = Criterion::default().sample_size(10);
    targets = bench
}
