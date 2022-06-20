use core::arch::asm;

use crate::syscalls::{self, CommHandle, SyscallError};

#[derive(Debug)]
pub enum Message {
    Short(u64, u64, u64),
    Long
}

impl Message {
    pub fn to_values(&self)
                 -> Result<(u64, u64, u64, u64), SyscallError> {
        match self {
            Message::Short(data1, data2, data3) => {
                Ok((0, *data1, *data2, *data3))
            },
            _ => Err(SyscallError::new(0))
        }
    }
    pub fn from_values(_ctrl: u64,
                   data1: u64, data2: u64, data3: u64)
                   -> Message {
        Message::Short(data1, data2, data3)
    }
}

/// Remote call.
/// Wrapper around send_receive syscall
pub fn rcall(
    handle: &CommHandle,
    data1: u64,
    data2: u64,
    data3: u64,
    expect_rdata1: Option<u64>
) -> Result<(u64, u64, u64), SyscallError> {

    const MAX_RETRIES: usize = 100;

    let mut retry = 0;
    loop {
        // Try sending
        let result = syscalls::send_receive(
            handle,
            Message::Short(data1, data2, data3));

        match result {
            Err(syscalls::SYSCALL_ERROR_SEND_BLOCKING) |
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Rendezvous blocked => Wait and try again

                retry += 1;
                if retry > MAX_RETRIES {
                    // Give up
                    return Err(syscalls::SYSCALL_ERROR_SEND_BLOCKING);
                }

                // Delay. Should have a syscall for short delay
                for _i in 0..10000 {
                    unsafe{asm!("nop")};
                }
                continue; // Go around for another try
            }
            Ok(Message::Short(rdata1, rdata2, rdata3)) => {
                if let Some(rd1) = expect_rdata1 {
                    // Filter on first argument
                    if rdata1 != rd1 {
                        return Err(SyscallError::new(0));
                    }
                }
                return Ok((rdata1, rdata2, rdata3));
            }
            _ => return Err(SyscallError::new(0)),
        }
    }
}

/// Message types for the system PCI program
pub mod pci {
    // Calls
    pub const FIND_DEVICE: u64 = 256;
    pub const READ_BAR: u64 = 257;
    pub const ENABLE_BUS_MASTERING: u64 = 258;

    // Replies

    /// The bus/slot/function address
    pub const ADDRESS: u64 = 384;
    pub const NOTFOUND: u64 = 385;
    pub const BAR: u64 = 386;
}
