//! Message type in EuraliOS standard library
//!
//! Interface to syscalls from user code. Note that
//! the kernel message types are implemented differently.

use core::convert::From;

use crate::syscalls::{self, CommHandle, MemoryHandle, SyscallError};

#[derive(Debug)]
pub enum MessageData {
    Value(u64),
    MemoryHandle(MemoryHandle),
    CommHandle(CommHandle),
    Error(SyscallError)
}

impl MessageData {
    pub fn value(&self) -> u64 {
        match self {
            MessageData::Value(value) => *value,
            _ => panic!("Expected MessageData::Value")
        }
    }
    pub fn memory(self) -> MemoryHandle {
        match self {
            MessageData::MemoryHandle(handle) => handle,
            _ => panic!("Expected MessageData::Value")
        }
    }
}

#[derive(Debug)]
pub enum Message {
    Short(u64, u64, u64),
    Long(u64, MessageData, MessageData)
}

impl From<u64> for MessageData {
    fn from (value: u64) -> Self {
        MessageData::Value(value)
    }
}
impl From<MemoryHandle> for MessageData {
    fn from (handle: MemoryHandle) -> Self {
        MessageData::MemoryHandle(handle)
    }
}
impl From<CommHandle> for MessageData {
    fn from (handle: CommHandle) -> Self {
        MessageData::CommHandle(handle)
    }
}

// Syscall message control bits
const MESSAGE_LONG: u64 = 1 << 8;
const MESSAGE_DATA2_RDV: u64 = 1 << 9;
const MESSAGE_DATA2_MEM: u64 = 2 << 9;
const MESSAGE_DATA2_ERR: u64 = 3 << 9;

const MESSAGE_DATA2_TYPE: u64 =
    MESSAGE_DATA2_RDV | MESSAGE_DATA2_MEM | MESSAGE_DATA2_ERR; // Bit mask

const MESSAGE_DATA3_RDV: u64 = 1 << 11;
const MESSAGE_DATA3_MEM: u64 = 2 << 11;
const MESSAGE_DATA3_ERR: u64 = 3 << 11;

const MESSAGE_DATA3_TYPE: u64 =
    MESSAGE_DATA3_RDV | MESSAGE_DATA3_MEM | MESSAGE_DATA3_ERR; // Bit mask

impl Message {
    /// Convert a Message to values which can be put into registers
    /// for a send or send_receive syscall.
    ///
    /// This should be the inverse of from_values, and consistent with
    /// the kernel Message implementation.
    pub fn to_values(
        &mut self
    ) -> Result<(u64, u64, u64, u64), SyscallError> {
        match self {
            Message::Short(data1, data2, data3) => {
                Ok((0, *data1, *data2, *data3))
            },
            Message::Long(value1, ref mut data2, ref mut data3) => {
                let mut ctrl: u64 = MESSAGE_LONG;
                let value2 = match data2 {
                    MessageData::Value(value) => *value,
                    MessageData::CommHandle(ref mut handle) => {
                        ctrl |= MESSAGE_DATA2_RDV; // Rendezvous
                        unsafe{handle.take() as u64}
                    }
                    MessageData::MemoryHandle(ref mut handle) => {
                        ctrl |= MESSAGE_DATA2_MEM; // Memory
                        unsafe{handle.take()}
                    }
                    MessageData::Error(syserror) => {
                        ctrl |= MESSAGE_DATA2_ERR; // Error
                        syserror.as_u64()
                    }
                };
                let value3 = match data3 {
                    MessageData::Value(value) => *value,
                    MessageData::CommHandle(ref mut handle) => {
                        ctrl |= MESSAGE_DATA3_RDV; // Rendezvous
                        unsafe{handle.take() as u64}
                    }
                    MessageData::MemoryHandle(ref mut handle) => {
                        ctrl |= MESSAGE_DATA3_MEM; // Memory
                        unsafe{handle.take()}
                    }
                    MessageData::Error(syserror) => {
                        ctrl |= MESSAGE_DATA3_ERR; // Error
                        syserror.as_u64()
                    }
                };
                Ok((ctrl, *value1, value2, value3))
            }
        }
    }

    /// Reconstruct a Message from register values returned by a
    /// receive syscall.
    ///
    /// This should be the inverse of to_values, and consistent with
    /// the kernel Message implementation.
    pub fn from_values(
        ctrl: u64,
        data1: u64, data2: u64, data3: u64
    ) -> Message {
        if ctrl & MESSAGE_LONG == 0 {
            Message::Short(data1, data2, data3)
        } else {
            Message::Long(
                data1,
                match ctrl & MESSAGE_DATA2_TYPE {
                    MESSAGE_DATA2_RDV =>
                        MessageData::CommHandle(
                            CommHandle::new(data2 as u32)),
                    MESSAGE_DATA2_MEM =>
                        MessageData::MemoryHandle(
                            MemoryHandle::new(data2)),
                    MESSAGE_DATA2_ERR =>
                        MessageData::Error(
                            SyscallError::new(data2)),
                    _ => MessageData::Value(data2)
                },
                match ctrl & MESSAGE_DATA3_TYPE {
                    MESSAGE_DATA3_RDV =>
                        MessageData::CommHandle(
                            CommHandle::new(data3 as u32)),
                    MESSAGE_DATA3_MEM =>
                        MessageData::MemoryHandle(
                            MemoryHandle::new(data3)),
                    MESSAGE_DATA3_ERR =>
                        MessageData::Error(
                            SyscallError::new(data3)),
                    _ => MessageData::Value(data3)
                })
        }
    }
}

/// Remote call.
/// Wrapper around send_receive syscall
pub fn rcall(
    handle: &CommHandle,
    data1: u64,
    data2: MessageData,
    data3: MessageData,
    expect_rdata1: Option<u64>
) -> Result<(u64, MessageData, MessageData), (SyscallError, Message)> {

    let mut message = match (data2, data3) {
        (MessageData::Value(value2), MessageData::Value(value3)) => Message::Short(data1, value2, value3),
        (data2, data3) => Message::Long(data1, data2, data3)
    };

    const MAX_RETRIES: usize = 100;

    let mut retry = 0;
    loop {
        // Try sending
        let result = syscalls::send_receive(
            handle,
            message);

        match result {
            Err((syscalls::SYSCALL_ERROR_SEND_BLOCKING, ret_message)) |
            Err((syscalls::SYSCALL_ERROR_RECV_BLOCKING, ret_message)) => {
                // Rendezvous blocked => Wait and try again

                message = ret_message; // Handles may have changed

                retry += 1;
                if retry > MAX_RETRIES {
                    // Give up
                    return Err((syscalls::SYSCALL_ERROR_SEND_BLOCKING, message));
                }

                // Let another thread run
                syscalls::thread_yield();

                continue; // Go around for another try
            }
            Err(err_message) => {
                return Err(err_message);
            }
            Ok(Message::Short(rdata1, rdata2, rdata3)) => {
                if let Some(rd1) = expect_rdata1 {
                    // Filter on first argument
                    if rdata1 != rd1 {
                        return Err((SyscallError::new(0), Message::Short(rdata1, rdata2, rdata3)));
                    }
                }
                return Ok((rdata1, rdata2.into(), rdata3.into()));
            }
            Ok(Message::Long(rdata1, rdata2, rdata3)) => {
                if let Some(rd1) = expect_rdata1 {
                    // Filter on first argument
                    if rdata1 != rd1 {
                        return Err((SyscallError::new(0), Message::Long(rdata1, rdata2, rdata3)));
                    }
                }
                return Ok((rdata1, rdata2, rdata3));
            }
        }
    }
}

/// General message types
pub const READ: u64 = 1;  // Short(READ, offset, length
pub const WRITE: u64 = 2; // Long(WRITE, length, handle)
pub const DATA: u64 = 2;  // Same as write
pub const OPEN: u64 = 3;

pub const COMM_HANDLE: u64 = 64; // A communication handle

pub const EMPTY: u64 = 128;
pub const ERROR: u64 = 129;
pub const ERROR_INVALID_FORMAT: u64 = 130;
pub const ERROR_INVALID_UTF8: u64 = 131;
pub const ERROR_INVALID_VALUE: u64 = 132;

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

/// Message types specific to Network Interface Cards
pub mod nic {
    pub const GET_MAC_ADDRESS: u64 = 260;

    pub const MAC_ADDRESS: u64 = 300;
}
