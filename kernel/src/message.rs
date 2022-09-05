//! Message type in EuraliOS "Merriwig" kernel

use alloc::sync::Arc;
use spin::RwLock;
use x86_64::{VirtAddr, PhysAddr};

use crate::process::Thread;
use crate::rendezvous::Rendezvous;
use crate::syscalls;

/// Messages can transmit values, communication handles,
/// or memory chunks. In the kernel these are represented
/// as u64 values, Rendezvous objects, and physical memory
/// addresses.
pub enum MessageData {
    Value(u64),
    Rendezvous(Arc<RwLock<Rendezvous>>),
    Memory(PhysAddr)
}

impl From<u64> for MessageData {
    fn from (value: u64) -> Self {
        MessageData::Value(value)
    }
}
impl From<Arc<RwLock<Rendezvous>>> for MessageData {
    fn from (rv: Arc<RwLock<Rendezvous>>) -> Self {
        MessageData::Rendezvous(rv)
    }
}
impl From<PhysAddr> for MessageData {
    fn from (physaddr: PhysAddr) -> Self {
        MessageData::Memory(physaddr)
    }
}

/// Messages can be either Short or Long
///
/// Short messages just contain values
/// Long messages can contain memory or communication handles.
pub enum Message {
    Short(u64, u64, u64),
    Long(u64, MessageData, MessageData),
}

// Syscall message control bits
//
// The only constraint is that syscalls reserve the first 8 bits for
// the syscall number. The other 56 bits can be used as part of the
// message.
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

// General message types
pub const READ: u64 = 1;  // Short(READ, offset, length
pub const WRITE: u64 = 2; // Long(WRITE, length, handle)
pub const DATA: u64 = 2;  // Same as write
pub const CHAR: u64 = 3;
pub const JSON: u64 = 4;  // Information in JSON format
pub const VIDEO_MEMORY: u64 = 5; // Specific memory handle for video memory
pub const COMM_HANDLE: u64 = 6; // A communication handle

impl Message {
    /// Convert a Message into values which will be returned to user
    /// code by the receive or send_receive syscalls.
    ///
    /// Includes moving Rendezvous and memory chunks into the
    /// receiving process' handles and page tables, calling
    /// give_rendezvous() and give_memory_chunk() methods.
    ///
    /// Note: No error return type because errors are indicated to the
    ///       receiver in the values.
    pub fn to_values(
        &self,
        thread: &Thread
    ) -> (u64, u64, u64, u64) {
        match self {
            Message::Short(data1, data2, data3) => (0, *data1, *data2, *data3),
            Message::Long(data1, data2, data3) => {
                let mut ctrl: u64 = 0; // No error

                let value2 = match data2 {
                    MessageData::Value(value) => *value,
                    MessageData::Rendezvous(rdv) => {
                        ctrl |= MESSAGE_DATA2_RDV | MESSAGE_LONG;
                        thread.give_rendezvous(rdv.clone()) as u64
                    }
                    MessageData::Memory(physaddr) => {
                        match thread.give_memory_chunk(*physaddr) {
                            Ok(virtaddr) => {
                                ctrl |= MESSAGE_DATA2_MEM | MESSAGE_LONG;
                                virtaddr.as_u64()
                            }
                            Err(error_code) => {
                                ctrl |= MESSAGE_DATA2_ERR | MESSAGE_LONG;
                                error_code as u64
                            }
                        }
                    }
                };

                let value3 = match data3 {
                    MessageData::Value(value) => *value,
                    MessageData::Rendezvous(rdv) => {
                        ctrl |= MESSAGE_DATA3_RDV | MESSAGE_LONG;
                        thread.give_rendezvous(rdv.clone()) as u64
                    }
                    MessageData::Memory(physaddr) => {
                        match thread.give_memory_chunk(*physaddr) {
                            Ok(virtaddr) => {
                                ctrl |= MESSAGE_DATA3_MEM | MESSAGE_LONG;
                                virtaddr.as_u64()
                            }
                            Err(error_code) => {
                                ctrl |= MESSAGE_DATA3_ERR | MESSAGE_LONG;
                                error_code as u64
                            }
                        }
                    }
                };
                (ctrl, *data1, value2, value3)
            }
        }
    }

    /// Take data passed via syscall and convert to
    /// a kernel Message object.
    ///
    /// If the user passed rendezvous or memory handles then these are
    /// removed from the process using take_rendezvous() and
    /// take_memory_chunk() methods, and stored in the Message.
    ///
    pub fn from_values(
        thread: &mut Thread,
        syscall_id: u64,
        data1: u64,
        data2: u64,
        data3: u64) -> Result<Message, usize> {
        
        if syscall_id & MESSAGE_LONG == 0 {
            Ok(Message::Short(data1,
                              data2,
                              data3))
        } else {
            // Long message
            let message = Message::Long(
                data1,
                match syscall_id & MESSAGE_DATA2_TYPE {
                    MESSAGE_DATA2_RDV => {
                        // Moving or copying a handle
                        // First copy, then drop if message is valid
                        if let Some(rdv) = thread.rendezvous(data2) {
                            MessageData::Rendezvous(rdv)
                        } else {
                            // Invalid handle
                            return Err(syscalls::SYSCALL_ERROR_INVALID_HANDLE);
                        }
                    }
                    MESSAGE_DATA2_MEM => {
                        // Memory handle
                        let (physaddr, _level) = thread.memory_chunk(
                            VirtAddr::new(data2))?;
                        MessageData::Memory(physaddr)
                    }
                    _ => MessageData::Value(data2)
                },
                match syscall_id & MESSAGE_DATA3_TYPE {
                    MESSAGE_DATA3_RDV => {
                        if let Some(rdv) = thread.rendezvous(data3) {
                            MessageData::Rendezvous(rdv)
                        } else {
                            // Invalid handle.
                            // If we moved data2 we would have to put it back here
                            return Err(syscalls::SYSCALL_ERROR_INVALID_HANDLE);
                        }
                    }
                    MESSAGE_DATA3_MEM => {
                        // Memory handle
                        let (physaddr, _level) = thread.memory_chunk(
                            VirtAddr::new(data3))?;
                        MessageData::Memory(physaddr)
                    }
                    _ => MessageData::Value(data3)
                });
            // Message is valid => Remove handles being moved
            match syscall_id & MESSAGE_DATA2_TYPE {
                MESSAGE_DATA2_RDV => {
                    let _ = thread.take_rendezvous(data2);
                }
                MESSAGE_DATA2_MEM => {
                    let _ = thread.take_memory_chunk(VirtAddr::new(data2));
                }
                _ => {}
            }
            match syscall_id & MESSAGE_DATA3_TYPE {
                MESSAGE_DATA3_RDV => {
                    let _ = thread.take_rendezvous(data3);
                }
                MESSAGE_DATA3_MEM => {
                    let _ = thread.take_memory_chunk(VirtAddr::new(data3));
                }
                _ => {}
            }
            Ok(message)
        }
    }
}
