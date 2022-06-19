use core::arch::asm;
use core::fmt;

pub use crate::message::Message;
use crate::debug_println;

/// Communication handle
#[derive(Debug)]
pub struct CommHandle(u32);

pub const STDIN:CommHandle = CommHandle(0);
pub const STDOUT:CommHandle = CommHandle(1);

/// Handle to a chunk of memory that can be
/// passed to other processes and free'd when dropped
///
/// Note: Cannot be copied, but can be sent to another process.
#[derive(Debug)]
pub struct MemoryHandle(u64);

impl MemoryHandle {
    /// Get a reference with lifetime tied to MemoryHandle
    pub unsafe fn as_ref<T>(&self) -> &T {
        & *(self.0 as *const T)
    }

    /// Get a mutable reference with lifetime tied to MemoryHandle
    pub unsafe fn as_mut_ref<T>(&mut self) -> &mut T {
        &mut *(self.0 as *mut T)
    }
}

impl Drop for MemoryHandle {
    fn drop(&mut self) {
        debug_println!("Drop MemoryHandle {:X}", self.0);
    }
}

/// Represents an error returned by a syscall
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SyscallError(u64);

impl SyscallError {
    pub fn new(value: u64) -> SyscallError {
        SyscallError(value)
    }
}

/// Spawn a new thread with a given entry point
///
/// # Returns
///
///  Ok(thread_id) or Err(error_code)
///
pub fn thread_spawn(func: extern "C" fn() -> ()) -> Result<u64, SyscallError> {
    let mut tid: u64;
    let mut errcode: u64;
    unsafe {
        asm!("mov rax, 0", // fork_current_thread syscall
             "syscall",
             // rax = 0 indicates no error
             "cmp rax, 0",
             "jnz 2f",
             // rdi = 0 for new thread
             "cmp rdi, 0",
             "jnz 2f",
             // New thread
             "call r8",
             "mov rax, 1", // exit_current_thread syscall
             "syscall",
             // New thread never leaves this asm block
             "2:",
             in("r8") func,
             lateout("rax") errcode,
             lateout("rdi") tid);
    }
    if errcode != 0 {
        return Err(SyscallError(errcode));
    }
    Ok(tid)
}

/// Exit the current thread. Never returns.
pub fn thread_exit() -> ! {
    unsafe {
        asm!("mov rax, 1", // exit_current_thread syscall
             "syscall",
             options(noreturn));
    }
}

/// Wait for a message to be received
pub fn receive(handle: &CommHandle) -> Result<Message, SyscallError> {
    let ctrl: u64;
    let (data1, data2, data3): (u64, u64, u64);
    unsafe {
        asm!("mov rax, 3", // sys_receive
             "syscall",
             in("rdi") handle.0,
             lateout("rax") ctrl,
             lateout("rdi") data1,
             lateout("rsi") data2,
             lateout("rdx") data3,
             out("rcx") _,
             out("r11") _);
    }
    let err = ctrl & 0xFF;
    if err == 0 {
        return Ok(Message::from_values(ctrl, data1, data2, data3));
    }
    Err(SyscallError(err))
}

/// Send a message and wait for it to be received
pub fn send(
    handle: &CommHandle,
    message: Message
) -> Result<(), SyscallError> {

    let (ctrl, data1, data2, data3) = message.to_values()?;

    let err: u64;
    unsafe {
        asm!("syscall",
             in("rax") 4 | ctrl | ((handle.0 as u64) << 32),
             in("rdi") data1,
             in("rsi") data2,
             in("rdx") data3,
             lateout("rax") err,
             out("rcx") _,
             out("r11") _);
    }
    if err == 0 {
        return Ok(());
    }
    Err(SyscallError(err))
}

/// Send a message and wait for a message back from the same thread
pub fn send_receive(
    handle: &CommHandle,
    message: Message
) -> Result<Message, SyscallError> {

    // Convert the message to register values
    let (ctrl, data1, data2, data3) = message.to_values()?;

    // Values to be received
    let (ret_ctrl, ret_data1, ret_data2, ret_data3): (u64, u64, u64, u64);
    unsafe {
        asm!("syscall",
             in("rax") 5 | ctrl | ((handle.0 as u64) << 32),
             in("rdi") data1,
             in("rsi") data2,
             in("rdx") data3,
             lateout("rax") ret_ctrl,
             lateout("rdi") ret_data1,
             lateout("rsi") ret_data2,
             lateout("rdx") ret_data3,
             out("rcx") _,
             out("r11") _);
    }
    let err = ret_ctrl & 0xFF;
    if err == 0 {
        return Ok(Message::from_values(ret_ctrl,
                                       ret_data1, ret_data2, ret_data3));
    }
    Err(SyscallError(err))
}

/// Returns a handle on success, or an error code
pub fn open(path: &str) -> Result<CommHandle, SyscallError> {
    let error: u64;
    let handle: u32;
    unsafe {
        asm!("mov rax, 6", // syscall function
             "syscall",
             in("rdi") path.as_ptr(), // First argument
             in("rsi") path.len(), // Second argument
             out("rax") error,
             lateout("rdi") handle,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        Ok(CommHandle(handle))
    } else {
        Err(SyscallError(error))
    }
}

pub fn malloc(
    num_bytes: u64,
    max_physaddr: u64
) -> Result<(MemoryHandle, u64), SyscallError> {

    let num_pages = (num_bytes >> 12) +
        if (num_bytes & 4095) != 0 {1} else {0};

    let error: u64;
    let handle: u16;
    let virtaddr: u64;
    let physaddr: u64;
    unsafe {
        asm!("mov rax, 7", // syscall function
             "syscall",
             in("rdi") num_pages, // First argument
             in("rsi") max_physaddr, // Second argument
             out("rax") error,
             lateout("rdi") virtaddr,
             lateout("rsi") physaddr,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        Ok((MemoryHandle(virtaddr), physaddr))
    } else {
        Err(SyscallError(error))
    }
}

// Syscall numbers
pub const SYSCALL_MASK: u64 = 0xFF;
pub const SYSCALL_FORK_THREAD: u64 = 0;
pub const SYSCALL_EXIT_THREAD: u64 = 1;
pub const SYSCALL_DEBUG_WRITE: u64 = 2;
pub const SYSCALL_RECEIVE: u64 = 3;
pub const SYSCALL_SEND: u64 = 4;
pub const SYSCALL_SENDRECEIVE: u64 = 5;
pub const SYSCALL_OPEN: u64 = 6;

// Syscall error codes
pub const SYSCALL_ERROR_SEND_BLOCKING: SyscallError = SyscallError(1);
pub const SYSCALL_ERROR_RECV_BLOCKING: SyscallError = SyscallError(2);
pub const SYSCALL_ERROR_INVALID_HANDLE: SyscallError = SyscallError(3);
pub const SYSCALL_ERROR_MEMALLOC: SyscallError = SyscallError(4); // Memory allocation error
pub const SYSCALL_ERROR_PARAM: SyscallError = SyscallError(5); // Invalid parameter
pub const SYSCALL_ERROR_UTF8: SyscallError = SyscallError(6); // UTF8 conversion error
pub const SYSCALL_ERROR_NOTFOUND: SyscallError = SyscallError(7);

impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} : {}", self.0,
               match *self {
                   SYSCALL_ERROR_SEND_BLOCKING => "Send blocking",
                   SYSCALL_ERROR_RECV_BLOCKING => "Receive blocking",
                   SYSCALL_ERROR_INVALID_HANDLE => "Invalid handle",
                   SYSCALL_ERROR_MEMALLOC => "Memory allocation error",
                   SYSCALL_ERROR_PARAM => "Invalid parameter",
                   SYSCALL_ERROR_UTF8 => "UTF8 conversion error",
                   SYSCALL_ERROR_NOTFOUND => "Not found",
                   _ => "Unknown error"
               })
    }
}

// Standard message types
pub const MESSAGE_TYPE_CHAR: u64 = 0;
