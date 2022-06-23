use core::arch::asm;
use core::fmt;

pub use crate::message::Message;
use crate::debug_println;

/// Communication handle
#[derive(Debug)]
pub struct CommHandle(u32);

pub const STDIN:CommHandle = CommHandle(0);
pub const STDOUT:CommHandle = CommHandle(1);

impl CommHandle {
    pub fn new(handle: u32) -> Self {
        CommHandle(handle)
    }

    pub unsafe fn take(&mut self) -> u32 {
        let handle = self.0;
        self.0 = 0;
        handle
    }
}

impl Drop for CommHandle {
    /// Drop a CommHandle by removing the Rendezvous pointer
    fn drop(&mut self) {
        if self.0 == 0 {
            return; // Already taken
        }
    }
}

/// Handle to a chunk of memory that can be
/// passed to other processes and free'd when dropped
///
/// Note: Cannot be copied, but can be sent to another process.
#[derive(Debug)]
pub struct MemoryHandle(u64);

impl MemoryHandle {
    pub fn new(virtaddr: u64) -> Self {
        MemoryHandle(virtaddr)
    }

    /// Get the virtual address of the start of the memory region
    pub fn as_u64(&self) -> u64 {
        return self.0;
    }
    /// Take the value out of the handle
    /// Note: When the handle is dropped the memory
    ///       the memory will not be freed
    pub unsafe fn take(&mut self) -> u64 {
        let handle = self.0;
        self.0 = 0;
        handle
    }

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
    /// Drop a MemoryHandle by freeing the memory
    fn drop(&mut self) {
        if self.0 == 0 {
            return; // Already taken
        }
        let error: u64;
        unsafe {
            asm!("syscall",
                 in("rax") SYSCALL_FREE,
                 in("rdi") self.0, // First argument
                 lateout("rax") error,
                 out("rcx") _,
                 out("r11") _);
        }

        if error != 0 {
            debug_println!("MemoryHandle::drop({:X}) error {}", self.0, error);
        }
    }
}

/// Represents an error returned by a syscall
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SyscallError(u64);

impl SyscallError {
    pub fn new(value: u64) -> SyscallError {
        SyscallError(value)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Spawn a new thread with a given entry point
///
/// # Returns
///
///  Ok(thread_id) or Err(error_code)
///
pub fn thread_spawn(func: extern "C" fn() -> ()) -> Result<u64, SyscallError> {
    let tid: u64;
    let errcode: u64;
    unsafe {
        asm!("syscall",
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
             in("rax") SYSCALL_FORK_THREAD,
             in("r8") func,
             lateout("rax") errcode,
             lateout("rdi") tid,
             out("rcx") _,
             out("r11") _);
    }
    if errcode != 0 {
        return Err(SyscallError(errcode));
    }
    Ok(tid)
}

/// Exit the current thread. Never returns.
pub fn thread_exit() -> ! {
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_EXIT_THREAD,
             options(noreturn));
    }
}

/// Wait for a message to be received
pub fn receive(handle: &CommHandle) -> Result<Message, SyscallError> {
    let ctrl: u64;
    let (data1, data2, data3): (u64, u64, u64);
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_RECEIVE,
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
    mut message: Message
) -> Result<(), SyscallError> {

    let (ctrl, data1, data2, data3) = message.to_values()?;

    let err: u64;
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_SEND | ctrl | ((handle.0 as u64) << 32),
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
    mut message: Message
) -> Result<Message, SyscallError> {

    // Convert the message to register values
    let (ctrl, data1, data2, data3) = message.to_values()?;

    // Values to be received
    let (ret_ctrl, ret_data1, ret_data2, ret_data3): (u64, u64, u64, u64);
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_SENDRECEIVE | ctrl | ((handle.0 as u64) << 32),
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
        asm!("syscall",
             in("rax") SYSCALL_OPEN,
             in("rdi") path.as_ptr(), // First argument
             in("rsi") path.len(), // Second argument
             lateout("rax") error,
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
    let virtaddr: u64;
    let physaddr: u64;
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_MALLOC,
             in("rdi") num_pages, // First argument
             in("rsi") max_physaddr, // Second argument
             lateout("rax") error,
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
pub const SYSCALL_MALLOC: u64 = 7;
pub const SYSCALL_FREE: u64 = 8;

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
