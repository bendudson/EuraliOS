use core::arch::asm;
use core::{fmt, ptr, slice, clone::Clone};

pub use crate::message::{self, Message};
use crate::debug_println;
use crate::ffi::OsStr;

/// Communication handle
#[derive(Debug)]
pub struct CommHandle(u32);

pub static STDIN:CommHandle = CommHandle(0);
pub static STDOUT:CommHandle = CommHandle(1);

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
        // close syscall
        unsafe {
            asm!("syscall",
                 in("rax") SYSCALL_CLOSE,
                 in("rdi") self.0, // First argument
                 out("rcx") _,
                 out("r11") _);
        }
    }
}

impl Clone for CommHandle {
    /// Makes a copy of a communication handle
    fn clone(&self) -> Self {
        let error: u64;
        let new_handle: u32;
        unsafe {
            asm!("syscall",
                 in("rax") SYSCALL_COPY_RENDEZVOUS,
                 in("rdi") self.0, // First argument
                 lateout("rax") error,
                 lateout("rdi") new_handle,
                 out("rcx") _,
                 out("r11") _);
        }
        if error != 0 {
            panic!("CommHandle::clone({:X}) error {}", self.0, error);
        }
        CommHandle(new_handle)
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

    pub fn from_u8_slice(values: &[u8]) -> Self {
        // Allocate memory
        let (mem_handle, _) = malloc(values.len() as u64, 0).unwrap();
        // Copy data from slice into memory
        unsafe{
            ptr::copy_nonoverlapping(values.as_ptr(),
                                     mem_handle.as_u64() as *mut u8,
                                     values.len());
        }
        mem_handle
    }

    pub fn as_slice<T>(&self, length: usize) -> &[T] {
        unsafe{slice::from_raw_parts(
            self.as_ptr::<T>(),
            length)}
    }

    pub fn as_mut_slice<T>(&mut self, length: usize) -> &mut [T] {
        unsafe{slice::from_raw_parts_mut(
            self.as_mut_ptr::<T>(),
            length)}
    }

    /// Get the virtual address of the start of the memory region
    pub fn as_u64(&self) -> u64 {
        return self.0;
    }
    /// Take the value out of the handle
    /// Note: When the handle is dropped the memory will not be freed
    pub unsafe fn take(&mut self) -> u64 {
        let handle = self.0;
        self.0 = 0;
        handle
    }

    pub unsafe fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    /// Get a reference with lifetime tied to MemoryHandle
    pub unsafe fn as_ref<T>(&self) -> &T {
        & *(self.0 as *const T)
    }

    /// Get a mutable reference with lifetime tied to MemoryHandle
    pub unsafe fn as_mut_ref<T>(&mut self) -> &mut T {
        &mut *(self.0 as *mut T)
    }

    pub unsafe fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.0 as *mut T
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
pub fn thread_spawn(
    func: extern "C" fn(usize) -> (),
    param: usize
) -> Result<u64, SyscallError> {

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
             "mov rdi, r9", // Function argument
             "call r8",
             "mov rax, 1", // exit_current_thread syscall
             "syscall",
             // New thread never leaves this asm block
             "2:",
             in("rax") SYSCALL_FORK_THREAD,
             in("r8") func,
             in("r9") param,
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

/// Gives up the processor for another thread to run.
///
/// Usually called when a thread has nothing useful to do
/// and can wait for an undetermined amount of time.
pub fn thread_yield() {
    unsafe{
        asm!("syscall",
             in("rax") SYSCALL_YIELD,
             out("rcx") _,
             out("r11") _);
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
///
/// If an error occurs then a message is returned.
/// Note: handles not guaranteed to have same internal state
pub fn send(
    handle: &CommHandle,
    mut message: Message
) -> Result<(), (SyscallError, Message)> {

    let (ctrl, data1, data2, data3) = message.to_values().map_err(|e| (e, message))?;

    let ret_ctrl: u64;
    let ret_data1: u64;
    let ret_data2: u64;
    let ret_data3: u64;
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_SEND | ctrl | ((handle.0 as u64) << 32),
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
    let err = ret_ctrl & (SYSCALL_ERROR_MASK as u64);
    if err == 0 {
        return Ok(());
    }
    if ret_ctrl & (SYSCALL_ERROR_CONTAINS_MESSAGE as u64) != 0 {
        // Error. Original message not valid, new message returned
        return Err((SyscallError(err),
                    Message::from_values(ret_ctrl,
                                         ret_data1, ret_data2, ret_data3)));
    }
    // Error, original message still valid
    Err((SyscallError(err), Message::from_values(ctrl,
                                                 data1, data2, data3)))
}

/// Send a message and wait for a message back from the same thread
///
///
pub fn send_receive(
    handle: &CommHandle,
    mut message: Message
) -> Result<Message, (SyscallError, Message)> {

    // Convert the message to register values
    let (ctrl, data1, data2, data3) = message.to_values().map_err(|e| (e, message))?;

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
    let err = ret_ctrl & (SYSCALL_ERROR_MASK as u64);
    if err == 0 {
        return Ok(Message::from_values(ret_ctrl,
                                       ret_data1, ret_data2, ret_data3));
    }
    if ret_ctrl & (SYSCALL_ERROR_CONTAINS_MESSAGE as u64) != 0{
        // Error. Original message not valid, new message returned
        return Err((SyscallError(err),
                    Message::from_values(ret_ctrl,
                                         ret_data1, ret_data2, ret_data3)));
        }
    // Error, original message still valid
    Err((SyscallError(err), Message::from_values(ctrl,
                                                 data1, data2, data3)))
}

/// Returns a handle on success, or an error code
///
/// flags   zero (0) for readonly, or a combination (sum) of O_WRITE,
///         O_CREATE and O_TRUNCATE
#[inline]
pub fn open<T: AsRef<OsStr>>(path: T, flags: u64) -> Result<CommHandle, SyscallError> {
    _open(path.as_ref().to_str().unwrap(), flags)
}

fn _open(path: &str, flags: u64) -> Result<CommHandle, SyscallError> {
    let error: u64;
    let handle: u32;
    let match_len: usize;
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_OPEN,
             in("rdi") path.as_ptr(), // First argument
             in("rsi") path.len(), // Second argument
             lateout("rax") error,
             lateout("rdi") handle,
             lateout("rsi") match_len,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        // Found mount point
        let subpath = &path[match_len..];

        if subpath.len() != 0 {
            // Send unmatched part of the path to the given handle
            let bytes = subpath.as_bytes();

            match message::rcall(
                &CommHandle(handle),
                message::OPEN_READONLY + flags,
                (bytes.len() as u64).into(),
                MemoryHandle::from_u8_slice(bytes).into(),
                None) {
                // Success, returning a communication handle
                Ok((message::COMM_HANDLE,
                    message::MessageData::CommHandle(handle), _)) => {
                    return Ok(handle);
                }
                msg => {
                    debug_println!("Unexpected rcall reply {:?}", msg);
                    return Err(SYSCALL_ERROR_NOTFOUND);
                }
            }
        }
        Ok(CommHandle(handle))
    } else {
        Err(SyscallError(error))
    }
}

pub fn malloc(
    num_bytes: u64,
    max_physaddr: u64
) -> Result<(MemoryHandle, u64), SyscallError> {

    if num_bytes == 0 {
        return Err(SYSCALL_ERROR_PARAM);
    }

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

pub fn new_rendezvous() -> Result<(CommHandle, CommHandle), SyscallError> {
    let error: u64;
    let handle1: u32;
    let handle2: u32;
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_NEW_RENDEZVOUS,
             lateout("rax") error,
             lateout("rdi") handle1,
             lateout("rsi") handle2,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        Ok((CommHandle(handle1), CommHandle(handle2)))
    } else {
        Err(SyscallError(error))
    }
}

/// Execute a new process
///
/// # Arguments
///
/// * `bin`    - A slice containing ELF binary data
/// * `flags`  - Permission flags
/// * `stdin`  - The new process' STDIN communication handle
/// * `stdout` - The new process' STDOUT communication handle.
///
/// Returns the thread ID if successful, or a `SyscallError`
pub fn exec(
    bin: &[u8],
    flags: u8,
    mut stdin: CommHandle,
    mut stdout: CommHandle) -> Result<u64, SyscallError> {

    let error: u64;
    let tid: u64;
    unsafe {
        asm!("syscall",
             // RAX contains | bin length (32) | param length (16) | flags (8) | syscall (8)
             in("rax") SYSCALL_EXEC | ((flags as u64) << 8) | ((bin.len() as u64) << 32),
             // RDI contains pointer to ELF binary data
             in("rdi") bin.as_ptr() as usize,
             // RSI contains STDIN & STDOUT handles
             in("rsi") ((stdin.take() as u64) << 32) | (stdout.take() as u64),
             // RDX will contain a pointer to a parameter string
             in("rdx") 0,
             lateout("rax") error,
             lateout("rdi") tid,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        // Return new thread ID
        Ok(tid)
    } else {
        Err(SyscallError(error))
    }
}

pub fn mount(path: &str, mut handle: CommHandle) -> Result<(), SyscallError> {
    let error: u64;
    unsafe {
        asm!("syscall",
             // RAX contains | handle (32) | empty (24) | syscall (8)
             in("rax") SYSCALL_MOUNT | ((handle.take() as u64) << 32),
             // RDI contains pointer to string data
             in("rdi") path.as_ptr() as usize,
             // RSI contains string length
             in("rsi") path.len(),
             lateout("rax") error,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        Ok(())
    } else {
        Err(SyscallError(error))
    }
}

pub fn list_mounts() -> Result<(MemoryHandle, u64), SyscallError> {
    let error: u64;
    let mem_handle: u64;
    let length: u64;
    unsafe {
        asm!("syscall",
             in("rax") SYSCALL_LISTMOUNTS,
             lateout("rax") error,
             lateout("rdi") mem_handle,
             lateout("rsi") length,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        Ok((MemoryHandle(mem_handle), length))
    } else {
        Err(SyscallError(error))
    }
}

pub fn umount(path: &str) -> Result<(), SyscallError> {
    let error: u64;
    unsafe {
        asm!("syscall",
             // RAX contains syscall (8)
             in("rax") SYSCALL_UMOUNT,
             // RDI contains pointer to string data
             in("rdi") path.as_ptr() as usize,
             // RSI contains string length
             in("rsi") path.len(),
             lateout("rax") error,
             out("rcx") _,
             out("r11") _);
    }
    if error == 0 {
        Ok(())
    } else {
        Err(SyscallError(error))
    }
}

/// Wait for a hardware interrupt to occur
pub fn await_interrupt() {
    unsafe {
        asm!("syscall",
             // RAX contains syscall
             in("rax") SYSCALL_AWAIT_INTERRUPT,
             out("rcx") _,
             out("r11") _);
    }
}

// Exec permission flags
pub const EXEC_PERM_IO: u8 = 1;

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
pub const SYSCALL_YIELD: u64 = 9;
pub const SYSCALL_NEW_RENDEZVOUS: u64 = 10;
pub const SYSCALL_COPY_RENDEZVOUS: u64 = 11;
pub const SYSCALL_EXEC: u64 = 12;
pub const SYSCALL_MOUNT: u64 = 13;
pub const SYSCALL_LISTMOUNTS: u64 = 14;
pub const SYSCALL_UMOUNT: u64 = 15;
pub const SYSCALL_CLOSE: u64 = 16;
pub const SYSCALL_AWAIT_INTERRUPT: u64 = 17;

// Syscall error codes
pub const SYSCALL_ERROR_MASK : usize = 127; // Lower 7 bits
pub const SYSCALL_ERROR_CONTAINS_MESSAGE: usize = 128;
pub const SYSCALL_ERROR_SEND_BLOCKING: SyscallError = SyscallError(1);
pub const SYSCALL_ERROR_RECV_BLOCKING: SyscallError = SyscallError(2);
pub const SYSCALL_ERROR_INVALID_HANDLE: SyscallError = SyscallError(3);
pub const SYSCALL_ERROR_MEMALLOC: SyscallError = SyscallError(4); // Memory allocation error
pub const SYSCALL_ERROR_PARAM: SyscallError = SyscallError(5); // Invalid parameter
pub const SYSCALL_ERROR_UTF8: SyscallError = SyscallError(6); // UTF8 conversion error
pub const SYSCALL_ERROR_NOTFOUND: SyscallError = SyscallError(7);
pub const SYSCALL_ERROR_THREAD: SyscallError = SyscallError(8);
pub const SYSCALL_ERROR_MEMORY: SyscallError = SyscallError(9);
pub const SYSCALL_ERROR_DOUBLEFREE: SyscallError = SyscallError(10);
pub const SYSCALL_ERROR_NOMEMSLOTS: SyscallError = SyscallError(11);
pub const SYSCALL_ERROR_CLOSED: SyscallError = SyscallError(12);
pub const SYSCALL_ERROR_EXISTS: SyscallError = SyscallError(13); // Already exists

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
                   SYSCALL_ERROR_THREAD => "Thread error",
                   SYSCALL_ERROR_MEMORY => "Memory error",
                   SYSCALL_ERROR_DOUBLEFREE => "Double free",
                   SYSCALL_ERROR_NOMEMSLOTS => "No memory slots",
                   SYSCALL_ERROR_CLOSED => "Rendezvous closed",
                   SYSCALL_ERROR_EXISTS => "Already exists",
                   _ => "Unknown error"
               })
    }
}

