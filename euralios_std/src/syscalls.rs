use core::arch::asm;

/// Spawn a new thread with a given entry point
///
/// # Returns
///
///  Ok(thread_id) or Err(error_code)
///
pub fn thread_spawn(func: extern "C" fn() -> ()) -> Result<u64, u64> {
    let mut tid: u64 = 0;
    let mut errcode: u64 = 0;
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
        return Err(errcode);
    }
    Ok(tid)
}

pub fn thread_exit() -> ! {
    unsafe {
        asm!("mov rax, 1", // exit_current_thread syscall
             "syscall");
    }
    loop{}
}

pub fn receive(handle: u64) -> Result<u64, u64> {
    let mut err: u64;
    let value: u64;
    unsafe {
        asm!("mov rax, 3", // sys_receive
             "syscall",
             in("rdi") handle,
             lateout("rax") err,
             lateout("rdi") value);
    }
    if err == 0 {
        return Ok(value);
    }
    Err(err)
}

pub fn send(handle: u64, value: u64) -> Result<(), u64> {
    let err: u64;
    unsafe {
        asm!("mov rax, 4", // sys_send
             "syscall",
             in("rdi") handle,
             in("rsi") value,
             lateout("rax") err);
    }
    if err == 0 {
        return Ok(());
    }
    Err(err)
}
