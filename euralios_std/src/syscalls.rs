use core::arch::asm;

/// Spawn a new thread with a given entry point
///
/// # Returns
///
///  Ok(thread_id) or Err(error_code)
///
pub fn thread_spawn(func: extern "C" fn() -> ()) -> Result<u64, u64> {
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
        return Err(errcode);
    }
    Ok(tid)
}

pub fn thread_exit() -> ! {
    unsafe {
        asm!("mov rax, 1", // exit_current_thread syscall
             "syscall",
             options(noreturn));
    }
}

pub enum Message {
    Short(u64, u64, u64),
    Long
}

pub fn receive(handle: u64) -> Result<Message, u64> {
    let mut err: u64;
    let (data1, data2, data3): (u64, u64, u64);
    unsafe {
        asm!("mov rax, 3", // sys_receive
             "syscall",
             in("rdi") handle,
             lateout("rax") err,
             lateout("rdi") data1,
             lateout("rsi") data2,
             lateout("rdx") data3,
             out("rcx") _,
             out("r11") _);
    }
    if err == 0 {
        return Ok(Message::Short(data1, data2, data3));
    }
    Err(err)
}

pub fn send(
    handle: u32,
    message: Message
) -> Result<(), u64> {
    match message {
        Message::Short(data1, data2, data3) => {
            let err: u64;
            unsafe {
                asm!("syscall",
                     in("rax") 4 + ((handle as u64) << 32),
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
            Err(err)
        },
        _ => return Err(0)
    }
}

// Standard message types
pub const MESSAGE_TYPE_CHAR: u64 = 0;
