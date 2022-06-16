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

/// Exit the current thread. Never returns.
pub fn thread_exit() -> ! {
    unsafe {
        asm!("mov rax, 1", // exit_current_thread syscall
             "syscall",
             options(noreturn));
    }
}

#[derive(Debug)]
pub enum Message {
    Short(u64, u64, u64),
    Long
}

impl Message {
    fn to_values(&self)
                 -> Result<(u64, u64, u64, u64), u64> {
        match self {
            Message::Short(data1, data2, data3) => {
                Ok((0, *data1, *data2, *data3))
            },
            _ => Err(0)
        }
    }
    fn from_values(_ctrl: u64,
                   data1: u64, data2: u64, data3: u64)
                   -> Message {
        Message::Short(data1, data2, data3)
    }
}

/// Wait for a message to be received
pub fn receive(handle: u64) -> Result<Message, u64> {
    let ctrl: u64;
    let (data1, data2, data3): (u64, u64, u64);
    unsafe {
        asm!("mov rax, 3", // sys_receive
             "syscall",
             in("rdi") handle,
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
    Err(err)
}

/// Send a message and wait for it to be received
pub fn send(
    handle: u32,
    message: Message
) -> Result<(), u64> {

    let (ctrl, data1, data2, data3) = message.to_values()?;

    let err: u64;
    unsafe {
        asm!("syscall",
             in("rax") 4 | ctrl | ((handle as u64) << 32),
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
}

/// Send a message and wait for a message back from the same thread
pub fn send_receive(
    handle: u32,
    message: Message
) -> Result<Message, u64> {

    // Convert the message to register values
    let (ctrl, data1, data2, data3) = message.to_values()?;

    // Values to be received
    let err: u64;
    let (ret_ctrl, ret_data1, ret_data2, ret_data3): (u64, u64, u64, u64);
    unsafe {
        asm!("syscall",
             in("rax") 5 | ctrl | ((handle as u64) << 32),
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
    Err(err)
}

/// Returns a handle on success, or an error code
pub fn open(path: &str) -> Result<u32, u64> {
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
        Ok(handle)
    } else {
        Err(error)
    }
}

// Standard message types
pub const MESSAGE_TYPE_CHAR: u64 = 0;
