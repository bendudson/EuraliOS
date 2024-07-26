//! Entry point for syscalls
//!
//! Initialise syscalls, entry point and syscall handlers
//!
//! Syscalls
//! --------
//!
//! syscall function selector in AL (first 8 bits of RAX)
//!
//!  0   fork_current_thread() -> (RAX: errcode, RDI: thread_id)
//!  1   exit_current_thread() -> !   (does not return)
//!  2   debug_write(RDI: *const u8, RSI: usize) -> ()
//!         Used to print to console for development/debugging
//!  3   receive
//!  4   send
//!  5   sendreceive
//!         Ensures a reply from the receiving thread
//!  6   open(RDI: *const u8, RSI: usize) -> RAX: errcode, RDI: handle
//!         Opens a VFS handle for read/write
//!  7   malloc(num_pages, max_physaddr)
//!  8   free(mem_handle)
//!  9   yield()
//! 10   new_rendezvous() -> (handle, handle)
//! 11   copy_rendezvous(handle) -> handle
//! 12   exec(RAX: flags, RDI: ELF, RSI: stdin/stdout, RDX: vfs)
//! 13   mount(RAX: handle, RDI: *const u8, RSI: length)
//! 14   listmounts() -> memory_handle
//! 15   umount(RDI: *const u8, RSI: length)
//! 16   close(RDI: handle)  Drop a Rendezvous
//! 17   await_interrupt(RDI: number)  Wait for an interrupt
//!
//! Potential future syscalls
//! -------------------------
//!
//! - wait(time)                 Stop thread for set time
//! - thread_kill(u64) -> bool   Kill the specified thread. Must be in the same process.
//! - unique_id() -> u64         Return a unique number
//! - pledge()                   Remove permissions (https://man.openbsd.org/pledge)
//!

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
pub const SYSCALL_ERROR_SEND_BLOCKING: usize = 1;
pub const SYSCALL_ERROR_RECV_BLOCKING: usize = 2;
pub const SYSCALL_ERROR_INVALID_HANDLE: usize = 3;
pub const SYSCALL_ERROR_MEMALLOC: usize = 4; // Memory allocation error
pub const SYSCALL_ERROR_PARAM: usize = 5; // Invalid parameter
pub const SYSCALL_ERROR_UTF8: usize = 6; // UTF8 conversion error
pub const SYSCALL_ERROR_NOTFOUND: usize = 7;
pub const SYSCALL_ERROR_THREAD: usize = 8;
pub const SYSCALL_ERROR_MEMORY: usize = 9;
pub const SYSCALL_ERROR_DOUBLEFREE: usize = 10;
pub const SYSCALL_ERROR_NOMEMSLOTS: usize = 11; // No memory chunk slots
pub const SYSCALL_ERROR_CLOSED: usize = 12; // Rendezvous closed

// Exec permission flags
pub const EXEC_PERM_IO: u64 = 1;

use crate::{print, println};
use core::arch::asm;
use core::{slice, str, ptr};
use core::mem::drop;
extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;

use x86_64::VirtAddr;

use crate::process;
use crate::gdt;
use crate::vfs;
use crate::interrupts::{self, Context};
use crate::message::Message;

// register for address of syscall handler
const MSR_STAR: usize = 0xc0000081;
const MSR_LSTAR: usize = 0xc0000082;
const MSR_FMASK: usize = 0xc0000084;

/// Register to store the kernel GS 64-bit address
const MSR_KERNEL_GS_BASE: usize = 0xC0000102;

/// Subtract this offset from the kernel stack
/// stored in the TSS interrupt table.
/// This is to enable syscalls to be interrupted.
const SYSCALL_KERNEL_STACK_OFFSET: u64 = 1024;

/// Set up syscall handler
///
/// Note: This depends on the order of the GDT table
///
/// <https://nfil.dev/kernel/rust/coding/rust-kernel-to-userspace-and-back/>
pub fn init() {
    let handler_addr = handle_syscall as *const () as u64;
    unsafe {
        // Enable System Call Extensions (SCE) to be able to use the
        // syscall/sysret opcodes by setting the last bit in the MSR
        // IA32_EFER
        asm!("mov ecx, 0xC0000080",
             "rdmsr",
             "or eax, 1",
             "wrmsr");

        // clear Trap and Interrupt flag on syscall with AMD's
        // MSR_FMASK register
        asm!("xor rdx, rdx",
             "mov rax, 0x300",
             "wrmsr",
             in("rcx") MSR_FMASK);

        // write handler address to AMD's MSR_LSTAR register
        asm!("mov rdx, rax",
             "shr rdx, 32",
             "wrmsr",
             in("rax") handler_addr,
             in("rcx") MSR_LSTAR);

        // write segments to use on syscall/sysret to AMD'S MSR_STAR register
        asm!(
            "xor rax, rax",
            "mov rdx, 0x230008", // use seg selectors 8, 16 for syscall and 43, 51 for sysret
            "wrmsr",
            in("rcx") MSR_STAR);

        // Write TSS address into kernel GS MSR
        //
        // On a syscall SWAPGS will put this into GS. The layout of
        // the TSS is here: <https://wiki.osdev.org/Task_State_Segment>
        // The first IST slot is at an offset of 0x24 and there are 7
        // available.
        asm!(
            // Want to move RDX into MSR but wrmsr takes EDX:EAX i.e. EDX
            // goes to high 32 bits of MSR, and EAX goes to low order bits
            // <https://www.felixcloutier.com/x86/wrmsr>
            "mov eax, edx",
            "shr rdx, 32", // Shift high bits into EDX
            "wrmsr",
            in("rcx") MSR_KERNEL_GS_BASE,
            in("rdx") gdt::tss_address()
        );
    }
}

/// Syscall entry point
///
/// This sets up the environment and then calls rust code
/// to perform the actual work.
///
/// Notes:
///  - RBX, RSP, RBP, and R12–R15 should be saved
///  - Caller's RIP is in RCX
///  - Caller's RFLAGS is in R11
///
#[naked]
extern "C" fn handle_syscall() {
    unsafe {
        asm!(
            // Here we switch stack to avoid messing with user stack
            // swapgs is a way to do this
            // - <https://github.com/redox-os/kernel/blob/master/src/arch/x86_64/interrupt/syscall.rs#L65>
            // - <https://www.felixcloutier.com/x86/swapgs>

            "swapgs", // Put the TSS address into GS (stored in syscalls::init)
            "mov gs:{tss_temp}, rsp", // Save user stack pointer in TSS entry

            "mov rsp, gs:{tss_timer}", // Get kernel stack pointer
            "sub rsp, {ks_offset}", // Use a different location than timer interrupt

            // Create an Exception stack frame
            "sub rsp, 8", // To be replaced with SS
            "push gs:{tss_temp}", // User stack pointer
            "swapgs", // Put TSS address back

            // Could re-enable interrupts here?

            "push r11", // Caller's RFLAGS
            "sub rsp, 8",  // CS
            "push rcx", // Caller's RIP

            // Create the remainder of the Context struct
            "push rax",
            "push rbx",
            "push rcx",
            "push rdx",

            "push rdi",
            "push rsi",
            "push rbp",
            "push r8",

            "push r9",
            "push r10",
            "push r11",
            "push r12",

            "push r13",
            "push r14",
            "push r15",

            // Call the rust dispatch_syscall function
            // C calling convention so arguments are in registers
            // RDI, RSI, RDX, RCX, R8, R9
            "mov r8, rdx", // Fifth argument <- Syscall third argument
            "mov rcx, rsi", // Fourth argument <- Syscall second argument
            "mov rdx, rdi", // Third argument <- Syscall first argument
            "mov rsi, rax", // Second argument is the syscall number
            "mov rdi, rsp", // First argument is the Context address
            "call {dispatch_fn}",

            "pop r15", // restore callee-saved registers
            "pop r14",
            "pop r13",

            "pop r12",
            "pop r11",
            "pop r10",
            "pop r9",

            "pop r8",
            "pop rbp",
            "pop rsi",
            "pop rdi",

            "pop rdx",
            "pop rcx",
            "pop rbx",
            "pop rax",

            "add rsp, 24", // Skip RIP, CS and RFLAGS
            "pop rsp", // Restore user stack
            // No need to pop SS

            "cmp rcx, {user_code_start}",
            "jl 2f", // rip < USER_CODE_START
            "cmp rcx, {user_code_end}",
            "jge 2f", // rip >= USER_CODE_END
            "sysretq", // back to userland

            "2:", // kernel code return
            "push r11",
            "popf", // Set RFLAGS
            "jmp rcx",
            dispatch_fn = sym dispatch_syscall,
            tss_timer = const(0x24 + gdt::TIMER_INTERRUPT_INDEX * 8),
            tss_temp = const(0x24 + gdt::SYSCALL_TEMP_INDEX * 8),
            ks_offset = const(SYSCALL_KERNEL_STACK_OFFSET),
            user_code_start = const(process::USER_CODE_START),
            user_code_end = const(process::USER_CODE_END),
            options(noreturn));
    }
}

extern "C" fn dispatch_syscall(context_ptr: *mut Context, syscall_id: u64,
                               arg1: u64, arg2: u64, arg3: u64) {

    let context = unsafe{&mut *context_ptr};

    // Set the CS and SS segment selectors
    let (code_selector, data_selector) =
        if context.rip < process::USER_CODE_START as usize {
            // Called from kernel code
            gdt::get_kernel_segments()
        } else {
            gdt::get_user_segments()
        };
    context.cs = code_selector.0 as usize;
    context.ss = data_selector.0 as usize;

    match syscall_id & SYSCALL_MASK {
        SYSCALL_FORK_THREAD => process::fork_current_thread(context),
        SYSCALL_EXIT_THREAD => process::exit_current_thread(context),
        SYSCALL_DEBUG_WRITE => sys_debug_write(arg1 as *const u8, arg2 as usize),
        SYSCALL_RECEIVE => sys_receive(context_ptr, arg1),
        SYSCALL_SEND => sys_send(context_ptr, syscall_id, arg1, arg2, arg3),
        SYSCALL_SENDRECEIVE => sys_send(context_ptr, syscall_id, arg1, arg2, arg3), // sys_sendreceive
        SYSCALL_OPEN => sys_open(context_ptr, arg1 as *const u8, arg2 as usize),
        SYSCALL_MALLOC => sys_malloc(context_ptr, arg1, arg2),
        SYSCALL_FREE => sys_free(context_ptr, arg1),
        SYSCALL_YIELD => sys_yield(context_ptr),
        SYSCALL_NEW_RENDEZVOUS => sys_new_rendezvous(context_ptr),
        SYSCALL_COPY_RENDEZVOUS => sys_copy_rendezvous(context_ptr, arg1),
        SYSCALL_EXEC => sys_exec(context_ptr, syscall_id, arg1 as *const u8, arg2, arg3 as *const u8),
        SYSCALL_MOUNT => sys_mount(context_ptr, syscall_id, arg1 as *const u8, arg2),
        SYSCALL_LISTMOUNTS => sys_listmounts(context_ptr),
        SYSCALL_UMOUNT => sys_umount(context_ptr, arg1 as *const u8, arg2),
        SYSCALL_CLOSE => sys_close(context_ptr, arg1),
        SYSCALL_AWAIT_INTERRUPT => sys_await_interrupt(context_ptr, arg1),
        _ => println!("Unknown syscall {:?} {} {} {}",
                      context_ptr, syscall_id, arg1, arg2)
    }
}

fn sys_debug_write(ptr: *const u8, len:usize) {
    // Check all inputs: Does ptr -> ptr+len lie entirely in user address space?
    if len == 0 {
        return;
    }
    // Convert raw pointer to a slice
    let u8_slice = unsafe {slice::from_raw_parts(ptr, len)};

    if let Ok(s) = str::from_utf8(u8_slice) {
        print!("{}", s);
    } // else error
}


fn sys_receive(context_ptr: *mut Context, handle: u64) {
    // Extract the current thread
    if let Some(mut thread) = process::take_current_thread() {
        let current_tid = thread.tid();
        thread.set_context(context_ptr);

        // Get the Rendezvous and call
        if let Some(rdv) = thread.rendezvous(handle) {
            let (thread1, thread2) = rdv.write().receive(thread);
            // thread1 should be started asap
            // thread2 should be scheduled

            let mut returning = false;
            for maybe_thread in [thread2, thread1] {
                if let Some(t) = maybe_thread {
                    if t.tid() == current_tid {
                        // Same thread -> return
                        process::set_current_thread(t);
                        returning = true;
                    } else {
                        process::schedule_thread(t);
                    }
                }
            }

            if !returning {
                // Original thread is waiting.
                // Switch to a different thread
                drop(rdv); // Not returning from launch_thread
                let new_context_addr = process::schedule_next(context_ptr as usize);
                interrupts::launch_thread(new_context_addr);
            }
        } else {
            // Missing handle
            thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
            process::set_current_thread(thread);
        }
    }
}

/// This handles both syscall_send and syscall_sendreceive
fn sys_send(
    context_ptr: *mut Context,
    syscall_id: u64,
    data1: u64,
    data2: u64,
    data3: u64) {
    let handle = syscall_id >> 32; // High 32 bits are the handle
    // Extract the current thread
    if let Some(mut thread) = process::take_current_thread() {
        let current_tid = thread.tid();
        thread.set_context(context_ptr);

        // Get the Rendezvous, create Message and call
        if let Some(rdv) = thread.rendezvous(handle) {
            // Check how many references this Rendezvous has.
            if Arc::strong_count(&rdv) == 2 {
                // Only this handle (rdv) and the one stored in the Thread/Process
                // All other handles have been dropped -> Return error
                thread.return_error(SYSCALL_ERROR_CLOSED);
                process::set_current_thread(thread);
                return;
            }

            match Message::from_values(&mut thread, syscall_id, data1, data2, data3) {
                Ok(message) => {
                    let (thread1, thread2) = match syscall_id & SYSCALL_MASK {
                        SYSCALL_SEND => rdv.write().send(
                            Some(thread),
                            message),
                        SYSCALL_SENDRECEIVE => rdv.write().send_receive(
                            thread,
                            message),
                        _ => panic!("Internal error")
                    };
                    // thread1 should be started asap
                    // thread2 should be scheduled

                    let mut returning = false;
                    for maybe_thread in [thread2, thread1] {
                        if let Some(t) = maybe_thread {
                            if t.tid() == current_tid {
                                // Same thread -> return
                                returning = true;
                                process::set_current_thread(t);
                            } else {
                                process::schedule_thread(t);
                            }
                        }
                    }

                    if !returning {
                        // Original thread is waiting.
                        // Switch to a different thread
                        drop(rdv); // Not returning from launch_thread
                        let new_context_addr = process::schedule_next(context_ptr as usize);
                        interrupts::launch_thread(new_context_addr);
                    }
                }
                Err(error_code) => {
                    // Message could not be created
                    thread.return_error(error_code);
                    process::set_current_thread(thread);
                }
            }
        } else {
            // Missing handle
            thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
            process::set_current_thread(thread);
        }
    }
}

fn sys_open(
    context_ptr: *mut Context,
    ptr: *const u8,
    len: usize) {

    let context = unsafe {&mut (*context_ptr)};

    // Check input length
    if len == 0 {
        context.rax = SYSCALL_ERROR_PARAM;
        return;
    }
    // Convert raw pointer to a slice
    let u8_slice = unsafe {slice::from_raw_parts(ptr, len)};

    if let Ok(path_string) = str::from_utf8(u8_slice) {
        match process::open_path(context, &path_string) {
            Ok((handle, match_len)) => {
                context.rax = 0; // No error
                context.rdi = handle; // Return handle
                context.rsi = match_len; // Path match length
            }
            Err(error_code) => {
                context.rax = error_code;
            }
        }
    } else {
        // Bad utf8 conversion
        context.rax = SYSCALL_ERROR_UTF8;
    }
}

/// Allocates a chunk of memory
///
/// Returns
///  - handle in RDI
///  - starting virtual address in RSI
///  - starting physical address in RDX
fn sys_malloc(
    context_ptr: *mut Context,
    num_pages: u64,
    max_physaddr: u64
) {
    let context = unsafe {&mut (*context_ptr)};

    match process::new_memory_chunk(
        num_pages,
        max_physaddr) {
        Ok((virtaddr, physaddr)) => {
            context.rax = 0; // No error
            context.rdi = virtaddr.as_u64() as usize;
            context.rsi = physaddr.as_u64() as usize;
        }
        Err(code) => {
            context.rax = code;
            context.rdi = 0;
            context.rsi = 0;
            context.rdx = 0;
        }
    }
}

/// Free a memory chunk containing the given virtual address
fn sys_free(
    context_ptr: *mut Context,
    virtaddr: u64
) {
    let context = unsafe {&mut (*context_ptr)};

    match process::free_memory_chunk(VirtAddr::new(virtaddr)) {
        Ok(()) => {
            context.rax = 0; // No error
        }
        Err(code) => {
            context.rax = code;
        }
    }
}

/// Yield to another process
fn sys_yield(context_ptr: *mut Context) {
    let next_stack = process::schedule_next(context_ptr as usize);
    interrupts::launch_thread(next_stack);
}

/// Create a new pair of Rendezvous handles
fn sys_new_rendezvous(context_ptr: *mut Context) {
    let context = unsafe {&mut (*context_ptr)};

    match process::new_rendezvous() {
        Ok((handle1, handle2)) => {
            context.rax = 0; // Success!
            context.rdi = handle1;
            context.rsi = handle2;
        }
        Err(code) => {
            context.rax = code;
        }
    }
}

/// Make a copy of a Rendezvous
///
/// Takes handle as first argument (syscall RDI)
/// Returns new handle in RDI
fn sys_copy_rendezvous(context_ptr: *mut Context, handle: u64) {
    let context = unsafe {&mut (*context_ptr)};

    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);

        // Thread::rendezvous() returns a clone
        if let Some(rdv) = thread.rendezvous(handle) {
            let new_handle = thread.give_rendezvous(rdv);
            // Return
            context.rax = 0; // Success!
            context.rdi = new_handle;
        } else {
            // Missing handle
            thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
        }
        process::set_current_thread(thread);
    }
}

/// Create a new process
///
/// # Input
///
///  - Pointer to ELF binary data  (Arg1, syscall RDI)
///  - Length of ELF binary data (high 32 bits of syscall_id)
///  - STDIN & STDOUT rendezvous handles (Arg2, syscall RSI)
///  - Pointer to parameter string (Arg3, syscall RDX)
///  - Length of parameter string (16 bits of syscall_id)
///  - Flags controlling permissions (8 bits of syscall_id)
///    - I/O privileges: EXEC_PERM_IO
///    - Thread fork?
///    - Malloc?
///    - Exec?
///    - Interrupts
fn sys_exec(
    context_ptr: *mut Context,
    syscall_id: u64,
    bin: *const u8, // Binary data (ELF format)
    stdio: u64, // The stdin/stdout rendezvous handles
    param: *const u8) { // String specifying the process VFS, command-line arguments, and environment variales

    let context = unsafe {&mut (*context_ptr)};

    // Low 8 bits of syscall_id contain syscall number
    // Remaining 48 bits are used to store the length
    // of the bin and param parameters, and the
    // capability flags.
    let bin_length = syscall_id >> 32; // High 32 bits
    let param_length = (syscall_id >> 16) & 0xFFFF;
    let flags = (syscall_id >> 8) & 0xFF;

    // Handles
    let stdin_handle = (stdio >> 32) & 0xFFFF_FFFF; // High 32 bits
    let stdout_handle = stdio & 0xFFFF_FFFF; // Low 32 bits

    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);

        if bin_length == 0 {
            // No data
            thread.return_error(SYSCALL_ERROR_PARAM);
            process::set_current_thread(thread);
            return;
        }

        // Get the Rendezvous handles for stdin & stdout
        let stdin = if let Some(rdv) = thread.take_rendezvous(stdin_handle) {
            rdv
        } else {
            // Invalid handle
            thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
            process::set_current_thread(thread);
            return;
        };

        let stdout = if let Some(rdv) = thread.take_rendezvous(stdout_handle) {
            rdv
        } else {
            // Invalid handle
            thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
            process::set_current_thread(thread);
            return;
        };

        // Check I/O privileges. Caller must have I/O privileges
        let io_privileges = (flags & EXEC_PERM_IO == EXEC_PERM_IO) &&
            ((context.rflags & 0x3000) == 0x3000);

        // Get the arguments and VFS for this process

        let (mounts, args, envs) = if param_length == 0 {
            // Default is shared VFS and no arguments
            (thread.vfs(), Vec::<u8>::new(), Vec::<u8>::new())
        } else {
            let param_slice = unsafe{slice::from_raw_parts(param, param_length as usize)};
            let mut it = param_slice.iter();

            // Create a VFS, by default the same as parent
            let mut vfs = thread.vfs();
            let mut args = Vec::<u8>::new();
            let mut envs = Vec::<u8>::new();

            while let Some(ctrl) = it.next() {
                match ctrl {
                    // Command-line arguments. Terminated with a null character.
                    b'A' => {
                        args = it.by_ref()
                            .take_while(|x| **x != 0)
                            .cloned()
                            .collect();
                    }
                    // Environment
                    b'E' => {
                        envs = it.by_ref()
                            .take_while(|x| **x != 0)
                            .cloned()
                            .collect();
                    }
                    // These determine the VFS to start with
                    b'S' => {vfs = thread.vfs();}
                    b'C' => {vfs = thread.vfs().copy();}
                    b'N' => {vfs = vfs::VFS::new()}
                    // Further arguments add or remove paths
                    b'-' => {
                        // Remove a mount path, ending in ':'

                        let path_u8: Vec<u8> = it.by_ref()
                            .take_while(|x| **x != b':')
                            .cloned()
                            .collect();

                        if let Ok(path_string) = str::from_utf8(&path_u8) {
                            if let Err(_) = vfs.umount(path_string) {
                                // Could not remove
                                thread.return_error(SYSCALL_ERROR_PARAM);
                                process::set_current_thread(thread);
                                return;
                            }
                        } else {
                            // Bad utf8 conversion
                            thread.return_error(SYSCALL_ERROR_UTF8);
                            process::set_current_thread(thread);
                            return;
                        }
                    }
                    b'm' => {
                        // Mount a communication handle. Number (in ASCII) followed by delimiter then path
                        // e.g. "m12|/mountpoint"
                        let mut handle: u64 = 0;
                        while let Some(ch) = it.next() {
                            if (*ch >= b'0') && (*ch <= b'9') {
                                // Digit
                                handle = handle * 10 + (ch - b'0') as u64;
                            } else {
                                // delimiter
                                break;
                            }
                        }

                        // Get the rendezvous for this handle
                        let rdv = match thread.take_rendezvous(handle) {
                            Some(rdv) => rdv,
                            None => {
                                // Invalid handle
                                thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
                                process::set_current_thread(thread);
                                return;
                            }
                        };

                        // Get the path
                        let path_u8: Vec<u8> = it.by_ref()
                            .take_while(|x| **x != b':')
                            .cloned()
                            .collect();

                        let path_string = match str::from_utf8(&path_u8) {
                            Ok(s) => s,
                            Err(_) => {
                                // Bad utf8 conversion
                                thread.return_error(SYSCALL_ERROR_UTF8);
                                process::set_current_thread(thread);
                                return;
                            }
                        };

                        vfs.mount(path_string, rdv);
                    }
                    _ => {
                        thread.return_error(SYSCALL_ERROR_PARAM);
                        process::set_current_thread(thread);
                        return;
                    }
                }
            }
            (vfs, args, envs)
        };

        // Copy the ELF data. The data needs to be accessible
        // within the kernel page table, but the given pointer
        // is mapped in the calling user program's address space.
        // Options are:
        //   1. Create new mappings. This avoids copying but is
        //      more complicated.
        //   2. Copy the data into the kernel heap. This needs to
        //      ensure that there is enough memory available.

        // Assemble a slice pointing to user data
        let bin_slice = unsafe{slice::from_raw_parts(bin, bin_length as usize)};

        let mut bin_vec : Vec<u8> = Vec::new();
        // Reserve space
        if bin_vec.try_reserve_exact(bin_slice.len()).is_err() {
            // Could not allocate memory
            println!("[kernel] Couldn't allocate {} bytes for Exec from thread {}", bin_slice.len(), thread.tid());
            thread.return_error(SYSCALL_ERROR_MEMORY);
            process::set_current_thread(thread);
            return;
        }
        // Copy data into vector, which is now large enough
        bin_vec.extend(bin_slice.iter());

        match process::new_user_thread(
            // Binary ELF data, now stored in kernel heap
            bin_vec.as_slice(),
            // Parameters
            process::Params {
                handles: Vec::from([
                    stdin, stdout
                ]),
                io_privileges,
                mounts,
                args,
                envs
            }) {
            Ok(new_thread) => {
                let tid = new_thread.tid() as usize;
                process::schedule_thread(new_thread);
                context.rax = 0; // Success!
                context.rdi = tid; // Thread ID in rdi
            }
            Err(msg) => {
                println!("sys_exec error: {}", msg);
                thread.return_error(SYSCALL_ERROR_THREAD);
            }
        }
        process::set_current_thread(thread);
    }
}

fn sys_mount(
    context_ptr: *mut Context,
    syscall_id: u64,
    path_ptr: *const u8,
    path_len: u64) {

    let context = unsafe {&mut (*context_ptr)};

    // High 32 bits of RAX contain the handle
    let handle = syscall_id >> 32;

    // Convert raw pointer to a slice
    let u8_slice = unsafe {slice::from_raw_parts(path_ptr, path_len as usize)};
    let path_string = match str::from_utf8(u8_slice) {
        Ok(s) => s,
        Err(_) => {
            // Bad utf8 conversion
            context.rax = SYSCALL_ERROR_UTF8;
            return;
        }
    };
    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);
        let rdv = match thread.take_rendezvous(handle) {
            Some(rdv) => rdv,
            None => {
                // Invalid handle
                thread.return_error(SYSCALL_ERROR_INVALID_HANDLE);
                process::set_current_thread(thread);
                return;
            }
        };

        let mut vfs = thread.vfs(); // An Arc clone of the VFS
        vfs.mount(path_string, rdv);
        context.rax = 0; // No error (vfs.mount never fails. Probably should)
        process::set_current_thread(thread);
    }
}

/// Get a list of mounted paths in a memory handle
fn sys_listmounts(context_ptr: *mut Context) {
    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);
        let context = unsafe {&mut (*context_ptr)};

        // Get a JSON string containing VFS mounts
        let json = thread.vfs().to_json();

        // No longer need thread, needed
        // by process::new_memory_chunk
        process::set_current_thread(thread);

        // Allocate memory chunk to hold the data
        let num_bytes = json.len() as u64;
        let num_pages = (num_bytes >> 12) +
            if (num_bytes & 4095) != 0 {1} else {0};

        match process::new_memory_chunk(
            num_pages,
            0xFFFF_FFFF_FFFF_FFFF) {
            Ok((virtaddr, _physaddr)) => {
                // Copy string into memory chunk
                unsafe {
                    ptr::copy_nonoverlapping(json.as_ptr(),
                                             virtaddr.as_u64() as *mut u8,
                                             json.len());
                }

                context.rax = 0; // No error
                context.rdi = virtaddr.as_u64() as usize;
                context.rsi = json.len();
            }
            Err(code) => {
                context.rax = code;
                context.rdi = 0;
                context.rsi = 0;
            }
        }
    }
}

/// Remove a mount point.
/// Most of this code is the same as `sys_mount`
fn sys_umount(
    context_ptr: *mut Context,
    path_ptr: *const u8,
    path_len: u64) {

    let context = unsafe {&mut (*context_ptr)};

    // Convert raw pointer to a slice
    let u8_slice = unsafe {slice::from_raw_parts(path_ptr, path_len as usize)};
    let path_string = match str::from_utf8(u8_slice) {
        Ok(s) => s,
        Err(_) => {
            // Bad utf8 conversion
            context.rax = SYSCALL_ERROR_UTF8;
            return;
        }
    };
    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);

        let mut vfs = thread.vfs(); // An Arc clone of the VFS
        if vfs.umount(path_string).is_err() {
            context.rax = SYSCALL_ERROR_NOTFOUND;
        } else {
            context.rax = 0; // No error
        }
        process::set_current_thread(thread);
    }
}

fn sys_close(context_ptr: *mut Context, handle: u64) {
    // Extract the current thread
    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);

        // Take the Rendezvous from the thread
        if let Some(rdv) = thread.take_rendezvous(handle) {
            if Arc::strong_count(&rdv) == 2 {
                // Only this handle (rdv) and one other
                // All other handles have been dropped
                let option_thread = rdv.write().close();
                if let Some(waiting_thread) = option_thread {
                    // A thread was waiting -> Switch to it
                    process::schedule_thread(thread);
                    process::schedule_thread(waiting_thread);

                    drop(rdv); // Not returning from launch_thread
                    let new_context_addr = process::schedule_next(context_ptr as usize);
                    interrupts::launch_thread(new_context_addr);
                }
            }
            // Drop rendezvous
        }
        process::set_current_thread(thread);
    }
}

fn sys_await_interrupt(context_ptr: *mut Context, _interrupt_number: u64) {
    // Extract the current thread
    if let Some(mut thread) = process::take_current_thread() {
        thread.set_context(context_ptr);

        // Check if this thread has permission to wait for interrupts

        // Pass thread to interrupt handler
        interrupts::await_interrupt(thread);

        // Schedule another thread
        let new_context_addr = process::schedule_next(context_ptr as usize);
        interrupts::launch_thread(new_context_addr);
    }
}
