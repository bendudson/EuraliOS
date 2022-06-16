//! Entry point for syscalls
//!
//! Initialise syscalls, entry point and syscall handlers
//!
//! Syscalls
//! --------
//!
//! syscall function selector in RAX
//!
//! 0   fork_current_thread() -> (RAX: errcode, RDI: thread_id)
//! 1   exit_current_thread() -> !   (does not return)
//! 2   write(RDI: *const u8, RSI: usize) -> ()
//! 3   receive
//! 4   send
//! 5   sendreceive
//! 6   open(RDI: *const u8, RSI: usize) -> RAX: errcode, RDI: handle
//!
//! Potential future syscalls
//! -------------------------
//!
//! - launch_process(..)         Start a new process
//!
//! - wait(time)                 Stop thread for set time
//! - yield() -> ()              Thread yields control
//! - thread_kill(u64) -> bool   Kill the specified thread. Must be in the same process.
//! - unique_id() -> u64         Return a unique number
//!
//! - mount(str, handle)         Attach a process to a vfs node
//! - open(str) -> handle        Open a vfs node
//!
//! - send_receive(handle, message)  Ensure reply from same thread

// Syscall numbers
pub const SYSCALL_MASK: u64 = 0xFF;
pub const SYSCALL_FORK_THREAD: usize = 0;
pub const SYSCALL_EXIT_THREAD: usize = 1;
pub const SYSCALL_DEBUG_WRITE: usize = 2;
pub const SYSCALL_RECEIVE: usize = 3;
pub const SYSCALL_SEND: usize = 4;
pub const SYSCALL_SENDRECEIVE: usize = 5;
pub const SYSCALL_OPEN: usize = 6;

// Syscall error codes
pub const SYSCALL_ERROR_SEND_BLOCKING: usize = 1;
pub const SYSCALL_ERROR_RECV_BLOCKING: usize = 2;
pub const SYSCALL_ERROR_INVALID_HANDLE: usize = 3;
pub const SYSCALL_ERROR_MEMALLOC: usize = 4; // Memory allocation error
pub const SYSCALL_ERROR_PARAM: usize = 5; // Invalid parameter
pub const SYSCALL_ERROR_UTF8: usize = 6; // UTF8 conversion error
pub const SYSCALL_ERROR_NOTFOUND: usize = 7;

// Syscall message control bits
pub const MESSAGE_LONG: u64 = 2 << 8;
pub const MESSAGE_DATA2_RDV: u64 = 2 << 9;
const MESSAGE_DATA2_TYPE: u64 = MESSAGE_DATA2_RDV; // Bit mask
const MESSAGE_DATA2_MOVE: u64 = 2 << 10;

pub const MESSAGE_DATA3_RDV: u64 = 2 << 11;
const MESSAGE_DATA3_TYPE: u64 = MESSAGE_DATA3_RDV; // Bit mask
const MESSAGE_DATA3_MOVE: u64 = 2 << 12;

use crate::{print, println};
use core::arch::asm;
use core::{slice, str};

use crate::process;
use crate::gdt;
use crate::interrupts::{self, Context};
use crate::rendezvous::{Message, MessageData};

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
/// https://nfil.dev/kernel/rust/coding/rust-kernel-to-userspace-and-back/
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
        // the TSS is here: https://wiki.osdev.org/Task_State_Segment
        // The first IST slot is at an offset of 0x24 and there are 7
        // available.
        asm!(
            // Want to move RDX into MSR but wrmsr takes EDX:EAX i.e. EDX
            // goes to high 32 bits of MSR, and EAX goes to low order bits
            // https://www.felixcloutier.com/x86/wrmsr
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
            // Here should switch stack to avoid messing with user stack
            // swapgs seems to be a way to do this
            // - https://github.com/redox-os/kernel/blob/master/src/arch/x86_64/interrupt/syscall.rs#L65
            // - https://www.felixcloutier.com/x86/swapgs

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
        0 => process::fork_current_thread(context),
        1 => process::exit_current_thread(context),
        2 => sys_write(arg1 as *const u8, arg2 as usize),
        3 => sys_receive(context_ptr, arg1),
        4 => sys_send(context_ptr, syscall_id, arg1, arg2, arg3),
        5 => sys_send(context_ptr, syscall_id, arg1, arg2, arg3), // sys_sendreceive
        6 => sys_open(context_ptr, arg1 as *const u8, arg2 as usize),
        _ => println!("Unknown syscall {:?} {} {} {}",
                      context_ptr, syscall_id, arg1, arg2)
    }
}

fn sys_write(ptr: *const u8, len:usize) {
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


fn format_message(
    thread: &mut process::Thread,
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
            if syscall_id & MESSAGE_DATA2_TYPE == MESSAGE_DATA2_RDV {
                // Moving or copying a handle
                // First copy, then drop if message is valid
                if let Some(rdv) = thread.rendezvous(data2) {
                    MessageData::Rendezvous(rdv)
                } else {
                    // Invalid handle
                    return Err(SYSCALL_ERROR_INVALID_HANDLE);
                }
            } else {
                MessageData::Value(data2)
            },
            if syscall_id & MESSAGE_DATA3_TYPE == MESSAGE_DATA3_RDV {
                if let Some(rdv) = thread.rendezvous(data3) {
                    MessageData::Rendezvous(rdv)
                } else {
                    // Invalid handle.
                    // If we moved data2 we would have to put it back here
                    return Err(SYSCALL_ERROR_INVALID_HANDLE);
                }
            } else {
                MessageData::Value(data3)
            });
        // Message is valid => Remove handles being moved
        if (syscall_id & MESSAGE_DATA2_TYPE == MESSAGE_DATA2_RDV) &&
            (syscall_id & MESSAGE_DATA2_MOVE != 0) {
                let _ = thread.take_rendezvous(data2);
            }
        if (syscall_id & MESSAGE_DATA3_TYPE == MESSAGE_DATA3_RDV) &&
            (syscall_id & MESSAGE_DATA3_MOVE != 0) {
                let _ = thread.take_rendezvous(data3);
            }
        Ok(message)
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
            match format_message(&mut thread, syscall_id, data1, data2, data3) {
                Ok(message) => {
                    let (thread1, thread2) = match (syscall_id & SYSCALL_MASK) as usize {
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
            Ok(handle) => {
                context.rax = 0; // No error
                context.rdi = handle; // Return handle
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
