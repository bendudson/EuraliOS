///
/// Handle processes
///

use x86_64::VirtAddr;
use x86_64::instructions::interrupts;
use spin::{Mutex, RwLock};
use lazy_static::lazy_static;
extern crate alloc;
use alloc::{boxed::Box, vec, vec::Vec};
use crate::println;
use crate::gdt;

use core::arch::asm;

/// Size of the kernel stack for each process, in bytes
const KERNEL_STACK_SIZE: usize = 4096 * 2;

/// Size of the user stack for each user process, in bytes
const USER_STACK_SIZE: usize = 4096 * 5;

lazy_static! {
    /// Table of processes
    ///
    /// Index into the table is the PID
    ///
    /// Notes:
    ///  - Structure must not be moved
    ///  - This data structure may change
    ///
    static ref PROCESS_TABLE: RwLock<Vec<Option<Box<Process>>>> =
        RwLock::new(Vec::new());

    static ref CURRENT_PROCESS: RwLock<u16> = RwLock::new(0);
}

#[derive(Clone, Debug)]
enum State {
    Runnable,
    Sleeping // Could attach wake time
}

/// Per-process state
///
///
/// https://samwho.dev/blog/context-switching-on-x86/
#[derive(Clone, Debug)]
struct Process {
    kernel: bool, // Kernel process? False -> user
    state: State, // Is the process running?

    pid: u16, // Process ID

    // List of mounted namespaces

    // Kernel stack needed to handle system calls
    // and save/restore process state
    kernel_stack: [u8; KERNEL_STACK_SIZE],

    // User stack
}

/// Start a new kernel thread
///
/// Inputs
/// ------
///
/// function : fn() -> ()
///    The function to call
///
///
pub fn new_kernel_thread(function: fn()->()) {
    let process_table_len = interrupts::without_interrupts(|| {PROCESS_TABLE.read().len()});
    if process_table_len == 0 {
        // Empty process table. This should only happen once during initialisation
        let new_process = Box::new(Process {
            kernel: true,
            state: State::Runnable,
            pid: 0,
            kernel_stack: [0; KERNEL_STACK_SIZE]
        });
        println!("New PID: {}", new_process.pid);

        // Get a pointer to the start of the kernel stack
        let kernel_stack_start = VirtAddr::from_ptr(unsafe { &new_process.kernel_stack });
        let kernel_stack_end = kernel_stack_start + KERNEL_STACK_SIZE;

        // Note: Turn off interrupts while modifying process table
        interrupts::without_interrupts(|| {
            let mut process_table = PROCESS_TABLE.write();
            process_table.push(Some(new_process));
        });

        // Switch stack, push the current stack onto it, and call the function
        // Note that function may be on the old stack
        unsafe {
            asm!(
                "mov rdx, rsp",
                "mov rsp, rcx", // Switch to new stack
                "push rdx", // Save the old stack pointer on the new stack
                "call rax", // Call function
                // Returned -> process ended
                "pop rsp",  // Restore the old stack pointer
                in("rcx") kernel_stack_end.as_u64(),  // New stack pointer
                in("rax") function); // Make sure that the function address is in register
        }

        // Remove process from table
        // Note that we don't want an interrupt to occur and the handler try to
        // read the process table while we're modifying it
        interrupts::without_interrupts(|| {
            let mut process_table = PROCESS_TABLE.write();
            process_table[0] = None;
        });
    }
}
