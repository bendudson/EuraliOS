///
/// Handle processes
///

use x86_64::VirtAddr;
use x86_64::instructions::interrupts;
use spin::RwLock;
use lazy_static::lazy_static;
extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use crate::{print, println};

use crate::interrupts::{Context, INTERRUPT_CONTEXT_SIZE};

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

    /// Process ID
    pid: usize,

    // List of mounted namespaces

    /// Kernel stack needed to handle system calls
    /// and save/restore process state
    kernel_stack: [u8; KERNEL_STACK_SIZE],

    /// The current kernel stack pointer
    kernel_stack_ptr: u64,

    // User stack

    /// Registers in a Context structure
    /// This is stored on the kernel stack
    context: u64,
}

/// Start a new kernel thread, by adding it to the process table.
/// This won't run immediately, but will run when the scheduler
/// next switches to it.
///
/// Inputs
/// ------
///
/// function : fn() -> ()
///    The new thread entry point
///
/// Returns
/// -------
/// The PID of the new thread
///
pub fn new_kernel_thread(function: fn()->()) -> usize {
    // Create a new process table entry
    let mut new_process = Box::new(Process {
        kernel: true,
        state: State::Runnable,
        pid: 0, // This will be set once a slot has been found
        kernel_stack: [0; KERNEL_STACK_SIZE],
        kernel_stack_ptr: 0,
        context:0
    });

    // Get a pointer to the kernel stack for the new process
    // Note that stacks move backwards, so SP points to the end
    new_process.kernel_stack_ptr = {
        let kernel_stack_start = VirtAddr::from_ptr(&new_process.kernel_stack);
        let kernel_stack_end = kernel_stack_start + KERNEL_STACK_SIZE;
        // Push a Context struct on the stack
        (kernel_stack_end - INTERRUPT_CONTEXT_SIZE).as_u64()
    };

    // Address of the Context
    new_process.context = new_process.kernel_stack_ptr;

    // Cast kernel stack to Context struct
    let context = unsafe {&mut *(new_process.context as *mut Context)};

    // Set the instruction pointer
    context.rip = function as usize;

    // Turn off interrupts while modifying process table
    interrupts::without_interrupts(|| {
        let mut process_table = PROCESS_TABLE.write();

        // Find an empty slot in the process table
        let mut empty_slot: Option<usize> = None;
        for (id, proc) in process_table.iter().enumerate() {
            if proc.is_none() {
                // empty slot found
                empty_slot = Some(id);
                break;
            }
        }
        match empty_slot {
            Some(id) => {
                // Empty slot found, so use it
                new_process.pid = id;
                println!("New PID {}: IP 0x{:X} SP 0x{:X}", id, context.rip, new_process.kernel_stack_ptr);
                process_table[id] = Some(new_process);
                id // Return PID
            },
            None => {
                // No empty slot, so extend table
                let id = process_table.len();
                new_process.pid = id;
                println!("New PID {}: IP 0x{:X} SP 0x{:X}", id, context.rip, new_process.kernel_stack_ptr);
                process_table.push(Some(new_process));
                id // Return PID
            }
        }
    })
}

/// This is called by the timer interrupt handler
///
/// Returns the stack containing the process state
/// (interrupts::Context struct)
pub fn schedule_next() -> usize {
    print!(".");
    return 0;
}
