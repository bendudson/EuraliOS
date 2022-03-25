///
/// Handle processes
///

use x86_64::VirtAddr;
use x86_64::instructions::interrupts;
use spin::RwLock;
use lazy_static::lazy_static;
extern crate alloc;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, vec::Vec};

use core::arch::asm;

use crate::println;
use crate::interrupts::{Context, INTERRUPT_CONTEXT_SIZE};

use crate::gdt;

/// Size of the kernel stack for each process, in bytes
const KERNEL_STACK_SIZE: usize = 4096 * 2;

/// Size of the user stack for each user process, in bytes
const USER_STACK_SIZE: usize = 4096 * 5;

lazy_static! {
    /// Queue of processes which can run
    ///
    /// Notes:
    ///  - Process structure must not be moved
    ///  - Processes are added to the back of the queue with push_back
    ///  - The next process to run is removed from the front with pop_front
    static ref RUNNING_QUEUE: RwLock<VecDeque<Box<Process>>> =
        RwLock::new(VecDeque::new());

    /// The process which is currently running
    static ref CURRENT_PROCESS: RwLock<Option<Box<Process>>> = RwLock::new(None);
}

/// Per-process state
///
///
/// https://samwho.dev/blog/context-switching-on-x86/
///
/// Notes:
///  - Box::new(Process { .. }) first constructs a new Process
///    on the stack, then moves it onto the heap. Fixed sized arrays
///    therefore can't be used for the new process' stack because they
///    overflow the current stack.
struct Process {
    /// Process ID
    pid: usize,

    /// Kernel stack needed to handle system calls
    /// and interrupts including
    /// save/restore process state in context switch
    kernel_stack: Vec<u8>,

    /// Address of the end of the stack.
    /// This value is put in the Interrupt Stack Table
    kernel_stack_end: u64,

    /// Address within the kernel_stack which stores
    /// the Context structure containing thread state.
    context: u64,

    /// User stack. Note that kernel threads also
    /// use this stack
    user_stack: Vec<u8>
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
    //
    // Note this is first created on the stack, then moved into a Box
    // on the heap.
    let mut new_process = Box::new(Process {
        pid: 0,
        kernel_stack: Vec::with_capacity(KERNEL_STACK_SIZE),
        kernel_stack_end: 0,
        context: 0,
        user_stack: Vec::with_capacity(USER_STACK_SIZE)
    });

    // Get a pointer to the context for the new process
    // Note that stacks move backwards, so SP points to the end
    new_process.kernel_stack_end = {
        let kernel_stack_start = VirtAddr::from_ptr(new_process.kernel_stack.as_ptr());
        (kernel_stack_start + KERNEL_STACK_SIZE).as_u64()
    };

    // Push a Context struct on the stack
    new_process.context = new_process.kernel_stack_end - INTERRUPT_CONTEXT_SIZE as u64;

    // Cast context address to Context struct
    let context = unsafe {&mut *(new_process.context as *mut Context)};

    // Set the instruction pointer
    context.rip = function as usize;

    // Set flags
    unsafe {
        asm!{
            "pushf",
            "pop rax", // Get RFLAGS in RAX
            lateout("rax") context.rflags,
        }
    }

    context.cs = 8; // Code segment flags

    // The kernel thread has its own stack
    // Note: Need to point to the end of the memory region
    //       because the stack moves down in memory
    context.rsp = (VirtAddr::from_ptr(new_process.user_stack.as_ptr()) + USER_STACK_SIZE).as_u64() as usize;

    let pid = new_process.pid;

    println!("New process PID: {:#016X}, rip: {:#016X}", pid, context.rip);
    println!("   Kernel stack: {:#016X} - {:#016X} Context: {:#016X}",
             VirtAddr::from_ptr(new_process.kernel_stack.as_ptr()).as_u64(),
             (VirtAddr::from_ptr(new_process.kernel_stack.as_ptr()) + KERNEL_STACK_SIZE).as_u64(),
             new_process.context);
    println!("   Thread stack: {:#016X} - {:#016X} RSP: {:#016X}",
             VirtAddr::from_ptr(new_process.user_stack.as_ptr()).as_u64(),
             (VirtAddr::from_ptr(new_process.user_stack.as_ptr()) + USER_STACK_SIZE).as_u64(),
             context.rsp);

    // Turn off interrupts while modifying process table
    interrupts::without_interrupts(|| {
        RUNNING_QUEUE.write().push_back(new_process);
    });
    pid
}

/// This is called by the timer interrupt handler
///
/// Returns the stack containing the process state
/// (interrupts::Context struct)
pub fn schedule_next(context: &Context) -> usize {

    let mut running_queue = RUNNING_QUEUE.write();
    let mut current_process = CURRENT_PROCESS.write();

    if let Some(process) = current_process.take() {
        // Put the current process to the back of the queue

        // Update the stack pointer
        let mut proc_mut = process;

        // Store context location. This should almost always be in the same
        // location on the kernel stack. The exception is the
        // first time a context switch occurs from the original kernel
        // stack to the first kernel thread stack.
        proc_mut.context = (context as *const Context) as u64;

        running_queue.push_back(proc_mut);
    }
    *current_process = running_queue.pop_front();

    match current_process.as_ref() {
        Some(process) => {
            // Set the kernel stack for the next interrupt
            gdt::set_interrupt_stack_table(
                gdt::TIMER_INTERRUPT_INDEX as usize,
                // Note: Point to the end of the stack
                VirtAddr::new(process.kernel_stack_end));
            // Point the stack to the new context
            // (which is usually stored on the kernel stack)
            process.context as usize
        },
        None => 0
    }
}
