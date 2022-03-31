///
/// Handle processes
///

use x86_64::VirtAddr;
use x86_64::instructions::interrupts;
use x86_64::structures::paging::PageTableFlags;

use spin::RwLock;
use lazy_static::lazy_static;
extern crate alloc;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, vec::Vec};

use core::arch::asm;

use crate::println;
use crate::interrupts::{Context, INTERRUPT_CONTEXT_SIZE};

use crate::gdt;
use crate::memory;

use core::ptr;

use object::{Object, ObjectSegment};

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

use core::fmt;

/// Enable Process structs to be printed
impl fmt::Display for Process {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Cast context address to Context struct
        let context = unsafe {&mut *(self.context as *mut Context)};

        let kernel_stack_start = VirtAddr::from_ptr(self.kernel_stack.as_ptr()).as_u64();
        let user_stack_start = VirtAddr::from_ptr(self.user_stack.as_ptr()).as_u64();

        write!(f, "\
PID: {}, rip: {:#016X}
    Kernel stack: {:#016X} - {:#016X} Context: {:#016X}
    Thread stack: {:#016X} - {:#016X} RSP: {:#016X}",
               self.pid, context.rip,
               // Second line
               kernel_stack_start,
               kernel_stack_start + (KERNEL_STACK_SIZE as u64),
               self.context,
               // Third line
               user_stack_start,
               user_stack_start + (USER_STACK_SIZE as u64),
               context.rsp)
    }
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
    let mut new_process = {
        let kernel_stack = Vec::with_capacity(KERNEL_STACK_SIZE);
        let kernel_stack_start = VirtAddr::from_ptr(kernel_stack.as_ptr());
        let kernel_stack_end = (kernel_stack_start + KERNEL_STACK_SIZE).as_u64();

        Box::new(Process {
            pid: 0,
            kernel_stack,
            // Note that stacks move backwards, so SP points to the end
            kernel_stack_end,
            // Push a Context struct on the kernel stack
            context: kernel_stack_end - INTERRUPT_CONTEXT_SIZE as u64,
            user_stack: Vec::with_capacity(USER_STACK_SIZE)
        })
    };

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

    println!("New kernel thread {}", new_process);

    // Turn off interrupts while modifying process table
    interrupts::without_interrupts(|| {
        RUNNING_QUEUE.write().push_back(new_process);
    });
    pid
}

pub fn new_user_thread(bin: &[u8]) -> Result<usize, &'static str> {
    // Check the header
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

    if bin[0..4] != ELF_MAGIC {
        return Err("Expected ELF binary");
    }
    // Use the object crate to parse the ELF file
    // https://crates.io/crates/object
    if let Ok(obj) = object::File::parse(bin) {

        // Create a user pagetable
        let user_page_table_ptr = memory::create_user_pagetable();

        let entry_point = obj.entry();
        println!("Entry point: {:#016X}", entry_point);

        for segment in obj.segments() {
            let segment_address = segment.address() as u64;

            println!("Section {:?} : {:#016X}", segment.name(), segment_address);

            if let Ok(data) = segment.data() {
                println!("  len : {}", data.len());

                // Allocate memory in the pagetable
                memory::allocate_pages(user_page_table_ptr,
                                       VirtAddr::new(segment_address), // Start address
                                       data.len() as u64, // Size (bytes)
                                       PageTableFlags::PRESENT |
                                       PageTableFlags::WRITABLE |
                                       PageTableFlags::USER_ACCESSIBLE);

                // Copy data
                let dest_ptr = segment_address as *mut u8;
                for (i, value) in data.iter().enumerate() {
                    unsafe {
                        let ptr = dest_ptr.add(i);
                        core::ptr::write(ptr, *value);
                    }
                }
            } else {
                return Err("Could not get segment data");
            }
        }

        // Create the new Process struct
        let mut new_process = {
            let kernel_stack = Vec::with_capacity(KERNEL_STACK_SIZE);
            let kernel_stack_start = VirtAddr::from_ptr(kernel_stack.as_ptr());
            let kernel_stack_end = (kernel_stack_start + KERNEL_STACK_SIZE).as_u64();

            Box::new(Process {
                pid: 0,
                kernel_stack,
                // Note that stacks move backwards, so SP points to the end
                kernel_stack_end,
                // Push a Context struct on the kernel stack
                context: kernel_stack_end - INTERRUPT_CONTEXT_SIZE as u64,
                // User stack needs new pages, not allocated on the kernel heap
                user_stack: Vec::new()
            })
        };

        // Cast context address to Context struct
        let context = unsafe {&mut *(new_process.context as *mut Context)};

        context.rip = entry_point as usize;

        // Set flags
        unsafe {
            asm!{
                "pushf",
                "pop rax", // Get RFLAGS in RAX
                lateout("rax") context.rflags,
            }
        }

        let (code_selector, data_selector) = gdt::get_user_segments();
        context.cs = code_selector.0 as usize; // Code segment flags
        context.ss = data_selector.0 as usize; // Without this we get a GPF

        // Allocate pages for the user stack
        const USER_STACK_START: u64 = 0x5002000;

        memory::allocate_pages(user_page_table_ptr,
                               VirtAddr::new(USER_STACK_START), // Start address
                               USER_STACK_SIZE as u64, // Size (bytes)
                               PageTableFlags::PRESENT |
                               PageTableFlags::WRITABLE |
                               PageTableFlags::USER_ACCESSIBLE);

        // Note: Need to point to the end of the allocated region
        //       because the stack moves down in memory
        context.rsp = (USER_STACK_START as usize) + USER_STACK_SIZE;

        let pid = new_process.pid;

        println!("New Process {}", new_process);

        //Turn off interrupts while modifying process table
        interrupts::without_interrupts(|| {
            RUNNING_QUEUE.write().push_back(new_process);
        });
    } else {
        return Err("Could not parse ELF");
    }

    Ok(0)
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
