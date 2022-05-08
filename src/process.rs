//! Handle processes
//!
//! Create processes, and determine which one to run next
//!

use x86_64::VirtAddr;
use x86_64::instructions::interrupts;
use x86_64::structures::paging::PageTableFlags;

use spin::RwLock;
use lazy_static::lazy_static;
extern crate alloc;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, vec::Vec, sync::Arc};

use core::arch::asm;

use crate::println;
use crate::interrupts::{Context, INTERRUPT_CONTEXT_SIZE};

use crate::gdt;
use crate::memory;
use crate::syscalls;

use object::{Object, ObjectSegment};

/// Size of the kernel stack for each process, in bytes
const KERNEL_STACK_SIZE: usize = 4096 * 2;

/// Size of the user stack for each user process, in bytes
const USER_STACK_SIZE: usize = 4096 * 5;

/// Lowest address that user code can be loaded into
const USER_CODE_START: u64 = 0x5000000;
/// Exclusive upper limit for user code
const USER_CODE_END: u64 = 0x80000000;

lazy_static! {
    /// Queue of processes which can run
    ///
    /// Notes:
    ///  - Threads are added to the back of the queue with push_back
    ///  - The next thread to run is removed from the front with pop_front
    static ref RUNNING_QUEUE: RwLock<VecDeque<Box<Thread>>> =
        RwLock::new(VecDeque::new());

    /// The process which is currently running
    static ref CURRENT_THREAD: RwLock<Option<Box<Thread>>> = RwLock::new(None);

    /// Unique ID counter
    static ref UNIQUE_COUNTER: RwLock<u64> = RwLock::new(0);
}

/// Generate a unique number
pub fn unique_id() -> u64 {
    interrupts::without_interrupts(|| {
        let mut counter = UNIQUE_COUNTER.write();
        *counter += 1;
        *counter
    })
}

/// Per-process state
struct Process {
    /// Page table physical address
    page_table_physaddr: u64
}

impl Drop for Process {
    fn drop(&mut self) {
        // Check if the page table is currently active
        if self.page_table_physaddr == memory::active_pagetable_physaddr() {
            memory::switch_to_kernel_pagetable();
        }
        memory::free_user_pagetables(self.page_table_physaddr);
    }
}

/// Per-thread state
///
///
/// https://samwho.dev/blog/context-switching-on-x86/
///
/// Notes:
///  - Box::new(Thread { .. }) first constructs a new Thread
///    on the stack, then moves it onto the heap. Fixed sized arrays
///    therefore can't be used for the new process' stack because they
///    overflow the current stack.
struct Thread {
    /// Thread ID
    tid: u64,

    /// Process shared data
    process: Arc<Process>,

    /// Page table physical address
    ///
    /// Note: Functions which manipulate page tables may temporarily
    /// modify their page table. To avoid having to disable
    /// interrupts, each thread's page table is saved and restored
    /// during context switches
    page_table_physaddr: u64,

    /// Kernel stack needed to handle system calls
    /// and interrupts including
    /// save/restore process state in context switch
    kernel_stack: Vec<u8>,

    /// Address of the end of the stack.
    /// This value is put in the Interrupt Stack Table
    kernel_stack_end: u64,

    /// Address of the end of the user stack
    user_stack_end: u64,

    /// Address within the kernel_stack which stores
    /// the Context structure containing thread state.
    context: u64,
}

use core::fmt;

/// Enable Thread structs to be printed
impl fmt::Display for Thread {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Cast context address to Context struct
        let context = unsafe {&mut *(self.context as *mut Context)};

        let kernel_stack_start = self.kernel_stack_end - (KERNEL_STACK_SIZE as u64);
        let user_stack_start = self.user_stack_end - (USER_STACK_SIZE as u64);

        write!(f, "\
TID: {}, rip: {:#016X}
    Kernel stack: {:#016X} - {:#016X} Context: {:#016X}
    Thread stack: {:#016X} - {:#016X} RSP: {:#016X}",
               self.tid, context.rip,
               // Second line
               kernel_stack_start, self.kernel_stack_end, self.context,
               // Third line
               user_stack_start, self.user_stack_end, context.rsp)
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        memory::free_user_stack(
            VirtAddr::new(self.user_stack_end));
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
/// The TID of the new thread
///
pub fn new_kernel_thread(function: fn()->()) -> u64 {
    // Create a new process table entry
    //
    // Note this is first created on the stack, then moved into a Box
    // on the heap.
    let new_thread = {
        // Allocate both "user" and kernel stacks in kernel memory
        let kernel_stack = Vec::with_capacity(KERNEL_STACK_SIZE + USER_STACK_SIZE);
        let kernel_stack_start = VirtAddr::from_ptr(kernel_stack.as_ptr());
        let kernel_stack_end = (kernel_stack_start + KERNEL_STACK_SIZE).as_u64();
        let user_stack_end = kernel_stack_end + (USER_STACK_SIZE as u64);

        Box::new(Thread {
            tid: unique_id(),
            process: Arc::new(Process {
                page_table_physaddr: 0
            }),
            page_table_physaddr: 0, // Don't need to switch PT
            kernel_stack,
            // Note that stacks move backwards, so SP points to the end
            kernel_stack_end,
            user_stack_end,
            // Push a Context struct on the kernel stack
            context: kernel_stack_end - INTERRUPT_CONTEXT_SIZE as u64,
        })
    };

    // Cast context address to Context struct
    let context = unsafe {&mut *(new_thread.context as *mut Context)};

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
    context.rsp = new_thread.user_stack_end as usize;

    let tid = new_thread.tid;

    println!("New kernel thread {}", new_thread);

    // Turn off interrupts while modifying process table
    interrupts::without_interrupts(|| {
        RUNNING_QUEUE.write().push_back(new_thread);
    });
    tid
}

/// Wrapper which runs a closure with a specified page table
///
/// Ensures that the original page table is restored after the
/// closure finishes.
fn with_pagetable<F, R>(page_table_physaddr: u64, func: F) -> R where
    F: FnOnce() -> R {
    // Store the page table and switch back before returning
    let original_page_table = memory::active_pagetable_physaddr();

    // Switch to the new user page table
    //
    // Note: We don't need to turn off interrupts because
    // schedule_next() saves the page table for each thread. This
    // thread temporarily has a different page table to the other
    // threads.
    memory::switch_to_pagetable(page_table_physaddr);

    let result = func();

    // Switch back to original page table
    memory::switch_to_pagetable(original_page_table);

    result
}

pub fn new_user_thread(bin: &[u8]) -> Result<u64, &'static str> {
    // Check the header
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

    if bin[0..4] != ELF_MAGIC {
        return Err("Expected ELF binary");
    }
    // Use the object crate to parse the ELF file
    // https://crates.io/crates/object
    if let Ok(obj) = object::File::parse(bin) {

        // Create a user pagetable with only kernel pages
        let (user_page_table_ptr, user_page_table_physaddr) =
            memory::create_kernel_only_pagetable();

        return with_pagetable(user_page_table_physaddr, || {

            let entry_point = obj.entry();
            println!("Entry point: {:#016X}", entry_point);

            for segment in obj.segments() {
                let segment_address = segment.address() as u64;

                println!("Section {:?} : {:#016X}", segment.name(), segment_address);

                if let Ok(data) = segment.data() {
                    println!("  len : {}", data.len());

                    let start_address = VirtAddr::new(segment_address);
                    let end_address = start_address + data.len() as u64;

                    // Check if data is in allowed range
                    if (start_address < VirtAddr::new(USER_CODE_START))
                        || (end_address >= VirtAddr::new(USER_CODE_END)) {
                            return Err("ELF segment outside allowed range");
                        }

                    // Allocate memory in the pagetable
                    if memory::allocate_pages(user_page_table_ptr,
                                              start_address,
                                              data.len() as u64, // Size (bytes)
                                              PageTableFlags::PRESENT |
                                              PageTableFlags::WRITABLE |
                                              PageTableFlags::USER_ACCESSIBLE).is_err() {
                        return Err("Could not allocate memory");
                    }

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

            // Create the new Thread struct
            let new_thread = {
                // Note: Kernel stack needs to be mapped in all pages
                //       because the page table will be changed during
                //       context switch
                let kernel_stack = Vec::with_capacity(KERNEL_STACK_SIZE);
                let kernel_stack_start = VirtAddr::from_ptr(kernel_stack.as_ptr());
                let kernel_stack_end = (kernel_stack_start + KERNEL_STACK_SIZE).as_u64();

                // Allocate user stack
                let (user_stack_start, user_stack_end) = memory::allocate_user_stack(user_page_table_ptr)?;

                Box::new(Thread {
                    tid: unique_id(),
                    // Create a new process
                    process: Arc::new(Process {
                        page_table_physaddr: user_page_table_physaddr
                    }),
                    page_table_physaddr: user_page_table_physaddr,
                    kernel_stack: kernel_stack,
                    // Note that stacks move backwards, so SP points to the end
                    kernel_stack_end,
                    user_stack_end,
                    // Push a Context struct on the kernel stack
                    context: kernel_stack_end - INTERRUPT_CONTEXT_SIZE as u64
                })
            };

            // Cast context address to Context struct
            let context = unsafe {&mut *(new_thread.context as *mut Context)};

            context.rip = entry_point as usize;

            // Set flags
            context.rflags = 0x0200; // Interrupt enable

            let (code_selector, data_selector) = gdt::get_user_segments();
            context.cs = code_selector.0 as usize; // Code segment flags
            context.ss = data_selector.0 as usize; // Without this we get a GPF

            // Note: Need to point to the end of the allocated region
            //       because the stack moves down in memory
            context.rsp = new_thread.user_stack_end as usize;

            let tid = new_thread.tid;

            println!("New Thread {}", new_thread);
            // No interrupts while modifying queue
            interrupts::without_interrupts(|| {
                RUNNING_QUEUE.write().push_back(new_thread);
            });

            return Ok(tid);
        });
    }
    return Err("Could not parse ELF");
}

/// Fork the current user thread
///
///
pub fn fork_current_thread(current_context: &mut Context) {

    if let Some(current_thread) = CURRENT_THREAD.read().as_ref() {

        // Allocate user stack
        let page_table_ptr = memory::active_pagetable_ptr();
        if let Ok((user_stack_start, user_stack_end)) = memory::allocate_user_stack(page_table_ptr) {
            let new_thread = {
                // Create a new kernel stack
                let kernel_stack = Vec::with_capacity(KERNEL_STACK_SIZE);
                let kernel_stack_start = VirtAddr::from_ptr(kernel_stack.as_ptr());
                let kernel_stack_end = (kernel_stack_start + KERNEL_STACK_SIZE).as_u64();

                Box::new(Thread {
                    tid: unique_id(),
                    process: current_thread.process.clone(), // Shared state
                    page_table_physaddr: current_thread.page_table_physaddr, // Shared page table
                    kernel_stack,
                    kernel_stack_end,
                    user_stack_end,
                    context: kernel_stack_end - INTERRUPT_CONTEXT_SIZE as u64,
                })
            };

            let new_context = unsafe {&mut *(new_thread.context as *mut Context)};
            *new_context = current_context.clone();

            // Set new stack pointer
            new_context.rsp = new_thread.user_stack_end as usize;

            // Set return values in rax
            new_context.rax = 0; // No error
            new_context.rdi = 0; // Indicates that this is the new thread
            current_context.rax = 0; // No error
            current_context.rdi = new_thread.tid as usize;

            let tid = new_thread.tid;
            RUNNING_QUEUE.write().push_back(new_thread);
        } else {
            // Failed to allocate user stack
            current_context.rax = syscalls::SYSCALL_ERROR_MEMALLOC; // Error code
        }
    } else {
        // Somehow no current thread
        current_context.rax = 2; // Error code
    }
}

/// This function is called via syscall (and maybe other mechanism)
/// to remove the current thread.
pub fn exit_current_thread(current_context: &mut Context) {
    {
        let mut current_thread = CURRENT_THREAD.write();

        if let Some(thread) = current_thread.take() {
            // Drop thread, freeing stacks. If this is the last thread
            // in this process, memory and page tables will be freed
            // in the Process drop() function
        }
    }
    // Can't return from this syscall, so this thread now waits for a
    // timer interrupt to switch context.
    unsafe {
        asm!("sti",
             "2:",
             "hlt",
             "jmp 2b");
    }
}

/// This is called by the timer interrupt handler
///
/// Returns the stack containing the process state
/// (interrupts::Context struct)
pub fn schedule_next(context: &Context) -> usize {
    let mut running_queue = RUNNING_QUEUE.write();
    let mut current_thread = CURRENT_THREAD.write();

    if let Some(thread) = current_thread.take() {
        // Put the current thread to the back of the queue

        // Update the stack pointer
        let mut thread_mut = thread;

        // Store context location. This should almost always be in the same
        // location on the kernel stack. The exception is the
        // first time a context switch occurs from the original kernel
        // stack to the first kernel thread stack.
        thread_mut.context = (context as *const Context) as u64;

        // Save the page table. This is to enable context
        // switching during functions which manipulate page tables
        // for example new_user_thread
        thread_mut.page_table_physaddr = memory::active_pagetable_physaddr();

        running_queue.push_back(thread_mut);
    }
    *current_thread = running_queue.pop_front();

    match current_thread.as_ref() {
        Some(thread) => {
            // Set the kernel stack for the next interrupt
            gdt::set_interrupt_stack_table(
                gdt::TIMER_INTERRUPT_INDEX as usize,
                // Note: Point to the end of the stack
                VirtAddr::new(thread.kernel_stack_end));

            if thread.page_table_physaddr != 0 {
                // Change page table
                // Note: zero for kernel thread
                memory::switch_to_pagetable(thread.page_table_physaddr);
            }

            // Point the stack to the new context
            // (which is usually stored on the kernel stack)
            thread.context as usize
        },
        None => 0
    }
}
