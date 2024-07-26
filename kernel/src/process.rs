//! Handle processes
//!
//! Create processes, and determine which one to run next
//!

use x86_64::{VirtAddr, PhysAddr};
use x86_64::instructions::interrupts;
use x86_64::structures::paging::PageTableFlags;

use spin::RwLock;
use lazy_static::lazy_static;
extern crate alloc;
use alloc::{boxed::Box, collections::vec_deque::VecDeque, vec::Vec, sync::Arc};

use core::{slice, arch::asm};

use crate::println;
use crate::interrupts::{Context, INTERRUPT_CONTEXT_SIZE};

use crate::gdt;
use crate::memory;
use crate::syscalls;
use crate::rendezvous::Rendezvous;
use crate::message::Message;
use crate::vfs;

use object::{Object, ObjectSegment};

/// Size of the kernel stack for each process, in bytes
const KERNEL_STACK_SIZE: usize = 4096 * 2;

/// Size of the user stack for each user process, in bytes
const USER_STACK_SIZE: usize = 4096 * 5;

/// Lowest address that user code can be loaded into
pub const USER_CODE_START: u64 = 0x20_0000;
/// Exclusive upper limit for user code or data
pub const USER_CODE_END: u64 = 0x5000_0000;

const USER_HEAP_START: u64 = 0x280_0060_0000;
const USER_HEAP_SIZE: u64 = 4 * 1024 * 1024; //0x28002e00000 - 0x28000600000;

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
    page_table_physaddr: u64,

    /// Communication/file handles
    handles: Vec<Option<Arc<RwLock<Rendezvous>>>>,

    /// Paths to handlers which can be open'ed
    mounts: vfs::VFS
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

impl Process {
    /// Add a Rendezvous to this process, returning
    /// the handle
    fn add_handle(&mut self, rv: Arc<RwLock<Rendezvous>>) -> usize {
        // Find if there is an empty handles slot
        if let Some(index) = self.handles.iter().position(
            |handle| handle.is_none()) {

            // Use empty slot
            self.handles[index] = Some(rv);
            return index;
        }

        // No free slot -> Add one
        self.handles.push(Some(rv));
        self.handles.len() - 1
    }
}

/// Per-thread state
///
///
/// <https://samwho.dev/blog/context-switching-on-x86/>
///
/// Notes:
///  - Box::new(Thread { .. }) first constructs a new Thread
///    on the stack, then moves it onto the heap. Fixed sized arrays
///    therefore can't be used for the new process' stack because they
///    overflow the current stack.
pub struct Thread {
    /// Thread ID
    tid: u64,

    /// Process shared data
    process: Arc<RwLock<Process>>,

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

impl Thread {
    /// Get the Thread ID
    pub fn tid(&self) -> u64 {
        self.tid
    }

    /// Get a reference to the thread Context
    fn context(&self) -> &Context {
        unsafe {& *(self.context as *const Context)}
    }

    /// Get a mutable reference to the thread Context
    fn context_mut(&self) -> &mut Context {
        unsafe {&mut *(self.context as *mut Context)}
    }

    pub fn set_context(&mut self, context_ptr: *mut Context) {
        self.context = context_ptr as u64;
    }

    /// Modify a thread context, setting the RAX
    /// register to signal an error.
    ///
    /// Note: Should only be applied to threads that
    /// will return from a syscall.
    pub fn return_error(&self, error_code: usize) {
        // Ensure that the error is in range, no message
        self.context_mut().rax = error_code &
            syscalls::SYSCALL_ERROR_MASK;
    }

    /// Modify a thread context, setting registers
    ///
    /// Note: Should only be applied to threads that
    /// will return from a syscall.
    ///
    /// If error != 0 then an error is sent along with the message
    ///
    /// Note:
    ///  - RCX and R11 are used by sysret so can't be used
    ///    to return data
    pub fn return_error_message(&self, error: usize, message: Message) {
        let context = self.context_mut();

        let (ctrl, data1, data2, data3) = message.to_values(self);
        context.rax = ctrl as usize;
        if error != 0 {
            // Error returning a message
            context.rax |=  syscalls::SYSCALL_ERROR_CONTAINS_MESSAGE |
            (error & syscalls::SYSCALL_ERROR_MASK);
        }
        context.rdi = data1 as usize;
        context.rsi = data2 as usize;
        context.rdx = data3 as usize;
    }

    /// Return a message to the thread
    pub fn return_message(&self, message: Message) {
        self.return_error_message(0, message)
    }

    /// Get a clone of a rendezvous handle if it exists
    pub fn rendezvous(&self, id: u64)
                      -> Option<Arc<RwLock<Rendezvous>>> {
        self.process.read().handles.get(id as usize) // Option<&Option<Arc<>>>
            .unwrap_or(&None)  // &Option<Arc<>>
            .as_ref() // Option<&Arc<>>
            .map(|rv| rv.clone()) // Option<Arc<>>
    }

    /// Take the rendezvous, leaving handle empty (None)
    pub fn take_rendezvous(&self, id: u64)
                           -> Option<Arc<RwLock<Rendezvous>>> {
        self.process.write().handles.get_mut(id as usize).map_or(None, |elem| elem.take())
    }

    /// Add a rendezvous to the process, returning the handle
    pub fn give_rendezvous(&self, rendezvous: Arc<RwLock<Rendezvous>>) -> usize {
        // Lock the handles
        let handles = &mut self.process.write().handles;

        // Find empty handle slot
        for (pos, handle) in handles.iter().enumerate() {
            if handle.is_none() {
                // Found empty slot => Store rendezvous
                handles[pos] = Some(rendezvous);
                return pos;
            }
        }
        // All full => Add new handle
        handles.push(Some(rendezvous));
        handles.len() - 1
    }

    /// Get the physical address and page table level of the memory
    /// chunk containing the given virtual address
    pub fn memory_chunk(
        &self,
        address: VirtAddr
    ) -> Result<(PhysAddr, u16), usize> {
        memory::get_page_chunk(
            self.page_table_physaddr,
            address,
            false) // false => Don't remove from pagetable
    }

    /// Remove a memory chunk from this thread's page table which
    /// contains the given virtual address.
    ///
    /// Note: Doesn't free the frames or pagetables
    pub fn take_memory_chunk(
        &self,
        address: VirtAddr
    ) -> Result<(PhysAddr, u16), usize> {
        memory::get_page_chunk(
            self.page_table_physaddr,
            address,
            true) // true => Remove from pagetable
    }

    /// Add a memory chunk to this thread's page table
    pub fn give_memory_chunk(
        &self,
        physaddr: PhysAddr
    ) -> Result<VirtAddr, usize> {
        memory::put_page_chunk(
            self.page_table_physaddr,
            physaddr)
    }

    /// Get a clone of the VFS mount points
    pub fn vfs(&self) -> vfs::VFS {
        self.process.read().mounts.clone()
    }
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
        if let Err(e) = memory::free_user_stack(
            VirtAddr::new(self.user_stack_end)) {
            println!("Error in Thread::drop : {:?}", e);
        }
    }
}

/// Adds a thread to the front of the running queue
/// so it will be scheduled next
pub fn schedule_thread(thread: Box<Thread>) {
    // Turn off interrupts while modifying process table
    interrupts::without_interrupts(|| {
        RUNNING_QUEUE.write().push_front(thread);
    });
}


/// Takes ownership of the current Thread
pub fn take_current_thread() -> Option<Box<Thread>> {
    CURRENT_THREAD.write().take()
}

/// Makes the given thread the current thread
/// If another thread was running schedule it
pub fn set_current_thread(thread: Box<Thread>) {
    // Replace the current thread
    let old_current = CURRENT_THREAD.write().replace(thread);
    if let Some(t) = old_current {
        schedule_thread(t);
    }
}

/// Start a new kernel thread by adding it to the process table.
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
/// Note: returning Box<Thread> to be scheduled
/// leads to panic in VirtAddr::new(). Cause unknown,
/// exposing memory/stack bug?
///
pub fn new_kernel_thread(
    function: fn()->(),
    mut handles: Vec<Arc<RwLock<Rendezvous>>>
) -> u64 {

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
            process: Arc::new(RwLock::new(Process {
                page_table_physaddr: 0,
                // Wrap each handle in an Option
                handles:handles.drain(..)
                    .map(|h| Some(h)).collect(),
                // Empty set of mount paths
                mounts: vfs::VFS::new()
            })),
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
    let context = new_thread.context_mut();

    // Set the instruction pointer
    context.rip = function as usize;

    // Set flags
    context.rflags = 0x200;

    // Set segment selector flags
    let (code_selector, data_selector) = gdt::get_kernel_segments();
    context.cs = code_selector.0 as usize;
    context.ss = data_selector.0 as usize;

    // The kernel thread has its own stack
    // Note: Need to point to the end of the memory region
    //       because the stack moves down in memory
    context.rsp = new_thread.user_stack_end as usize;

    let tid = new_thread.tid;
    schedule_thread(new_thread);
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

pub struct Params {
    pub handles: Vec<Arc<RwLock<Rendezvous>>>,
    pub io_privileges: bool,
    pub mounts: vfs::VFS,
    pub args: Vec<u8>, // Command-line arguments
    pub envs: Vec<u8>, // Environment variables
}

/// Create a new user thread
///
/// # Arguments
///
/// * `bin`    - ELF binary containing the program.
///              Note: This must be accessible in the kernel page tables
/// * `params` - A collection of parameters. Used so that the calling
///              site is clearer in what parameters are being set.
pub fn new_user_thread(
    bin: &[u8],
    params: Params
) -> Result<Box<Thread>, &'static str> {
    // Check the header
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

    if bin[0..4] != ELF_MAGIC {
        return Err("Expected ELF binary");
    }
    // Use the object crate to parse the ELF file
    // <https://crates.io/crates/object>
    if let Ok(obj) = object::File::parse(bin) {

        // Create a user pagetable with only kernel pages
        let (user_page_table_ptr, user_page_table_physaddr) =
            memory::create_new_user_pagetable();

        // Allocate user heap
        if memory::create_user_ondemand_pages(
            user_page_table_physaddr,
            VirtAddr::new(USER_HEAP_START),
            USER_HEAP_SIZE).is_err() {
            return Err("Couldn't allocate on-demand pages");
        }

        return with_pagetable(user_page_table_physaddr, || {

            let entry_point = obj.entry();

            for segment in obj.segments() {
                let segment_address = segment.address() as u64;

                let start_address = VirtAddr::new(segment_address);
                let end_address = start_address + segment.size() as u64;

                // Check if data is in allowed range
                if (start_address < VirtAddr::new(USER_CODE_START))
                    || (end_address >= VirtAddr::new(USER_CODE_END)) {
                        return Err("ELF segment outside allowed range");
                    }

                // Allocate memory in the pagetable
                if memory::allocate_pages(user_page_table_ptr,
                                          start_address,
                                          segment.size() as u64, // Size (bytes)
                                          PageTableFlags::PRESENT |
                                          PageTableFlags::WRITABLE |
                                          PageTableFlags::USER_ACCESSIBLE).is_err() {
                    return Err("Could not allocate memory");
                }
                memory::switch_to_pagetable(user_page_table_physaddr);

                if let Ok(data) = segment.data() {
                    if data.len() > segment.size() as usize {
                        return Err("ELF data length > segment size");
                    } else if data.len() > 0 {
                        // Copy data
                        let dest_ptr = segment_address as *mut u8;
                        for (i, value) in data.iter().enumerate() {
                            unsafe {
                                let ptr = dest_ptr.add(i);
                                core::ptr::write(ptr, *value);
                            }
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
                let (_user_stack_start, user_stack_end) = memory::allocate_user_stack(user_page_table_ptr)?;

                let mut handles = params.handles;
                Box::new(Thread {
                    tid: unique_id(),
                    // Create a new process
                    process: Arc::new(RwLock::new(Process {
                        page_table_physaddr: user_page_table_physaddr,
                        handles:handles.drain(..)
                            .map(|h| Some(h)).collect(),
                        mounts: params.mounts,
                    })),
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
            let context = new_thread.context_mut();

            context.rip = entry_point as usize;

            // Set flags
            context.rflags = if params.io_privileges {
                0x200 + 0x3000 // Interrupt enable + IOPL 3
            } else {
                0x200 // Interrupt enable
            };

            let (code_selector, data_selector) = gdt::get_user_segments();
            context.cs = code_selector.0 as usize; // Code segment flags
            context.ss = data_selector.0 as usize; // Without this we get a GPF

            // Note: Need to point to the end of the allocated region
            //       because the stack moves down in memory
            context.rsp = new_thread.user_stack_end as usize;

            // Modify the context to pass information to the new thread
            context.rax = USER_HEAP_START as usize;
            context.rcx = USER_HEAP_SIZE as usize;

            // Store the arguments on the stack
            // with start address in RDX
            // Note: Only one page of the stack is allocated
            //       so argument string must fit in 4k
            if params.args.len() == 0 {
                // No arguments
                context.rdx = 0;
            } else {
                let length = params.args.len();
                let user_args = unsafe{slice::from_raw_parts_mut((context.rsp - length) as *mut u8, length)};
                user_args.copy_from_slice(&params.args);
                context.rsp -= length + 4;
                unsafe{
                    *(context.rsp as *mut i32) = length as i32;
                }
                context.rdx = context.rsp;
            }

            // Store environment variables on the stack
            // with start address in RDI
            // Note: RBX is reserved by LLVM
            if params.envs.len() == 0 {
                // No environment
                context.rdi = 0;
            } else {
                let length = params.envs.len();
                let user_env = unsafe{slice::from_raw_parts_mut((context.rsp - length) as *mut u8, length)};
                user_env.copy_from_slice(&params.envs);
                context.rsp -= length + 4;
                unsafe{
                    *(context.rsp as *mut i32) = length as i32;
                }
                context.rdi = context.rsp;
            }

            Ok(new_thread)
        });
    }
    Err("Could not parse ELF")
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
pub fn exit_current_thread(_current_context: &mut Context) {
    {
        let mut current_thread = CURRENT_THREAD.write();

        if let Some(_thread) = current_thread.take() {
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
pub fn schedule_next(context_addr: usize) -> usize {
    let mut running_queue = RUNNING_QUEUE.write();
    let mut current_thread = CURRENT_THREAD.write();

    if let Some(mut thread) = current_thread.take() {
        // Put the current thread to the back of the queue

        // Store context location. This should almost always be in the same
        // location on the kernel stack. The exception is the
        // first time a context switch occurs from the original kernel
        // stack to the first kernel thread stack.
        thread.context = context_addr as u64;

        // Save the page table. This is to enable context
        // switching during functions which manipulate page tables
        // for example new_user_thread
        thread.page_table_physaddr = memory::active_pagetable_physaddr();

        running_queue.push_back(thread);
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

/// Open the given path
/// Returns either a Rendezvous handle and path match length, or an error
pub fn open_path(
    _current_context: &mut Context,
    path: &str) -> Result<(usize, usize), usize> {

    if let Some(current_thread) = CURRENT_THREAD.read().as_ref() {
        let mut process = current_thread.process.write();

        if let Some((rv, match_len)) = process.mounts.open(path) {
            // Found!
            let handle = process.add_handle(rv.clone());
            return Ok((handle, match_len));
        } else {
            return Err(syscalls::SYSCALL_ERROR_NOTFOUND);
        }
    }
    // No thread(?)
    Err(0)
}

/// Create a new memory chunk
///
/// num_pages    - Size of the memory chunk
/// max_physaddr - If Some() then consecutive frames
///                are allocated which are all below the
///                maximum physical address.
///
/// Returns either (handle, physaddr) or error code
pub fn new_memory_chunk(
    num_pages: u64,
    max_physaddr: u64
) -> Result<(VirtAddr, PhysAddr), usize> {
    // Get the current thread
    if let Some(thread) = CURRENT_THREAD.read().as_ref() {

        // Virtual address of the available page chunk
        let start_addr = match memory::find_available_page_chunk(
            thread.page_table_physaddr) {
            Some(values) => values,
            None => {
                println!("Thread {} no available chunks!", thread.tid());
                return Err(syscalls::SYSCALL_ERROR_MEMORY)
            }
        };

        if max_physaddr != 0 {
            // Allocate a consecutive set of frames
            let physaddr = match memory::create_consecutive_pages(
                thread.page_table_physaddr,
                start_addr,
                num_pages,
                max_physaddr) {
                Ok(physaddr) => physaddr,
                Err(_) => return Err(syscalls::SYSCALL_ERROR_MEMORY)
            };

            return Ok((start_addr, physaddr));
        } else {
            // User doesn't need frames to be consecutive
            // -> Allocate frames only when actually used
            if memory::create_user_ondemand_pages(
                thread.page_table_physaddr,
                start_addr,
                num_pages * 4096).is_err() { // size in bytes
                return Err(syscalls::SYSCALL_ERROR_MEMORY);
            }

            // Note: physical address not returned because
            //       the frames are not guaranteed to be
            //       consecutive in physical address.
            return Ok((start_addr, PhysAddr::new(0)));
        }
    }
    Err(syscalls::SYSCALL_ERROR_THREAD)
}

/// A memory chunk which maps a specific range of
/// physical memory
///
/// No frame allocation, so assumes that the physical
/// memory is ok to use.
///
/// # Arguments
///
/// * `thread` - The thread which will have the new chunk mapped
/// * `num_pages` - Number of 4k pages
/// * `start_physaddr` - Starting physical address.
///                      Must be page aligned
///
pub fn special_memory_chunk(
    thread: &Thread,
    num_pages: u64,
    start_physaddr: u64
) -> Result<(VirtAddr, PhysAddr), usize> {
    // Virtual address of the available page chunk
    let start_virtaddr = match memory::find_available_page_chunk(
        thread.page_table_physaddr) {
        Some(value) => value,
        None => return Err(syscalls::SYSCALL_ERROR_MEMORY)
    };

    match memory::create_physical_range_pages(
        thread.page_table_physaddr,
        start_virtaddr,
        num_pages,
        PhysAddr::new(start_physaddr)) {
        Ok(physaddr) => Ok((start_virtaddr, physaddr)),
        Err(_) => Err(syscalls::SYSCALL_ERROR_MEMORY)
    }
}

/// Free a memory chunk previously allocated with new_memory_chunk
pub fn free_memory_chunk(
    address: VirtAddr
) -> Result<(), usize> {
    if let Some(thread) = CURRENT_THREAD.read().as_ref() {
        return memory::free_page_chunk(thread.page_table_physaddr,
                                       address);
    }
    Err(syscalls::SYSCALL_ERROR_THREAD)
}

pub fn new_rendezvous() -> Result<(usize, usize), usize> {
    if let Some(thread) = CURRENT_THREAD.read().as_ref() {
        let rv = Arc::new(RwLock::new(Rendezvous::Empty));

        let handle1 = thread.give_rendezvous(rv.clone());
        let handle2 = thread.give_rendezvous(rv);
        return Ok((handle1, handle2));
    }
    Err(syscalls::SYSCALL_ERROR_THREAD)
}
