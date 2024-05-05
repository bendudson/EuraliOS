#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(blog_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use kernel::println;
use bootloader::{BootInfo, entry_point};
extern crate alloc;
use alloc::{vec::Vec, sync::Arc};
use spin::RwLock;

use kernel::memory;
use kernel::syscalls;
use kernel::process;
use kernel::rendezvous::Rendezvous;
use kernel::vfs;
use kernel::message::{self, Message};

entry_point!(kernel_entry);

/// Main kernel thread entry point
/// This is the first process added to the scheduler
/// which is started once basic kernel functions have
/// been initialised in kernel_entry
fn kernel_thread_main() {
    // User-space init process
    let null = Arc::new(RwLock::new(Rendezvous::Empty));
    let init_screen = Arc::new(RwLock::new(Rendezvous::Empty));
    let init_thread = process::new_user_thread(
        include_bytes!("../../user/init"),
        process::Params{
            handles: Vec::from([
                // Null input
                null,
                // Output used to pass data
                init_screen.clone()
            ]),
            io_privileges: true,
            mounts: vfs::VFS::new(), // Create a Virtual File System
            args: Vec::new()
        }).unwrap();

    // Allocate a memory chunk mapping video memory
    let (virtaddr, _) = process::special_memory_chunk(
        &init_thread,
        32,  // Pages, 128k. 0xC0000 - 0xA0000
        0xA0000).unwrap();

    // Remove chunk from table so it can be sent
    let (physaddr, _) = init_thread.take_memory_chunk(virtaddr).unwrap();

    // Send a message to init process containing the chunk.
    // When received the chunk will be mapped into address space
    init_screen.write().send(None, Message::Long(
        message::VIDEO_MEMORY,
        (0xC0000 - 0xA0000).into(),
        physaddr.into()
    ));

    process::schedule_thread(init_thread);

    kernel::hlt_loop();
}

/// Function called by the bootloader
/// via _start entry point declared in entry_point! above
///
/// Inputs
///  BootInfo    Bootloader memory mapping information
///
fn kernel_entry(boot_info: &'static BootInfo) -> ! {
    kernel::init();

    // Set up memory and kernel heap with allocator
    memory::init(boot_info);

    // Set up system calls
    syscalls::init();

    #[cfg(test)]
    test_main();

    // Launch the main kernel thread
    // which will be scheduled and take over from here
    process::new_kernel_thread(kernel_thread_main, Vec::new());

    kernel::hlt_loop();
}

/// This function is called on panic.
#[cfg(not(test))]  // If not in QEMU test mode
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("Kernel panic: {}", info);
    kernel::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel::test_panic_handler(info)
}

#[test_case]
fn trivial_assertion() {
    assert_eq!(1, 1);
}
