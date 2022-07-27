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
use kernel::vga_buffer;
use kernel::interrupts;
use kernel::rendezvous::Rendezvous;
use kernel::vfs;
use kernel::message::{self, Message};

entry_point!(kernel_entry);

/// Main kernel thread entry point
/// This is the first process added to the scheduler
/// which is started once basic kernel functions have
/// been initialised in kernel_entry
fn kernel_thread_main() {
    let keyboard_rz = interrupts::keyboard_rendezvous();
    let vga_rz = vga_buffer::start_listener();

    // Create a Virtual File System
    let mut vfs = vfs::VFS::new();

    // Start PCI program with new input and VGA output
    let pci_input = Arc::new(RwLock::new(Rendezvous::Empty));
    process::schedule_thread(
        process::new_user_thread(
            include_bytes!("../../user/pci"),
            process::Params{
                handles: Vec::from([
                    pci_input.clone(),
                    vga_rz.clone()
                ]),
                io_privileges: true,
                mounts: vfs.clone()
            }).unwrap());

    vfs.mount("/pci", pci_input);

    // VGA user-space device driver
    let vga_input = Arc::new(RwLock::new(Rendezvous::Empty));
    let vga_thread = process::new_user_thread(
        include_bytes!("../../user/vga_driver"),
        process::Params{
            handles: Vec::from([
                vga_input.clone(),
                // No STDOUT
            ]),
            io_privileges: true,
            mounts: vfs.clone()
        }).unwrap();

    // Allocate a memory chunk mapping video memory
    let (virtaddr, _) = process::special_memory_chunk(
        &vga_thread,
        32,  // Pages, 128k. 0xC0000 - 0xA0000
        0xA0000).unwrap();

    // Remove chunk from table so it can be sent
    let (physaddr, _) = vga_thread.take_memory_chunk(virtaddr).unwrap();

    // Send a message to VGA process containing the chunk.
    // When received the chunk will be mapped into address space
    vga_input.write().send(None, Message::Long(
        message::VIDEO_MEMORY,
        (0xC0000 - 0xA0000).into(),
        physaddr.into()
    ));

    process::schedule_thread(vga_thread);

    // // New input for the rtl8139 driver
    // let rtl_input = Arc::new(RwLock::new(Rendezvous::Empty));
    // process::schedule_thread(
    //     process::new_user_thread(
    //         include_bytes!("../../user/rtl8139"),
    //         process::Params{
    //             handles: Vec::from([
    //                 // Input
    //                 rtl_input.clone(),
    //                 // VGA output
    //                 vga_rz.clone()
    //             ]),
    //             io_privileges: true,
    //             mounts: vfs.clone()
    //         }).unwrap());
    // vfs.mount("/dev/nic", rtl_input);

    // // New input for tcp stack
    // let tcp_input = Arc::new(RwLock::new(Rendezvous::Empty));
    // process::schedule_thread(
    //     process::new_user_thread(
    //         include_bytes!("../../user/tcp"),
    //         process::Params{
    //             handles: Vec::from([
    //                 // Input
    //                 tcp_input.clone(),
    //                 // VGA output
    //                 vga_rz.clone()
    //             ]),
    //             io_privileges: false,
    //             mounts: vfs.clone()
    //         }).unwrap());
    // vfs.mount("/tcp", tcp_input);

    // // Use keyboard input
    // process::schedule_thread(
    //     process::new_user_thread(
    //         include_bytes!("../../user/gopher"),
    //         process::Params{
    //             handles: Vec::from([
    //                 // Input
    //                 keyboard_rz,
    //                 // VGA output
    //                 vga_rz
    //             ]),
    //             io_privileges: false,
    //             mounts: vfs
    //         }).unwrap());

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
    println!("{}", info);
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
