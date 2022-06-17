#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(blog_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use kernel::println;
use bootloader::{BootInfo, entry_point};
extern crate alloc;
use alloc::{vec::Vec, sync::Arc, string::String};
use spin::RwLock;

use kernel::memory;
use kernel::syscalls;
use kernel::process;
use kernel::vga_buffer;
use kernel::interrupts;
use kernel::rendezvous::Rendezvous;

entry_point!(kernel_entry);

/// Main kernel thread entry point
/// This is the first process added to the scheduler
/// which is started once basic kernel functions have
/// been initialised in kernel_entry
fn kernel_thread_main() {
    let pci_input = interrupts::keyboard_rendezvous();
    let vga_rz = vga_buffer::start_listener();

    // Start PCI program with keyboard input and VGA output
    process::new_user_thread(
        include_bytes!("../../user/pci"),
        process::Params{
            handles: Vec::from([
                pci_input.clone(),
                vga_rz.clone()
            ]),
            io_privileges: true,
            mounts: Arc::new(RwLock::new(Vec::new()))
        });

    process::new_user_thread(
        include_bytes!("../../user/rtl8139"),
        process::Params{
            handles: Vec::from([
                // New input (not shared with anything else)
                Arc::new(RwLock::new(Rendezvous::Empty)),
                // VGA output
                vga_rz
            ]),
            io_privileges: true,
            mounts: Arc::new(RwLock::new(Vec::from([
                // A VFS path to the PCI input
                (String::from("/pci"), pci_input)
            ])))
        });

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
