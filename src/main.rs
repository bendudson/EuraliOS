#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(blog_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use blog_os::println;
use bootloader::{BootInfo, entry_point};

use blog_os::memory;
use blog_os::process;

entry_point!(kernel_main);

use core::arch::asm;

#[inline(never)]
fn test_fn() {
    // Print the current stack pointer, to check we're in the right range
    let rsp: usize;
    unsafe {
        asm!{
            "mov rax, rsp",
            lateout("rax") rsp
        }
    }
    println!("Hello from test fn! (0x{:X})", rsp)
}

/// Entry point for the kernel thread.
/// This is the first process added to the scheduler
/// which is started once basic kernel functions have
/// been initialised in kernel_main
fn kernel_thread_main() {
    println!("Kernel thread start");

    // Call a function, to check call/return on stack
    test_fn();

    // Launch another kernel thread
    process::new_kernel_thread(test_kernel_fn2);

    loop {
        println!("<< 1 >>");
        x86_64::instructions::hlt();
    }
}

fn test_kernel_fn2() {
    println!("Hello from kernel function 2!");
    test_fn();
    loop {
        println!("       << 2 >>");
        x86_64::instructions::hlt();
    }
}

/// Function called by the bootloader
/// via _start entry point declared in entry_point! above
///
/// Inputs
///  BootInfo    Bootloader memory mapping information
///
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    println!("Hello World{}", "!");

    blog_os::init();

    // Set up memory and kernel heap with allocator
    memory::init(boot_info);



    #[cfg(test)]
    test_main();

    // Launch the main kernel thread
    // which will be scheduled and take over from here
    process::new_kernel_thread(kernel_thread_main);

    blog_os::hlt_loop();
}

/// This function is called on panic.
#[cfg(not(test))]  // If not in QEMU test mode
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    blog_os::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    blog_os::test_panic_handler(info)
}

#[test_case]
fn trivial_assertion() {
    assert_eq!(1, 1);
}
