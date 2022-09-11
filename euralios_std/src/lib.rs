#![no_std]
#![cfg_attr(test, no_main)]
#![feature(alloc_error_handler)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::arch::asm;
pub mod syscalls;
pub mod debug;
pub mod memory;
pub mod net;
pub mod message;
pub mod ports;
pub mod thread;
pub mod time;
pub mod io;
pub mod fs;
pub mod path;
pub mod ffi;

use core::panic::PanicInfo;
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    debug_println!("User panic: {}", info);
    syscalls::thread_exit();
}

// User program entry point
#[cfg(not(test))]
extern {
    fn main() -> ();
}

#[no_mangle]
pub unsafe extern "sysv64" fn _start() -> ! {
    // Information passed from the operating system
    let heap_start: usize;
    let heap_size: usize;
    asm!("",
         lateout("rax") heap_start,
         lateout("rcx") heap_size,
         options(pure, nomem, nostack)
    );
    memory::init(heap_start, heap_size);

    // Call the user program
    #[cfg(not(test))]
    main();

    #[cfg(test)]
    test_main();

    syscalls::thread_exit();
}

// Custom test framework

pub trait Testable {
    fn run(&self) -> ();
}

// Implement Testable trait for all types with Fn() trait
impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        print!("{}...\t", core::any::type_name::<T>());
        self();
        println!("[ok]");
    }
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Testable]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
}
