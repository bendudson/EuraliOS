#![no_std]
#![feature(alloc_error_handler)]

use core::arch::asm;
pub mod syscalls;
pub mod debug;
pub mod memory;
pub mod net;
pub mod message;
pub mod ports;
pub mod thread;

use core::panic::PanicInfo;
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    debug_println!("User panic: {}", info);
    syscalls::thread_exit();
}

// User program entry point
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
    main();

    syscalls::thread_exit();
}

