#![no_std]
#![no_main]

use core::panic::PanicInfo;

use core::arch::asm;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub unsafe extern "sysv64" fn _start() -> ! {

    asm!("syscall");

    loop {
        // Note: hlt is a privileged instruction
    }
}
