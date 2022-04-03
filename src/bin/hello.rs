#![no_std]
#![no_main]

use core::panic::PanicInfo;

use core::arch::asm;
use core::format_args;
use core::fmt;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

struct Writer {}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe {
            asm!("mov rax, 1", // syscall function
                 "syscall",
                 in("rdi") s.as_ptr(), // First argument
                 in("rsi") s.len()); // Second argument
        }
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    Writer{}.write_fmt(args).unwrap();
}

macro_rules! print {
    ($($arg:tt)*) => {
        _print(format_args!($($arg)*));
    };
}

macro_rules! println {
    () => (print!("\n"));
    ($fmt:expr) => (print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(
        concat!($fmt, "\n"), $($arg)*));
}

#[no_mangle]
pub unsafe extern "sysv64" fn _start() -> ! {
    print!("Hello from user world! {}", 42);

    loop {
        // Note: hlt is a privileged instruction
    }
}
