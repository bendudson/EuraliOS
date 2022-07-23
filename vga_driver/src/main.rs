#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   syscalls};

#[no_mangle]
fn main() {
    debug_println!("[vga] Hello, world!");
}
