#![no_std]
#![no_main]

use euralios_std::{println,
                   syscalls::{self, STDIN}};

#[no_mangle]
fn main() {
    println!("[ramdisk] Hello, world!");
}
