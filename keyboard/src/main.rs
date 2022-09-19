#![no_std]
#![no_main]

use euralios_std::{println, syscalls};

#[no_mangle]
fn main() {
    println!("Hello, world!");

    loop {
        syscalls::await_interrupt();
        println!("Interrupt!");
    }
}
