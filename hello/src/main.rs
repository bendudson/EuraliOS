#![no_std]
#![no_main]

use euralios_std::{debug_println, syscalls};

#[no_mangle]
fn main() {
    loop{
        let value = syscalls::receive(0).unwrap();
        let ch = char::from_u32(value as u32).unwrap();
        debug_println!("Received: {} => {}", value, ch);
        if ch == 'x' {
            debug_println!("Exiting");
            break;
        }
        syscalls::send(1, value).unwrap();
    }
}
