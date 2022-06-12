#![no_std]
#![no_main]

use euralios_std::{debug_println, syscalls, syscalls::Message};

#[no_mangle]
fn main() {
    loop{
        let msg = syscalls::receive(0).unwrap();
        let value = match msg {
            Message::Short(_, value, _) => value,
            _ => 0
        };
        let ch = char::from_u32(value as u32).unwrap();
        debug_println!("Received: {} => {}", value, ch);
        if ch == 'x' {
            debug_println!("Exiting");
            break;
        }
        syscalls::send(1, msg).unwrap();
    }
}
