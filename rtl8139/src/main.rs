#![no_std]
#![no_main]

use euralios_std::{debug_println, syscalls};

#[no_mangle]
fn main() {
    debug_println!("rtl8139");

    let handle = syscalls::open("/pci").expect("Couldn't open");
    debug_println!("{}", handle);

    syscalls::send(handle,
                   syscalls::Message::Short(
                       0, 'X' as u64, 0));
}
