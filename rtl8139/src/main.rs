#![no_std]
#![no_main]

use euralios_std::debug_println;

#[no_mangle]
fn main() {
    debug_println!("Hello world!");
}
