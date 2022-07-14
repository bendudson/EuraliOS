#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   time};

#[no_mangle]
fn main() {
    debug_println!("Hello, world! : {}", time::time_stamp_counter());
}
