#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   syscalls::{self, STDIN},
                   time};

#[no_mangle]
fn main() {
    loop {
        let _ = syscalls::receive(&STDIN);
        debug_println!("[timing_test] TSC: {} microseconds: {}",
                       time::time_stamp_counter(),
                       time::microseconds_monotonic());
        syscalls::thread_yield();
    }
}
