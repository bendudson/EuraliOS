#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   syscalls,
                   time};

pub struct KernelInfo {
    pit_ticks: u64, // Number of PIT ticks since restart
    last_tsc: u64, // TSC value at last pit_ticks update
    tsc_per_pit: u64, // Change in TSC ticks per PIT tick
}

const KERNELINFO_VIRTADDR: u64 = 0x4fff000;

pub fn kernel_info() -> &'static KernelInfo {
    let ptr = KERNELINFO_VIRTADDR as *const KernelInfo;
    unsafe{&(*ptr)}
}

#[no_mangle]
fn main() {
    let info = kernel_info();

    loop {
        debug_println!("[timing_test] {}, {}, {}, {}",
                       time::time_stamp_counter(),
                       info.pit_ticks, info.last_tsc, info.tsc_per_pit);
        syscalls::thread_yield();
    }
}
