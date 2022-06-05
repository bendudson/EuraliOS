#![no_std]
#![no_main]

use core::arch::asm;
use euralios_std::debug_println;

struct Device {
    vendor_id: u16,
    device_id: u16
}



#[no_mangle]
fn main() {
    debug_println!("Hello world!");

    let device_info: u32;
    let device_addr: u32 = 0x8000_0000;
    const addr_port: u16 = 0x0CF8;
    const data_port: u16 = 0x0CFC;
    unsafe {
        asm!("out dx, eax",
             in("dx") addr_port,
             in("eax") device_addr,
             options(nomem, nostack));

        asm!("in eax, dx",
             in("dx") data_port,
             lateout("eax") device_info,
             options(nomem, nostack));
    }
    let device = Device {
        vendor_id: (device_info & 0xFFFF) as u16,
        device_id: (device_info >> 16) as u16
    };

    debug_println!("Device {:04X}:{:04X}",
                   device.vendor_id, device.device_id);
}
