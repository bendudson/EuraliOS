#![no_std]
#![no_main]

use euralios_std::{println,
                   syscalls,
                   message::{self, rcall, pci, MessageData}};

#[no_mangle]
fn main() {
    println!("[virtio-net] Starting driver");

    let handle = syscalls::open("/pci", message::O_READ).expect("Couldn't open pci");

    // Use PCI program to look for device
    let (msg_type, md_address, _) = rcall(&handle, pci::FIND_DEVICE,
                                          0x1AF4.into(), 0x1000.into(),
                                          None).unwrap();
    let address = md_address.value();
    if msg_type != pci::ADDRESS {
        println!("[virtio-net] Device not found. Exiting.");
        return;
    }
    println!("[virtio-net] Found at address: {:08X}", address);

}
