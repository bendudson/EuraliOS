#![no_std]
#![no_main]

use euralios_std::{debug_println, syscalls};

const MESSAGE_PCI_DEVICE: u64 = 256;
const MESSAGE_PCI_ADDRESS: u64 = 257;
const MESSAGE_PCI_NOTFOUND: u64 = 258;

#[no_mangle]
fn main() {
    debug_println!("Start rtl8139 driver");

    let handle = syscalls::open("/pci").expect("Couldn't open pci");

    // Use PCI program to look for device
    let reply = syscalls::send_receive(
        handle,
        syscalls::Message::Short(
            MESSAGE_PCI_DEVICE, 0x10EC, 0x8139)).unwrap();

    let address = match reply {
        syscalls::Message::Short(MESSAGE_PCI_ADDRESS,
                                 address, _) => {
            debug_println!("rtl8139 found at address: {:08X}", address);
            address
        }
        syscalls::Message::Short(MESSAGE_PCI_NOTFOUND,
                                 _, _) => {
            debug_println!("rtl8139 not found");
            return;
        }
        _ => {
            debug_println!("rtl8139 unexpected reply: {:?}", reply);
            return;
        }
    };

}
