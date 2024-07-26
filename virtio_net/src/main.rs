// Parts adapted from
// https://github.com/torokernel/torokernel/blob/7d6df4c40fa4cc85febd5fd5799404592ffdff53/rtl/drivers/VirtIONet.pas

#![no_std]
#![no_main]

use euralios_std::{println,
                   syscalls,
                   net::MacAddress,
                   message::{self, rcall, pci, MessageData},
                   ports::{outportb, outportw, outportd,
                           inportb, inportw, inportd}};

// Device status field, in the order the bits are typically set
const VIRTIO_RESET: u8 = 0;
const VIRTIO_ACKNOWLEDGE: u8 = 1;
const VIRTIO_DRIVER_LOADED: u8 = 2;
const VIRTIO_DRIVER_FAILED: u8 = 128;
const VIRTIO_DRIVER_FEATURES_OK: u8 = 8;
const VIRTIO_DRIVER_OK: u8 = 4;
const VIRTIO_DEVICE_NEEDS_RESET: u8 = 64;

// Feature bits
// 0 to 23, and 50 to 127 Feature bits for the specific device type
// 24 to 40 Feature bits reserved for extensions to the queue and feature negotiation mechanisms
// 41 to 49, and 128 and above Feature bits reserved for future extensions.

//const VIRTIO_F_VERSION_1

const REG_DEVICE_FEATURES: u16 = 0;
const REG_GUEST_FEATURES: u16 = 4;
const REG_STATUS: u16 = 0x12;
const REG_QUEUE_SIZE: u16 = 0x0C;
const REG_QUEUE_SELECT: u16 = 0x0E;

#[no_mangle]
fn main() {
    println!("[virtio_net] Starting driver");

    let handle = syscalls::open("/pci", message::O_READ).expect("Couldn't open pci");

    // Use PCI program to look for device
    let (msg_type, md_address, _) = rcall(&handle, pci::FIND_DEVICE,
                                          0x1AF4.into(), 0x1000.into(),
                                          None).unwrap();
    let address = md_address.value();
    if msg_type != pci::ADDRESS {
        println!("[virtio_net] Device not found. Exiting.");
        return;
    }
    println!("[virtio_net] Found at address: {:08X}", address);

    // Read BAR0 to get the I/O address
    let (_, md_bar0, _) = rcall(&handle, pci::READ_BAR,
                                address.into(), 0.into(),
                                Some(pci::BAR)).unwrap();
    let bar0 = md_bar0.value();
    let ioaddr = (bar0 & 0xFFFC) as u16;
    println!("[virtio_net] BAR0: {:08X}. I/O addr: {:04X}", bar0, ioaddr);

    let mut device = Device{ioaddr};
    device.reset();
    println!("[virtio_net] MAC address {}", device.mac_address());


}

struct Device {
    ioaddr: u16
}

impl Device {
    /// Perform a software reset
    fn reset(&mut self) -> Result<(), &'static str> {
        // reset device
        outportb(self.ioaddr + REG_STATUS, VIRTIO_RESET);

        // Wait for the device to present 0 device status
        while inportb(self.ioaddr + REG_STATUS) != VIRTIO_RESET {
            syscalls::thread_yield(); // Wait for a while
        }

        // Tell the device that we found it
        outportb(self.ioaddr + REG_STATUS, VIRTIO_ACKNOWLEDGE);
        outportb(self.ioaddr + REG_STATUS, VIRTIO_ACKNOWLEDGE | VIRTIO_DRIVER_LOADED);

        // Negotiation phase

        let features = inportd(self.ioaddr + REG_DEVICE_FEATURES);
        println!("[virtio_net] features: {:0x}", features);

        // Setup virtual queues
        for i in 0..16 {
            outportw(self.ioaddr + REG_QUEUE_SELECT, i);
            // Read the size of the queue needed
            let queue_size = inportw(self.ioaddr + REG_QUEUE_SIZE);
            if queue_size == 0 {
                continue;
            }

            println!("Queue {}: {}", i, queue_size);
        }
        Err("Incomplete")
    }

    /// Read the Media Access Control (MAC) address
    /// from the network card.
    fn mac_address(&self) -> MacAddress {
        let mut octet: [u8; 6] = [0; 6];
        for ind in 0..octet.len() {
            octet[ind] = inportb(self.ioaddr + 0x14 + ind as u16);
        }
        MacAddress::new(octet)
    }
}
