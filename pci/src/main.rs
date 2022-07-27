//! EuraliOS PCI bus driver
//!
//!Code based on
//!  - MOROS : <https://github.com/vinc/moros/blob/trunk/src/sys/pci.rs>
//!  - Theseus : <https://github.com/theseus-os/Theseus/blob/theseus_main/kernel/pci/src/lib.rs>
//!
//! Reference:
//! - OSdev: <http://wiki.osdev.org/PCI#PCI_Device_Structure>

#![no_std]
#![no_main]

use core::arch::asm;
use euralios_std::{debug_println, syscalls, message::pci,
                   syscalls::STDIN};
use core::fmt;

extern crate alloc;
use alloc::vec::Vec;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

#[derive(Clone, Copy)]
struct PciLocation {
    bus:  u16,
    slot: u16,
    function: u16
}

impl fmt::Display for PciLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
           write!(f, "{:04X}:{:02X}:{:02X}",
                  self.bus, self.slot, self.function)
    }
}

impl PciLocation {
    fn from_address(address: u32) -> PciLocation {
        PciLocation{
            function:((address >> 8) & 0b111) as u16,
            slot:((address >> 11) & 0b1_1111) as u16,
            bus:((address >> 16) & 0xFF) as u16
        }
    }

    /// Return PCI bus address
    fn address(&self) -> u32 {
        0x8000_0000
            | ((self.bus  as u32) << 16)
            | ((self.slot as u32) << 11)
            | ((self.function as u32) <<  8)
    }

    fn read_register(&self, register: u8) -> u32 {
        let addr = self.address()
            | ((register as u32) << 2);

        let value: u32;
        unsafe {
            asm!("out dx, eax",
                 in("dx") CONFIG_ADDRESS,
                 in("eax") addr,
                 options(nomem, nostack));

            asm!("in eax, dx",
                 in("dx") CONFIG_DATA,
                 lateout("eax") value,
                 options(nomem, nostack));
        }
        value
    }

    fn write_register(&self, register: u8, value: u32) {
        let addr = self.address()
            | ((register as u32) << 2);

        unsafe {
            asm!("out dx, eax",
                 in("dx") CONFIG_ADDRESS,
                 in("eax") addr,
                 options(nomem, nostack));

            asm!("out dx, eax",
                 in("dx") CONFIG_DATA,
                 in("eax") value,
                 options(nomem, nostack));
        }
    }

    /// Return the Device which is at this PCI bus location
    /// May return None if there is no device
    fn get_device(&self) -> Option<Device> {
        let reg_0 = self.read_register(0);
        if reg_0 == 0xFFFF_FFFF {
            return None // No device
        }

        let vendor_id = (reg_0 & 0xFFFF) as u16;
        let device_id = (reg_0 >> 16) as u16;

        let reg_2 = self.read_register(2);

        let revision_id = (reg_2 & 0xFF) as u8;
        let prog_if = ((reg_2 >> 8) & 0xFF) as u8;
        let subclass = ((reg_2 >> 16) & 0xFF) as u8;
        let class = ((reg_2 >> 24) & 0xFF) as u8;
        Some(Device {
            location: self.clone(),
            vendor_id,
            device_id,
            class,
            subclass,
            prog_if,
            revision_id
        })
    }
}

/// Information about a PCI device
struct Device {
    location: PciLocation,
    vendor_id: u16, // Identifies the manufacturer of the device
    device_id: u16, // Identifies the particular device. Valid IDs are allocated by the vendor
    class: u8, // The type of function the device performs
    subclass: u8, // The specific function the device performs
    prog_if: u8, // register-level programming interface, if any
    revision_id: u8 // revision identifier. Valid IDs are allocated by the vendor
}

impl Device {
    fn class_str(&self) -> &'static str {
        match self.class {
            0x0 => match self.subclass {
                0 => "Non-VGA-Compatible Unclassified Device",
                1 => "VGA-Compatible Unclassified Device",
                _ => "Unknown",
            },
            0x1 => match self.subclass {
                0x0 => "SCSI Bus Controller",
                0x1 => "IDE Controller",
                0x2 => "Floppy Disk Controller",
                0x3 => "IPI Bus Controller",
                0x4 => "RAID Controller",
                0x5 => "ATA Controller",
                0x6 => "Serial ATA Controller",
                0x7 => "Serial Attached SCSI Controller",
                0x8 => "Non-Volatile Memory Controller",
                _ => "Mass Storage Controller"
            }
            0x2 => match self.subclass {
                0x0 => "Ethernet Controller",
                0x1 => "Token Ring Controller",
                0x2 => "FDDI Controller",
                0x3 => "ATM Controller",
                0x4 => "ISDN Controller",
                0x5 => "WorldFip Controller",
                0x6 => "PICMG 2.14 Multi Computing Controller",
                0x7 => "Infiniband Controller",
                0x8 => "Fabric Controller",
                _ => "Network Controller"
            }
            0x3 => match self.subclass {
                0x0 => "VGA Compatible Controller",
                0x1 => "XGA Controller",
                0x2 => "3D Controller (Not VGA-Compatible)",
                _ => "Display Controller"
            }
            0x4 => match self.subclass {
                0x0 => "Multimedia Video Controller",
                0x1 => "Multimedia Audio Controller",
                0x2 => "Computer Telephony Device",
                0x3 => "Audio Device",
                _ => "Multimedia Controller"
            }
            0x5 => match self.subclass {
                0x0 => "RAM Controller",
                0x1 => "Flash Controller",
                _ => "Memory Controller"
            }
            0x6 => match self.subclass {
                0x0 => "Host Bridge",
                0x1 => "ISA Bridge",
                0x2 => "EISA Bridge",
                0x3 => "MCA Bridge",
                0x4 => "PCI-to-PCI Bridge",
                0x5 => "PCMCIA Bridge",
                0x6 => "NuBus Bridge",
                0x7 => "CardBus Bridge",
                0x8 => "RACEway Bridge",
                0x9 => "PCI-to-PCI Bridge",
                0xA => "InfiniBand-to-PCI Host Bridge",
                _ => "Bridge"
            }
            _ => "Unknown"
        }
    }
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} [{:04X}:{:04X}] {}",
               self.location, self.vendor_id, self.device_id, self.class_str())
    }
}

#[no_mangle]
fn main() {

    let mut devices = Vec::new();

    // Brute force check of all PCI slots
    for bus in 0..256 {
        for slot in 0..32 {
            if let Some(device) = (
                PciLocation{bus,
                            slot,
                            function:0}).get_device() {
                debug_println!("[pci] Device {}", device);
                devices.push(device);
            }
        }
    }

    // Enter loop waiting for messages
    loop {
        match syscalls::receive(&STDIN) {
            Ok(message) => {
                match message {
                    // Find a device with given vendor and device ID
                    // and return a message to the same Rendezvous
                    syscalls::Message::Short(
                        pci::FIND_DEVICE, vendor, device) => {
                        let vendor_id = (vendor & 0xFFFF) as u16;
                        let device_id = (device & 0xFFFF) as u16;

                        debug_println!("[pci] Finding device [{:04X}:{:04X}]",
                                       vendor_id, device_id);

                        if let Some(device) = devices.iter().find(
                            |&d| d.vendor_id == vendor_id &&
                                d.device_id == device_id) {

                            syscalls::send(&STDIN,
                                           syscalls::Message::Short(
                                               pci::ADDRESS,
                                               device.location.address() as u64,
                                               0));
                        } else {
                            // Not found
                            syscalls::send(&STDIN,
                                           syscalls::Message::Short(
                                               pci::NOTFOUND,
                                               0xFFFF_FFFF_FFFF_FFFF, 0));
                        }
                    }

                    // Read Base Address Register
                    syscalls::Message::Short(
                        pci::READ_BAR, address, bar_id) => {

                        if address > 0xFFFF_FFFF || bar_id > 5 {
                            // Out of range
                            syscalls::send(&STDIN,
                                           syscalls::Message::Short(
                                               pci::NOTFOUND,
                                               0xFFFF_FFFF_FFFF_FFFF, 0));
                            continue;
                        }

                        let bar_value =
                            PciLocation::from_address(address as u32)
                            .read_register(4 + bar_id as u8);

                        syscalls::send(&STDIN,
                                       syscalls::Message::Short(
                                           pci::BAR,
                                           bar_value as u64, bar_id));
                    }
                    // Enable bus mastering, allowing a device to use DMA
                    // https://github.com/vinc/moros/blob/trunk/src/sys/pci.rs#L74
                    syscalls::Message::Short(
                        pci::ENABLE_BUS_MASTERING, address, _) => {
                        let location = PciLocation::from_address(address as u32);

                        // Read the command register (1),
                        location.write_register(1,
                                                location.read_register(1) | (1 << 2));
                    }
                    _ => {}
                }
            },
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&STDIN,
                               syscalls::Message::Short(
                                   pci::NOTFOUND,
                                   0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(code) => {
                debug_println!("[pci] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}
