//! EuraliOS PCI bus driver
//!
//! Code initially based on
//!  - MOROS : <https://github.com/vinc/moros/blob/trunk/src/sys/pci.rs>
//!  - Theseus : <https://github.com/theseus-os/Theseus/blob/theseus_main/kernel/pci/src/lib.rs>
//!
//! Reference:
//! - OSdev: <http://wiki.osdev.org/PCI#PCI_Device_Structure>

#![no_std]
#![no_main]

use core::arch::asm;
use core::str;

use euralios_std::{println, syscalls, message::pci,
                   message::{self, Message},
                   server::{FileLike, DirLike, handle_directory},
                   syscalls::STDIN};
use core::fmt;

extern crate alloc;
use alloc::collections::btree_map::BTreeMap;
use alloc::{string::String, sync::Arc};
use alloc::format;

use spin::RwLock;

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

        let reg_3 = self.read_register(3);

        let header_type = ((reg_3 >> 16) & 0xFF) as u8;

        let subsystem_id = if header_type == 0 {
            let reg_B = self.read_register(0xB);
            ((reg_B >> 16) & 0xFFFF) as u16
        } else { 0 };

        Some(Device {
            location: self.clone(),
            vendor_id,
            device_id,
            class,
            subclass,
            prog_if,
            revision_id,
            header_type,
            subsystem_id
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
    revision_id: u8, // revision identifier. Valid IDs are allocated by the vendor
    header_type: u8,
    subsystem_id: u16
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

impl DirLike for Device {
    fn get_dir(&self, _name: &str) -> Result<Arc<RwLock<dyn DirLike + Send + Sync>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOTFOUND)
    }
    fn get_file(&self, _name: &str) -> Result<Arc<RwLock<dyn FileLike + Send + Sync>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOTFOUND)
    }
    fn query(&self) -> String {
        format!("{{
\"name\": \"{vendor_id:04X}_{device_id:04X}\",
\"description\": \"{self}\",
\"address\": \"0x{address:0X}\",
\"vendor_id\": \"0x{vendor_id:04X}\",
\"device_id\": \"0x{device_id:04X}\",
\"class\": {class},
\"subclass\": {subclass},
\"subsystem_id\": {subsystem_id}
\"subdirs\": [],
\"files\": []}}",
                address = self.location.address() as u64,
                vendor_id = self.vendor_id,
                device_id = self.device_id,
                class = self.class,
                subclass = self.subclass,
                subsystem_id = self.subsystem_id)
    }
}

struct DeviceCollection {
    devices: BTreeMap<String, Arc<RwLock<Device>>>
}

impl DeviceCollection {
    fn new() -> Self {
        Self{devices: BTreeMap::new()}
    }

    fn insert(&mut self, device: Device) {
        self.devices.insert(format!("{:04X}_{:04X}]",
                                    device.vendor_id, device.device_id),
                            Arc::new(RwLock::new(device)));
    }

    fn find(&self, vendor_id: u16, device_id:u16) -> Option<PciLocation> {
        println!("[pci] Finding device [{:04X}:{:04X}]",
                 vendor_id, device_id);

        if let Some((_key, device)) = self.devices.iter().find(
            |&(_key, d)| {
                let d = d.read();
                d.vendor_id == vendor_id &&
                    d.device_id == device_id}) {
            Some(device.read().location)
        } else {
            None
        }
    }
}

impl DirLike for DeviceCollection {
    /// Each subdirectory is a PCI Device
    fn get_dir(&self, name: &str) -> Result<Arc<RwLock<dyn DirLike + Send + Sync>>, syscalls::SyscallError> {
        match self.devices.get(name) {
            Some(device) => Ok(device.clone()),
            None => Err(syscalls::SYSCALL_ERROR_NOTFOUND)
        }
    }
    /// No files; always returns not found error
    fn get_file(&self, _name: &str) -> Result<Arc<RwLock<dyn FileLike + Send + Sync>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOTFOUND)
    }
    fn query(&self) -> String {
        // Make a list of devices
        let device_list = {
            let mut s = String::new();
            let mut it = self.devices.iter().peekable();
            while let Some((_name, device)) = it.next() {
                s.push_str(&device.read().query());

                if it.peek().is_some() {
                    s.push_str(", ");
                }
            }
            s
        };

        format!("{{
\"short\": \"PCI\",
\"description\": \"PCI bus devices\",
\"messages\": [{{\"name\": \"find_device\",
                 \"tag\": {find_device_tag}}},
               {{\"name\": \"read_bar\",
                 \"tag\": {read_bar_tag}}},
               {{\"name\": \"query\",
                 \"tag\": {query_tag}}}],
\"subdirs\": [{device_list}],
\"files\": []}}",
                find_device_tag = pci::FIND_DEVICE,
                read_bar_tag = pci::READ_BAR,
                query_tag = message::QUERY,
                device_list = device_list)
    }
}

#[no_mangle]
fn main() {

    let mut devices = DeviceCollection::new();

    // Brute force check of all PCI slots
    for bus in 0..256 {
        for slot in 0..32 {
            if let Some(device) = (
                PciLocation{bus,
                            slot,
                            function:0}).get_device() {
                println!("[pci] Device {}", device);
                devices.insert(device);
            }
        }
    }

    let devices = Arc::new(RwLock::new(devices));

    handle_directory(
        devices.clone(),
        STDIN.clone(),
        true, // Read-write
        |msg| {
            // Messages not handled
            match msg {
                // Find a device with given vendor and device ID
                // and return a message to the same Rendezvous
                Message::Short(
                    pci::FIND_DEVICE, vendor, device) => {

                    if let Some(location) = devices.read().find((vendor & 0xFFFF) as u16,
                                                                (device & 0xFFFF) as u16) {
                        syscalls::send(&STDIN,
                                       syscalls::Message::Short(
                                           pci::ADDRESS,
                                           location.address() as u64,
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
                Message::Short(
                    pci::READ_BAR, address, bar_id) => {

                    if address > 0xFFFF_FFFF || bar_id > 5 {
                        // Out of range
                        syscalls::send(&STDIN,
                                       syscalls::Message::Short(
                                           pci::NOTFOUND,
                                           0xFFFF_FFFF_FFFF_FFFF, 0));
                        return;
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
                Message::Short(
                    pci::ENABLE_BUS_MASTERING, address, _) => {
                    let location = PciLocation::from_address(address as u32);

                    // Read the command register (1),
                    location.write_register(1,
                                            location.read_register(1) | (1 << 2));
                }

                message => {
                    println!("[pci] Received unexpected message {:?}", message);
                }
            }
        });
}
