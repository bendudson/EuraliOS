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

use core::str;

use euralios_std::{println, syscalls, message::pci,
                   message::{self, Message},
                   server::{FileLike, DirLike, handle_directory},
                   syscalls::STDIN};

extern crate alloc;
use alloc::collections::btree_map::BTreeMap;
use alloc::{string::String, sync::Arc};
use alloc::format;
use spin::RwLock;

mod device;
use device::{PciLocation, Device};

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
\"subsystem_id\": {subsystem_id},
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
        self.devices.insert(format!("{:04X}_{:04X}",
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
