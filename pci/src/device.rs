
use core::arch::asm;
use core::fmt;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

#[derive(Clone, Copy)]
pub struct PciLocation {
    pub bus:  u16,
    pub slot: u16,
    pub function: u16
}

impl fmt::Display for PciLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04X}:{:02X}:{:02X}",
               self.bus, self.slot, self.function)
    }
}

impl PciLocation {
    pub fn from_address(address: u32) -> PciLocation {
        PciLocation{
            function:((address >> 8) & 0b111) as u16,
            slot:((address >> 11) & 0b1_1111) as u16,
            bus:((address >> 16) & 0xFF) as u16
        }
    }

    /// Return PCI bus address
    pub fn address(&self) -> u32 {
        0x8000_0000
            | ((self.bus  as u32) << 16)
            | ((self.slot as u32) << 11)
            | ((self.function as u32) <<  8)
    }

    pub fn read_register(&self, register: u8) -> u32 {
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

    pub fn write_register(&self, register: u8, value: u32) {
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
    pub fn get_device(&self) -> Option<Device> {
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
pub struct Device {
    pub location: PciLocation,
    pub vendor_id: u16, // Identifies the manufacturer of the device
    pub device_id: u16, // Identifies the particular device. Valid IDs are allocated by the vendor
    pub class: u8, // The type of function the device performs
    pub subclass: u8, // The specific function the device performs
    pub prog_if: u8, // register-level programming interface, if any
    pub revision_id: u8, // revision identifier. Valid IDs are allocated by the vendor
    pub header_type: u8,
    pub subsystem_id: u16
}

impl Device {
    pub fn class_str(&self) -> &'static str {
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
