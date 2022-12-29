use core::arch::asm;
use lazy_static::lazy_static;
use spin::Mutex;

/// Provides access to the PCI address space by reading and writing to ports
pub struct PciPorts {}

impl PciPorts {
    const CONFIG_ADDRESS: u16 = 0xCF8;
    const CONFIG_DATA: u16 = 0xCFC;

    /// Write to Address and Data ports
    pub fn write(&mut self, address: u32, value: u32) {
        unsafe {
            asm!("out dx, eax",
                 in("dx") Self::CONFIG_ADDRESS,
                 in("eax") address,
                 options(nomem, nostack));

            asm!("out dx, eax",
                 in("dx") Self::CONFIG_DATA,
                 in("eax") value,
                 options(nomem, nostack));
        }
    }

    /// Write to Address port, read from Data port
    /// Note: Mutates ports values so needs mut self
    pub fn read(&mut self, address: u32) -> u32 {
        let value: u32;
        unsafe {
            asm!("out dx, eax",
                 in("dx") Self::CONFIG_ADDRESS,
                 in("eax") address,
                 options(nomem, nostack));

            asm!("in eax, dx",
                 in("dx") Self::CONFIG_DATA,
                 lateout("eax") value,
                 options(nomem, nostack));
        }
        value
    }
}

lazy_static! {
    pub static ref PORTS: Mutex<PciPorts> = Mutex::new(PciPorts{});
}
