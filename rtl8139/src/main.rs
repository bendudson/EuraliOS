#![no_std]
#![no_main]

use core::arch::asm;
use euralios_std::{debug_println,
                   syscalls,
                   net::MacAddress,
                   message::rcall,
                   message::pci};

#[no_mangle]
fn main() {
    debug_println!("[rtl8139] Starting driver");

    let handle = syscalls::open("/pci").expect("Couldn't open pci");

    // Use PCI program to look for device
    let (msg_type, address, _) = rcall(&handle, pci::FIND_DEVICE,
                                       0x10EC, 0x8139,
                                       None).unwrap();
    if msg_type != pci::ADDRESS {
        debug_println!("[rtl8139] Device not found. Exiting.");
        return;
    }
    debug_println!("[rtl8139] Found at address: {:08X}", address);

    // Read BAR0 to get the I/O address
    let (_, bar0, _) = rcall(&handle, pci::READ_BAR,
                             address, 0,
                             Some(pci::BAR)).unwrap();
    let ioaddr = (bar0 & 0xFFFC) as u16;
    debug_println!("[rtl8139] BAR0: {:08X}. I/O addr: {:04X}", bar0, ioaddr);
    let mut device = Device{ioaddr};

    match device.reset() {
        Ok(()) => debug_println!("[rtl8139] Device reset OK"),
        Err(message) => {
            debug_println!("[rtl8139] Device failed to reset: {}", message);
            return;
        }
    }

    debug_println!("[rtl8139] MAC address {}", device.mac_address());

    let result = syscalls::malloc(8192 + 16, 0xFFFF_FFFF);
    debug_println!("Received: {:?}", result);
}

fn outportb(ioaddr: u16, value: u8) {
    unsafe {
        asm!("out dx, al",
             in("dx") ioaddr,
             in("al") value,
             options(nomem, nostack));
    }
}

fn inb(ioaddr: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx",
             in("dx") ioaddr,
             lateout("al") value,
             options(nomem, nostack));
    }
    value
}

const REG_CONFIG_1: u16 = 0x52;
const REG_CMD: u16 = 0x37;

struct Device {
    ioaddr: u16,
}

impl Device {
    /// Perform a software reset
    ///
    /// Note: Comments from the OSDev wiki
    ///       https://wiki.osdev.org/RTL8139
    fn reset(&mut self) -> Result<(), &'static str> {

        // Send 0x00 to the CONFIG_1 register (0x52) to set the LWAKE +
        // LWPTN to active high. this should essentially *power on* the
        // device.
        outportb(self.ioaddr + REG_CONFIG_1, 0);

        // Sending 0x10 to the Command register (0x37) will send the
        // RTL8139 into a software reset. Once that byte is sent, the RST
        // bit must be checked to make sure that the chip has finished the
        // reset. If the RST bit is high (1), then the reset is still in
        // operation.
        outportb(self.ioaddr + REG_CMD, 0x10);

        const MAX_ATTEMPTS: usize = 1000;
        let mut retry = 0;
        while (inb(self.ioaddr + 0x37) & 0x10) != 0 {
            retry += 1;
            if retry > MAX_ATTEMPTS {
                return Err("Timeout");
            }
            // Wait for a bit
            for _i in 0..100000 {
                unsafe{ asm!("nop"); }
            }
        }

        Ok(())
    }

    /// Read the Media Access Control (MAC) address
    /// from the network card.
    fn mac_address(&self) -> MacAddress {
        let mut octet: [u8; 6] = [0; 6];
        for ind in 0..octet.len() {
            octet[ind] = inb(self.ioaddr + ind as u16);
        }
        MacAddress::new(octet)
    }
}
