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


    // Allocate memory for receive buffer
    let (rx_buffer, rx_buffer_physaddr) =
        syscalls::malloc(8192 + 16, 0xFFFF_FFFF).unwrap();

    let mut device = Device{ioaddr,
                            rx_buffer_physaddr:(rx_buffer_physaddr as u32)};

    match device.reset() {
        Ok(()) => debug_println!("[rtl8139] Device reset OK"),
        Err(message) => {
            debug_println!("[rtl8139] Device failed to reset: {}", message);
            return;
        }
    }

    debug_println!("[rtl8139] MAC address {}", device.mac_address());

    loop {
        // Check if a packet has been received

        let _ = device.receive_packet();
    }
}

fn outportb(ioaddr: u16, value: u8) {
    unsafe {
        asm!("out dx, al",
             in("dx") ioaddr,
             in("al") value,
             options(nomem, nostack));
    }
}

/// Write a word (16 bits) to a port
fn outportw(ioaddr: u16, value: u16) {
    unsafe {
        asm!("out dx, ax",
             in("dx") ioaddr,
             in("ax") value,
             options(nomem, nostack));
    }
}

/// Write a double word (32 bits) to a port
fn outportd(ioaddr: u16, value: u32) {
    unsafe {
        asm!("out dx, eax",
             in("dx") ioaddr,
             in("eax") value,
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

fn inw(ioaddr: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx",
             in("dx") ioaddr,
             lateout("ax") value,
             options(nomem, nostack));
    }
    value
}

const REG_RX_ADDR: u16 = 0x30; // 32-bit physical memory address
const REG_CMD: u16 = 0x37;
const REG_CAPR: u16 = 0x38;
const REG_CBR: u16 = 0x3A;
const REG_IMR: u16 = 0x3C;  // Interrupt Mask Register
const REG_RX_CONFIG: u16 = 0x44;
const REG_CONFIG_1: u16 = 0x52;

const CR_BUFFER_EMPTY: u8 = 1;

struct Device {
    ioaddr: u16,
    rx_buffer_physaddr: u32
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

        // Set the receive buffer
        outportd(self.ioaddr + REG_RX_ADDR, self.rx_buffer_physaddr);

        // Set Interrupt Mask Register
        outportw(self.ioaddr + 0x3C, 0x0005); // Sets the TOK and ROK bits high

        // Configure receive buffer
        //
        // AB - Accept Broadcast: Accept broadcast packets
        //      sent to mac ff:ff:ff:ff:ff:ff
        // AM - Accept Multicast: Accept multicast packets.
        // APM - Accept Physical Match: Accept packets send
        //       to NIC's MAC address.
        // AAP - Accept All Packets. Accept all packets
        //       (run in promiscuous mode).
        outportd(self.ioaddr + REG_RX_CONFIG, 0xf); // 0xf is AB+AM+APM+AAP

        // Enable receive and transmitter
        outportb(self.ioaddr + REG_CMD, 0x0C); // Sets the RE and TE bits high

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

    /// Read a packet
    fn receive_packet(&self) -> Option<u64> {
        if inb(self.ioaddr + REG_CMD) & CR_BUFFER_EMPTY
            == CR_BUFFER_EMPTY {
                return None
            }
        debug_println!("Received packet!");

        Some(0)
    }
}
