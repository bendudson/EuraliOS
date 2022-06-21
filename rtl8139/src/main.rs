#![no_std]
#![no_main]

use core::arch::asm;
use core::ptr;
use euralios_std::{debug_println,
                   syscalls,
                   syscalls::MemoryHandle,
                   net::MacAddress,
                   message::rcall,
                   message::pci};
use core::{slice, str};

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

    // Enable bus mastering so the card can access main memory
    syscalls::send(&handle, syscalls::Message::Short(
        pci::ENABLE_BUS_MASTERING, address, 0)).unwrap();

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
                            rx_buffer,
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

        for _i in 0..10000000 {
            unsafe{asm!("nop")};
        }
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

const REG_RBSTART: u16 = 0x30; // 32-bit physical memory address
const REG_CMD: u16 = 0x37;  // 8-bit
const REG_CAPR: u16 = 0x38; // 16-bit
const REG_CBR: u16 = 0x3A;  // 16-bit
const REG_IMR: u16 = 0x3C;  // Interrupt Mask Register
const REG_ISR: u16 = 0x3E;
const REG_RX_CONFIG: u16 = 0x44;
const REG_CONFIG_1: u16 = 0x52;

const RX_BUFFER_PAD: u64 = 16;

const CR_BUFFER_EMPTY: u8 = 1;

const ROK: u16 = 0x01;

struct Device {
    ioaddr: u16,
    rx_buffer: MemoryHandle,
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
        outportd(self.ioaddr + REG_RBSTART, self.rx_buffer_physaddr);

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
    ///
    /// Rx buffer, when not empty, will contain:
    /// [header            (2 bytes)]
    /// [length            (2 bytes)]
    /// [packet   (length - 4 bytes)]
    /// [crc               (4 bytes)]
    fn receive_packet(&self) -> Option<MemoryHandle> {
        if inb(self.ioaddr + REG_CMD) & CR_BUFFER_EMPTY
            == CR_BUFFER_EMPTY {
                return None
            }
        debug_println!("Received packet!");

        let capr = inw(self.ioaddr + REG_CAPR);
        let cbr = inw(self.ioaddr + REG_CBR);

        // CAPR starts at 65520 and with the pad it overflows to 0
        let offset = ((capr as u64) + RX_BUFFER_PAD) & 0xFFFF;

        let header = unsafe{*((self.rx_buffer.as_u64() + offset) as *const u16)};
        if header & ROK != ROK {
            debug_println!("    => Packet not ok");
            outportw(self.ioaddr + REG_CAPR, cbr);
            return None;
        }

        // Length of the packet
        let length = unsafe{*((self.rx_buffer.as_u64() + offset + 2) as *const u16)};

        // Receive buffer, including header (u16), length (u16) and crc (u32)
        let src_data = (self.rx_buffer.as_u64() + offset) as *const u8;

        // Copy data into a separate memory chunk which can be
        // sent to other processes. Use malloc syscall to get a MemoryHandle.
        let (mem_handle, _) = syscalls::malloc((length + 4) as u64, 0).ok()?;

        let dest_data = mem_handle.as_u64() as *mut u8;
        unsafe{
            ptr::copy_nonoverlapping(src_data, dest_data,
                                     (length + 4) as usize);
        }

        // Update buffer read pointer
        let rx_offset = ((offset as u16) + length + 4 + 3) & !3;
        outportw(self.ioaddr + REG_CAPR,
                 rx_offset - (RX_BUFFER_PAD as u16));

        Some(mem_handle)
    }
}
