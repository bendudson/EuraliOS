#![no_std]
#![no_main]

use core::ptr;
use euralios_std::{debug_println,
                   syscalls::{self, MemoryHandle, STDIN},
                   net::MacAddress,
                   message::{self, rcall, pci, MessageData},
                   ports::{outportb, outportw, outportd,
                           inportb, inportw, inportd}};

use core::str;

#[no_mangle]
fn main() {
    debug_println!("[rtl8139] Starting driver");

    let handle = syscalls::open("/pci").expect("Couldn't open pci");

    // Use PCI program to look for device
    let (msg_type, md_address, _) = rcall(&handle, pci::FIND_DEVICE,
                                          0x10EC.into(), 0x8139.into(),
                                          None).unwrap();
    let address = md_address.value();
    if msg_type != pci::ADDRESS {
        debug_println!("[rtl8139] Device not found. Exiting.");
        return;
    }
    debug_println!("[rtl8139] Found at address: {:08X}", address);

    // Enable bus mastering so the card can access main memory
    syscalls::send(&handle, syscalls::Message::Short(
        pci::ENABLE_BUS_MASTERING, address, 0)).unwrap();

    // Read BAR0 to get the I/O address
    let (_, md_bar0, _) = rcall(&handle, pci::READ_BAR,
                                address.into(), 0.into(),
                                Some(pci::BAR)).unwrap();
    let bar0 = md_bar0.value();
    let ioaddr = (bar0 & 0xFFFC) as u16;
    debug_println!("[rtl8139] BAR0: {:08X}. I/O addr: {:04X}", bar0, ioaddr);

    let mut device = {
        // Allocate memory for receive buffer
        let (rx_buffer, rx_buffer_physaddr) =
            syscalls::malloc(8192 + 16, 0xFFFF_FFFF).unwrap();

        // Allocate transmit buffers
        // Initializing arrays in Rust is awkward, so just repeat 4 times
        let (tx1, tx1_addr) = syscalls::malloc(TX_BUFFER_LEN as u64, 0xFFFF_FFFF).unwrap();
        let (tx2, tx2_addr) = syscalls::malloc(TX_BUFFER_LEN as u64, 0xFFFF_FFFF).unwrap();
        let (tx3, tx3_addr) = syscalls::malloc(TX_BUFFER_LEN as u64, 0xFFFF_FFFF).unwrap();
        let (tx4, tx4_addr) = syscalls::malloc(TX_BUFFER_LEN as u64, 0xFFFF_FFFF).unwrap();
        Device{ioaddr,
               rx_buffer,
               rx_buffer_physaddr: (rx_buffer_physaddr as u32),
               tx_buffer: [tx1, tx2, tx3, tx4],
               tx_buffer_physaddr: [tx1_addr as u32, tx2_addr as u32,
                                    tx3_addr as u32, tx4_addr as u32],
               active_tx_id: 0}};

    match device.reset() {
        Ok(()) => debug_println!("[rtl8139] Device reset OK"),
        Err(message) => {
            debug_println!("[rtl8139] Device failed to reset: {}", message);
            return;
        }
    }

    debug_println!("[rtl8139] MAC address {}", device.mac_address());

    // Server loop. Note: Single threaded for now
    loop {
        match syscalls::receive(&STDIN) {
            Ok(message) => {
                match message {
                    syscalls::Message::Short(
                        message::READ, _, _) => {

                        // Check if a packet has been received
                        if let Some((length, handle)) = device.receive_packet() {
                            // Received data in a MemoryHandle
                            // -> Send back
                            syscalls::send(
                                &STDIN,
                                syscalls::Message::Long(
                                    message::DATA, (length as u64).into(), handle.into()));
                        } else {
                            // No packet to read
                            syscalls::send(
                                &STDIN,
                                syscalls::Message::Short(
                                    message::EMPTY, 0, 0));
                        }
                    }
                    syscalls::Message::Long(
                        message::WRITE,
                        MessageData::Value(length),
                        MessageData::MemoryHandle(handle)) => {
                        device.send_packet(length as u16, handle);
                    }

                    syscalls::Message::Short(
                        message::nic::GET_MAC_ADDRESS, _, _) => {

                        let address = device.mac_address();
                        syscalls::send(
                                &STDIN,
                                syscalls::Message::Short(
                                    message::nic::MAC_ADDRESS,
                                    address.as_u64(), 0));
                    }
                    _ => {
                        debug_println!("[rtl8139] unknown message {:?}", message);
                    }
                }
            }
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&STDIN,
                               syscalls::Message::Short(
                                   0, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(code) => {
                debug_println!("[rtl8139] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}

const REG_TBSTART: u16 = 0x20; // 32-bit
const REG_RBSTART: u16 = 0x30; // 32-bit physical memory address
const REG_CMD: u16 = 0x37;  // 8-bit
const REG_CAPR: u16 = 0x38; // 16-bit
const REG_CBR: u16 = 0x3A;  // 16-bit
const REG_IMR: u16 = 0x3C;  // Interrupt Mask Register
const REG_ISR: u16 = 0x3E;
const REG_TX_CONFIG: u16 = 0x40; // Transmit buffer configuration
const REG_RX_CONFIG: u16 = 0x44; // Receive buffer configuration
const REG_CONFIG_1: u16 = 0x52;

const RX_BUFFER_PAD: u64 = 16;
const TX_BUFFER_LEN: u16 = 1792; // Maximum data length

// Interframe Gap Time
const TCR_IFG: u32 = 3 << 24;
// Max DMA Burst Size per Tx DMA Burst
// 000 = 16 bytes
// 001 = 32 bytes
// 010 = 64 bytes
// 011 = 128 bytes
// 100 = 256 bytes
// 101 = 512 bytes
// 110 = 1024 bytes
// 111 = 2048 bytes
const TCR_MXDMA0: u32 = 1 << 8;
const TCR_MXDMA1: u32 = 1 << 9;
const TCR_MXDMA2: u32 = 1 << 10;

const CR_BUFFER_EMPTY: u8 = 1;

const ROK: u16 = 0x01;
const TOK: u32 = 1 << 15; // Transmit OK

const TOWN: u32 = 1 << 13; // DMA operation completed

struct Device {
    ioaddr: u16,

    // Receive buffer
    rx_buffer: MemoryHandle,
    rx_buffer_physaddr: u32,

    // Transmit buffers
    tx_buffer: [MemoryHandle; 4],
    tx_buffer_physaddr: [u32; 4],

    // The currently active transmit buffer
    active_tx_id: usize
}

impl Device {
    /// Perform a software reset
    ///
    /// Note: Comments from the OSDev wiki
    ///      <https://wiki.osdev.org/RTL8139>
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
        while (inportb(self.ioaddr + 0x37) & 0x10) != 0 {
            retry += 1;
            if retry > MAX_ATTEMPTS {
                return Err("Timeout");
            }
            // Wait for a bit
            syscalls::thread_yield();
        }

        // Set the receive buffer
        outportd(self.ioaddr + REG_RBSTART, self.rx_buffer_physaddr);

        // Set transmit buffer addresses
        for (i, addr) in self.tx_buffer_physaddr.iter().enumerate() {
            outportd(self.ioaddr + REG_TBSTART + 4 * (i as u16), *addr);
        }

        // Set Interrupt Mask Register
        outportw(self.ioaddr + REG_IMR, 0x0005); // Sets the TOK and ROK bits high

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

        // Configure transmit buffer
        outportd(self.ioaddr + REG_TX_CONFIG,
                 TCR_IFG | TCR_MXDMA0 | TCR_MXDMA1 | TCR_MXDMA2);

        // Enable receive and transmitter
        outportb(self.ioaddr + REG_CMD, 0x0C); // Sets the RE and TE bits high

        Ok(())
    }

    /// Read the Media Access Control (MAC) address
    /// from the network card.
    fn mac_address(&self) -> MacAddress {
        let mut octet: [u8; 6] = [0; 6];
        for ind in 0..octet.len() {
            octet[ind] = inportb(self.ioaddr + ind as u16);
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
    ///
    /// The handle returned will not contain the header or length
    /// so starts with the packet and includes CRC
    fn receive_packet(&self) -> Option<(u16, MemoryHandle)> {
        if inportb(self.ioaddr + REG_CMD) & CR_BUFFER_EMPTY
            == CR_BUFFER_EMPTY {
                return None
            }
        debug_println!("[rtl8139] Received packet");

        let capr = inportw(self.ioaddr + REG_CAPR);
        let cbr = inportw(self.ioaddr + REG_CBR);

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
        let src_data = (self.rx_buffer.as_u64() + offset + 4) as *const u8;

        // Copy data into a separate memory chunk which can be
        // sent to other processes. Use malloc syscall to get a MemoryHandle.
        let (mem_handle, _) = syscalls::malloc(length as u64, 0).ok()?;

        let dest_data = mem_handle.as_u64() as *mut u8;
        unsafe{
            ptr::copy_nonoverlapping(src_data, dest_data,
                                     length as usize);
        }

        // Update buffer read pointer
        let rx_offset = ((offset as u16) + length + 4 + 3) & !3;
        outportw(self.ioaddr + REG_CAPR,
                 rx_offset - (RX_BUFFER_PAD as u16));

        Some((length, mem_handle))
    }

    /// Send a packet to the device
    ///
    /// handle should point to memory containing
    ///   - length : u16
    ///   - data : [u8; length]
    ///
    fn send_packet(&mut self, length: u16, handle: MemoryHandle) -> Result<(), ()> {
        if length > TX_BUFFER_LEN {
            debug_println!("Packet too large to transmit: {} bytes", length);
            return Err(());
        }

        let cmd_port = (0x10 + (self.active_tx_id << 2)) as u16;

        // Check that the buffer can be written to
        while inportd(self.ioaddr + cmd_port) & TOWN != TOWN {
            // Wait a bit
            syscalls::thread_yield();
        }
        // OWN bit now set to 1 => Can write to buffer

        let src_data = handle.as_u64() as *const u8;
        let dest_data = self.tx_buffer[self.active_tx_id].as_u64() as *mut u8;
        unsafe{
            ptr::copy_nonoverlapping(src_data, dest_data,
                                     length as usize);
        }

        // Set OWN bit low
        // Note: length is stored in the first 13 bits;
        //       the rest of the bits can be set low
        outportd(self.ioaddr + cmd_port, (length & 0x1FFF) as u32);

        // Move to the next buffer in round robin
        self.active_tx_id = (self.active_tx_id + 1) % 4;

        debug_println!("[rtl8139] Sent packet {} bytes", length);

        Ok(())
    }
}
