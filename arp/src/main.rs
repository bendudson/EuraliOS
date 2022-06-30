#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   syscalls,
                   net::MacAddress,
                   message::{self, rcall, nic}};

#[no_mangle]
fn main() {
    debug_println!("[arp] Starting");

    // Open link to the network interface driver
    let handle = syscalls::open("/dev/nic").expect("Couldn't open /dev/nic");

    // Get the hardware MAC address
    let (_, ret, _) = rcall(&handle, nic::GET_MAC_ADDRESS,
                            0.into(), 0.into(),
                            Some(message::nic::MAC_ADDRESS)).unwrap();

    let mac_address = MacAddress::from_u64(ret.value());
    debug_println!("[arp] MAC address: {}", mac_address);
    let mac = mac_address.bytes();

    // Ethernet frame format
    // containing an ARP packet
    // https://wiki.osdev.org/Address_Resolution_Protocol
    let frame = [
        // Ethernet frame header
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC address
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // Source address
        0x08, 0x06, // Ethernet protocol type: Ipv4 = 0x0800, Arp  = 0x0806, Ipv6 = 0x86DD
        // ARP packet
        0, 1, // u16 Hardware type (Ethernet is 0x1)
        8, 0, // u16 Protocol type (IP is 0x0800)
        6,    // u8 hlen, Hardware address length (Ethernet = 6)
        4,    // u8 plen, Protocol address length (IPv4 = 4)
        0, 1, // u16 ARP Operation Code (ARP request = 0x0001)
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // Source hardware address - hlen bytes
        10, 0, 2, 15,  // Source protocol address - plen bytes
        0, 0, 0, 0, 0, 0, // Destination hardware address
        10, 0, 2, 2    // Destination protocol address
    ];

    // Copy packet into a memory chunk that can be sent
    let mem_handle = syscalls::MemoryHandle::from_u8_slice(&frame);

    syscalls::send(&handle,
                   message::Message::Long(
                       message::WRITE,
                       (frame.len() as u64).into(),
                       mem_handle.into()));

    // Wait for a packet
    loop {
        match rcall(&handle, message::READ,
                    0.into(), 0.into(),
                    None).unwrap() {
            (message::DATA, md_length, md_handle) => {
                // Get the memory handle
                let handle = md_handle.memory();

                // Get the ethernet frame via a &[u8] slice
                let frame = handle.as_slice::<u8>(md_length.value() as usize);
                let from_mac = MacAddress::new(frame[0..6].try_into().unwrap());
                let to_mac = MacAddress::new(frame[6..12].try_into().unwrap());
                debug_println!("Ethernet frame: to {} from {} type {:02x}{:02x}",
                               from_mac, to_mac, frame[12], frame[13]);

                // ARP packet
                let arp = &frame[14..];

                debug_println!("ARP packet: hw {:02x}{:02x} protocol {:02x}{:02x} hlen {:02x} plen {:02x} op {:02x}{:02x}",
                               arp[0], arp[1], arp[2], arp[3], arp[4], arp[5], arp[6], arp[7]);
                debug_println!("            source {} / {}.{}.{}.{}",
                               MacAddress::new(arp[8..14].try_into().unwrap()), arp[14], arp[15], arp[16], arp[17]);
                debug_println!("            target {} / {}.{}.{}.{}",
                               MacAddress::new(arp[18..24].try_into().unwrap()), arp[24], arp[25], arp[26], arp[27]);
                break;
            }
            _ => {
                // Wait and retry
                syscalls::thread_yield();
            }
        }
    }
}
