//! EuraliOS TCP stack
//!
//! Based on code from MOROS
//! https://github.com/vinc/moros/blob/trunk/src/sys/net/mod.rs

#![no_std]
#![no_main]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::sync::Arc;
use core::str;

use smoltcp::{self, iface::{InterfaceBuilder, NeighborCache, Routes}};
use smoltcp::phy::DeviceCapabilities;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};

use euralios_std::{debug_println, debug_print,
                   syscalls::{self, STDIN},
                   net::MacAddress,
                   message::{self, rcall, nic, MessageData}};


/// Represents an ethernet device, which has a driver connected
/// through a communication handle
struct EthernetDevice {
    handle: Arc<syscalls::CommHandle>
}

impl EthernetDevice {
    fn new(handle: syscalls::CommHandle) -> Self {
        EthernetDevice{handle:Arc::new(handle)}
    }
}

/// Receive token contains packet data
struct RxToken {
    length: usize,
    data: syscalls::MemoryHandle
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self,
                     _timestamp: Instant,
                     f: F
    ) -> smoltcp::Result<R>
    where F: FnOnce(&mut [u8]) -> smoltcp::Result<R> {
        f(self.data.as_mut_slice::<u8>(self.length))
    }
}


struct TxToken {
    handle: Arc<syscalls::CommHandle>
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(mut self,
                     _timestamp: Instant,
                     length: usize, f: F
    ) -> smoltcp::Result<R> where F: FnOnce(&mut [u8]) -> smoltcp::Result<R> {
        // Allocate memory buffer
        let (mut buffer, _) = syscalls::malloc(length as u64, 0).unwrap();

        // Call function to fill buffer
        let res = f(buffer.as_mut_slice::<u8>(length));

        if res.is_ok() {
            // Transmit, sending buffer to NIC driver
            syscalls::send(
                self.handle.as_ref(),
                message::Message::Long(
                    message::WRITE,
                    (length as u64).into(),
                    buffer.into()));
        }
        res
    }
}

impl<'a> smoltcp::phy::Device<'a> for EthernetDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);
        caps
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        match message::rcall(self.handle.as_ref(),
                             message::READ,
                             0.into(), 0.into(), None) {
            Ok((message::DATA, length, data)) => {
                Some((RxToken{length:length.value() as usize,
                              data:data.memory()},
                      TxToken{handle: self.handle.clone()}))
            }
            Ok((message::EMPTY, _, _)) => None,
            value => {
                debug_println!("[tcp] received unexpected {:?}", value);
                None
            }
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken{handle: self.handle.clone()})
    }
}

pub type Interface = smoltcp::iface::Interface<'static, EthernetDevice>;

#[no_mangle]
fn main() {
    debug_println!("[tcp] Starting");

    let handle = syscalls::open("/dev/nic").expect("Couldn't open /dev/nic");

    // Get the hardware MAC address
    let (_, ret, _) = rcall(&handle, nic::GET_MAC_ADDRESS,
                            0.into(), 0.into(),
                            Some(message::nic::MAC_ADDRESS)).unwrap();

    let mac_address = MacAddress::from_u64(ret.value());
    debug_println!("[tcp] MAC address: {}", mac_address);

    // Wrap the communication handle in a type implementing
    // smoltcp's Device trait.
    let device = EthernetDevice::new(handle);

    // Initialise the smoltcp interface
    // Based on MOROS code here:
    //    https://github.com/vinc/moros/blob/trunk/src/sys/net/mod.rs#L227

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let routes = Routes::new(BTreeMap::new());

    // IP CIDR block
    let ip_addrs = [IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0)];

    let mut interface = InterfaceBuilder::new(device, vec![])
        .ip_addrs(ip_addrs)
        .routes(routes)
        .hardware_addr(EthernetAddress::from_bytes(
            &mac_address.bytes()).into())
        .neighbor_cache(neighbor_cache)
        .finalize();

    // DHCP
    // Based on https://github.com/vinc/moros/blob/trunk/src/usr/dhcp.rs
    use smoltcp::socket::{Dhcpv4Event, Dhcpv4Socket};

    let dhcp_socket = Dhcpv4Socket::new();
    let dhcp_handle = interface.add_socket(dhcp_socket);

    if let Err(e) = interface.poll(Instant::from_millis(0)) { // This transmits
        panic!("[tcp] Network Error: {}", e);
    }

    loop {
        let event = interface.get_socket::<Dhcpv4Socket>(dhcp_handle).poll();
        match event {
            None => {}
            Some(Dhcpv4Event::Configured(config)) => {
                interface.remove_socket(dhcp_handle);

                debug_print!("[tcp] DHCP: IP {}", config.address);
                if let Some(router) = config.router {
                    debug_print!(" Router {}", router);
                }

                for addr in config.dns_servers.iter()
                    .filter(|addr| addr.is_some()).map(|addr| addr.unwrap()) {
                        debug_print!(" DNS {}", addr);
                    }
                debug_println!("");
                break;
            }
            Some(Dhcpv4Event::Deconfigured) => {
            }
        }
        // Wait and retry
        syscalls::thread_yield();
    }


    // Server loop
    loop {
        match syscalls::receive(&STDIN) {
            Ok(message) => {
                match message {
                    syscalls::Message::Long(
                        message::OPEN, md_length, md_path) => {
                        match (md_length, md_path) {
                            (MessageData::Value(length),
                             MessageData::MemoryHandle(handle)) => {
                                let u8_slice = handle.as_slice::<u8>(length as usize);
                                if let Ok(path) = str::from_utf8(u8_slice) {
                                    let path = path.trim_matches(|c:char| c == '/' ||
                                                                 c.is_whitespace());
                                    debug_println!("[tcp] Opening path '{}'", path);
                                } else {
                                    debug_println!("[tcp] open invalid utf8 path");
                                }
                            }
                            _ => {
                                debug_println!("[tcp] open invalid message format");
                            }
                        }
                    }
                    _ => {
                        debug_println!("[tcp] unknown message {:?}", message);
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
                debug_println!("[tcp] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}
