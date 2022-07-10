//! EuraliOS TCP stack
//!
//! Based on code from MOROS
//! https://github.com/vinc/moros/blob/trunk/src/sys/net/mod.rs

#![no_std]
#![no_main]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::str;

use spin::RwLock;
use lazy_static::lazy_static;

use smoltcp::{self, iface::{InterfaceBuilder, NeighborCache, Routes}};
use smoltcp::phy::DeviceCapabilities;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Cidr, Ipv4Address, IpAddress};
use core::str::FromStr;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};

use euralios_std::{debug_println, debug_print,
                   syscalls::{self, STDIN, CommHandle},
                   thread,
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

lazy_static! {
    static ref INTERFACE: RwLock<Option<Interface>> = RwLock::new(None);
}

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
                set_ipv4_addr(&mut interface, config.address);

                if let Some(router) = config.router {
                    debug_print!(" Router {}", router);
                    interface.routes_mut().add_default_ipv4_route(router).unwrap();
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

    // Move the interface into static variable
    *(INTERFACE.write()) = Some(interface);

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

                                    if let Ok(handle) = open_path(path) {
                                        syscalls::send(&STDIN,
                                                       syscalls::Message::Long(
                                                           message::COMM_HANDLE,
                                                           handle.into(), 0.into()));
                                    } else {
                                        syscalls::send(&STDIN,
                                                       syscalls::Message::Short(
                                                           message::ERROR_INVALID_VALUE, 0, 0));
                                    }
                                } else {
                                    debug_println!("[tcp] open invalid utf8 path");
                                    syscalls::send(&STDIN,
                                                   syscalls::Message::Short(
                                                       message::ERROR_INVALID_UTF8, 0, 0));
                                }
                            }
                            _ => {
                                debug_println!("[tcp] open invalid message format");
                                syscalls::send(&STDIN,
                                               syscalls::Message::Short(
                                                   message::ERROR_INVALID_FORMAT, 0, 0));
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
                                   message::ERROR, 0, 0));
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

/// This function from:
/// https://github.com/smoltcp-rs/smoltcp/blob/master/examples/dhcp_client.rs#L97
fn set_ipv4_addr(iface: &mut Interface, cidr: Ipv4Cidr) {
    iface.update_ip_addrs(|addrs| {
        let dest = addrs.iter_mut().next().unwrap();
        *dest = IpCidr::Ipv4(cidr);
    });
}

/// Open a path from the root, returning a communication handle
///
/// Note: This function spawns a thread which will then attempt
///       to open the socket. It is possible that this function
///       succeeds but then opening the socket fails.
fn open_path(path: &str) -> Result<CommHandle, ()> {
    if let Some(ind) = path.find('/') {
        // Split and copy into Strings which can be moved to a new thread
        let ip = IpAddress::from_str(&path[..ind])
            .map_err(|e| {debug_println!("[tcp] Invalid host address: {:?}", e);})?;
        let port: u16 =  ((&path[(ind+1)..])
                                 .trim_matches(|c:char| c == '/' ||
                                               c.is_whitespace()))
            .parse().map_err(|e| {debug_println!("[tcp] Invalid port: {:?}", e);})?;

        // Make a new communication handle pair
        let (handle, client_handle) = syscalls::new_rendezvous()
            .map_err(|e| {debug_println!("[tcp] Couldn't create Rendezvous {:?}", e);})?;

        // Start a thread with one of the handles
        thread::spawn(move || {
            open_socket(ip, port, handle);
        });

        // Return the other handle to the client
        return Ok(client_handle);
    }
    debug_println!("[tcp] Error: open_path '{}' doesn't contain '/'", path);
    Err(())
}

/// Open a socket and wait in a loop for messages on given handle
fn open_socket(address: IpAddress, port: u16, comm_handle: CommHandle) {
    debug_println!("[tcp] Connecting to {} port {}", address, port);

    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; 2048]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; 2048]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut tcp_handle = {
        let mut some_interface = INTERFACE.write();
        let mut interface = (*some_interface).as_mut().unwrap();
        let tcp_handle = interface.add_socket(tcp_socket);

        if let Err(e) = interface.poll(Instant::from_millis(0)) {
            debug_println!("Network error: {:?}", e);
        }

        let (socket, cx) = interface.get_socket_and_context::<TcpSocket>(tcp_handle);

        let local_port = 49152; // Note: must be different
        if socket.connect(cx, (address, port), local_port).is_err() {
            debug_println!("[tcp {}/{}] socket.connect failed", address, port);
            interface.remove_socket(tcp_handle);
            None
        } else {
            debug_println!("[tcp {}/{}] open {} active {} can_send {} can_recv {} may_send {} may_recv {}",
                           address, port,
                           socket.is_open(), socket.is_active(),
                           socket.can_send(), socket.can_recv(),
                           socket.may_recv(), socket.may_recv(), );
            Some(tcp_handle)
        }
    };

    loop {
        match syscalls::receive(&comm_handle) {
            Ok(syscalls::Message::Long(
                message::WRITE,
                MessageData::Value(length),
                MessageData::MemoryHandle(handle))) => {

                // Get a slice
                let mut data = handle.as_slice::<u8>(length as usize);

                // Keep trying to send the data
                loop {
                    match tcp_handle {
                        Some(handle) => {
                            let mut some_interface = INTERFACE.write();
                            let mut interface = (*some_interface).as_mut().unwrap();

                            if let Err(e) = interface.poll(Instant::from_millis(0)) {
                                debug_println!("[tcp {}/{}] Network error: {:?}", address, port, e);
                            }

                            let (socket, cx) = interface.get_socket_and_context::<TcpSocket>(handle);

                            if socket.may_send() {
                                match socket.send_slice(data) {
                                    Ok(length) => { // Succeeded in sending some or all the data
                                        debug_println!("[tcp {}/{}] Sent {} bytes", address, port, length);
                                        if length == data.len() {
                                            // All data sent
                                            syscalls::send(&comm_handle,
                                                           syscalls::Message::Short(
                                                               message::OK, 0, 0));
                                            break;
                                        }
                                        // Some data still to send. Get slice containing unsent data
                                        data = &data[length..];
                                        // Continue around loop
                                    }
                                    Err(e) => {
                                        debug_println!("[tcp {}/{}] Send failed: {:?}", address, port, e);
                                        syscalls::send(&comm_handle,
                                                       syscalls::Message::Short(
                                                           message::ERROR, 0, 0));
                                        break;
                                    }
                                }
                            }
                            // Wait for a bit before trying again
                            syscalls::thread_yield();
                        }
                        None => {
                            // Return error
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::ERROR, 0, 0));
                            break;
                        }
                    }
                }
            }
            Ok(syscalls::Message::Short(
                message::READ, _, _)) => {

                // Data may be received in pieces. Use a Vec to combine them together
                let mut received_data: Vec<u8> = Vec::new();

                loop {
                    match tcp_handle {
                        Some(handle) => {
                            let mut some_interface = INTERFACE.write();
                            let mut interface = (*some_interface).as_mut().unwrap();

                            if let Err(e) = interface.poll(Instant::from_millis(0)) {
                                debug_println!("[tcp {}/{}] Network error: {:?}", address, port, e);
                            }

                            let (socket, cx) = interface.get_socket_and_context::<TcpSocket>(handle);

                            if socket.can_recv() {
                                socket
                                    .recv(|data| {
                                        received_data.extend_from_slice(&data);
                                        debug_println!("Received data: {} -> {}", data.len(), received_data.len());
                                        (data.len(), ())
                                    })
                                    .unwrap();
                            }

                            if !socket.may_recv() {
                                // Complete reply received

                                // Copy the data into a memory chunk which can be sent to client
                                let mem_handle = syscalls::MemoryHandle::from_u8_slice(
                                    received_data.as_slice());
                                syscalls::send(
                                    &comm_handle,
                                    syscalls::Message::Long(
                                        message::DATA,
                                        (received_data.len() as u64).into(),
                                        mem_handle.into()));
                                break;
                            }
                        }
                        None => {
                            // Return error
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::ERROR, 0, 0));
                            break;
                        }
                    }
                    // Wait a bit then try again
                    syscalls::thread_yield();
                }
            }
            Ok(msg) => {
                debug_println!("[tcp {}/{}] -> {:?}", address, port, msg);
            }
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&comm_handle,
                               syscalls::Message::Short(
                                   message::ERROR, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(code) => {
                debug_println!("[tcp {}/{}] Receive error {}", address, port, code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}

