//! Domain Name System (DNS)
//!
//! This code was adapted from the MOROS operating system
//! <https://github.com/vinc/moros/blob/trunk/src/usr/host.rs>
//! Copyright (c) 2019-2022 Vincent Ollivier (<https://vinc.cc/>)
//!
//! See RFC 1035 for implementation details

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bit_field::BitField;
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};
use smoltcp::socket::{UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Instant;

use spin::RwLock;
use lazy_static::lazy_static;

use euralios_std::{time, syscalls, println};

use crate::INTERFACE;

#[repr(u16)]
enum QueryType {
    A = 1,
    // NS = 2,
    // MD = 3,
    // MF = 4,
    // CNAME = 5,
    // SOA = 6,
    // MX = 15,
    // TXT = 16,
}

#[repr(u16)]
enum QueryClass {
    IN = 1,
}

#[derive(Debug)]
#[repr(u16)]
pub enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,

    UnknownError,
    NetworkError,
}

struct Message {
    datagram: Vec<u8>,
}

const FLAG_RD: u16 = 0x0100; // Recursion desired

impl Message {
    fn from(datagram: &[u8]) -> Self {
        Self {
            datagram: Vec::from(datagram),
        }
    }

    fn query(qname: &str, qtype: QueryType, qclass: QueryClass) -> Self {
        let mut datagram = Vec::new();

        let id = crate::ephemeral_port_number(); // A random semi-unique number
        for b in id.to_be_bytes().iter() {
            datagram.push(*b); // Transaction ID
        }
        for b in FLAG_RD.to_be_bytes().iter() {
            datagram.push(*b); // Flags
        }
        for b in (1 as u16).to_be_bytes().iter() {
            datagram.push(*b); // Questions
        }
        for _ in 0..6 {
            datagram.push(0); // Answer + Authority + Additional
        }
        for label in qname.split('.') {
            datagram.push(label.len() as u8); // QNAME label length
            for b in label.bytes() {
                datagram.push(b); // QNAME label bytes
            }
        }
        datagram.push(0); // Root null label
        for b in (qtype as u16).to_be_bytes().iter() {
            datagram.push(*b); // QTYPE
        }
        for b in (qclass as u16).to_be_bytes().iter() {
            datagram.push(*b); // QCLASS
        }

        Self { datagram }
    }

    fn id(&self) -> u16 {
        u16::from_be_bytes(self.datagram[0..2].try_into().unwrap())
    }

    fn header(&self) -> u16 {
        u16::from_be_bytes(self.datagram[2..4].try_into().unwrap())
    }

    fn is_response(&self) -> bool {
        self.header().get_bit(15)
    }

    fn rcode(&self) -> ResponseCode {
        match self.header().get_bits(11..15) {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::UnknownError,
        }
    }
}

/// Port number to connect to on DNS server
const DNS_PORT: u16 = 53;

lazy_static! {
    /// A vector of DNS servers. Currently only the last pushed is used
    /// Start with the Google DNS server as fallback
    static ref SERVERS: RwLock<Vec<IpAddress>> = RwLock::new(vec![IpAddress::v4(8, 8, 8, 8)]);

    /// Cache of host name to IP address lookup
    /// NOTE: These entries should also have an expiry time
    static ref CACHE: RwLock<BTreeMap<String, IpAddress>> = RwLock::new(BTreeMap::new());
}

/// Add a DNS server which can be used to resolve hostnames
pub fn add_server(address: IpAddress) {
    SERVERS.write().push(address);
}

/// Find the IP address of a given host name
///
/// Uses CACHE to store previous lookups, and uses the DNS server last
/// added to SERVERS.
pub fn resolve(name: &str) -> Result<IpAddress, ResponseCode> {
    // Check the cache
    {
        let cache = CACHE.read();
        if let Some(addr) = cache.get(name) {
            // Here could check expiry time
            return Ok(addr.clone());
        }
    }

    // Get the IP address of a DNS server
    let dns_address = {
        let servers = SERVERS.read();
        match servers.last() {
            Some(addr) => addr.clone(),
            None => {return Err(ResponseCode::NotImplemented);}
        }
    };

    let server = IpEndpoint::new(dns_address, DNS_PORT);

    // Get a local port for the connection
    let local_port = crate::ephemeral_port_number();
    let client = IpEndpoint::new(IpAddress::Unspecified, local_port);

    let query = Message::query(name, QueryType::A, QueryClass::IN);

    // Add the UDP socket to the network interface
    let udp_handle = {
        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 2048]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 2048]);
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

        let mut some_interface = INTERFACE.write();
        let interface = (*some_interface).as_mut().unwrap();
        interface.add_socket(udp_socket)
    };

    #[derive(Debug)]
    enum State { Bind, Query, Response }
    let mut state = State::Bind;

    // Don't keep a reference to INTERFACE because this thread
    // is interleaved with threads servicing other requests.
    loop {
        {
            // Get a lock on the INTERFACE
            let mut some_interface = INTERFACE.write();
            let interface = (*some_interface).as_mut().unwrap();

            if let Err(e) = interface.poll(Instant::from_micros(time::microseconds_monotonic() as i64)) {
                println!("Network Error: {}", e);
                return Err(ResponseCode::UnknownError);
            }

            let socket = interface.get_socket::<UdpSocket>(udp_handle);

            state = match state {
                State::Bind if !socket.is_open() => {
                    socket.bind(client).unwrap();
                    State::Query
                }
                State::Query if socket.can_send() => {
                    socket.send_slice(&query.datagram, server).expect("cannot send");
                    State::Response
                }
                State::Response if socket.can_recv() => {
                    let (data, _) = socket.recv().expect("cannot receive");
                    let message = Message::from(data);
                    if message.id() == query.id() && message.is_response() {
                        interface.remove_socket(udp_handle);
                        return match message.rcode() {
                            ResponseCode::NoError => {
                                // TODO: Parse the datagram instead of
                                // extracting the last 4 bytes.
                                //let rdata = message.answer().rdata();
                                let n = message.datagram.len();
                                let rdata = &message.datagram[(n - 4)..];

                                let addr = IpAddress::from(Ipv4Address::from_bytes(rdata));
                                // Put into the cache
                                CACHE.write().insert(String::from(name), addr.clone());

                                Ok(addr)
                            }
                            rcode => {
                                Err(rcode)
                            }
                        }
                    }
                    state
                }
                _ => state
            };
        } // release lock on INTERFACE

        // Wait, try again later
        syscalls::thread_yield();
    }
}
