//! EuraliOS TCP stack
//!
//! Based on code from MOROS
//! https://github.com/vinc/moros/blob/trunk/src/sys/net/mod.rs

#![no_std]
#![no_main]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec;
use core::slice;

use smoltcp::{self, iface::{InterfaceBuilder, NeighborCache, Routes}};
use smoltcp::phy::DeviceCapabilities;
use smoltcp::time::Instant;

use euralios_std::{debug_println,
                   syscalls,
                   message};


/// Represents an ethernet device, which has a driver connected
/// through a communication handle
struct EthernetDevice {
    handle: syscalls::CommHandle
}

/// Receive token contains packet data
struct RxToken {
    length: usize,
    data: syscalls::MemoryHandle
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(
        mut self,
        _timestamp: Instant,
        f: F
    ) -> smoltcp::Result<R>
    where F: FnOnce(&mut [u8]) -> smoltcp::Result<R> {
        f(unsafe{slice::from_raw_parts_mut(
            self.data.as_mut_ptr::<u8>(),
            self.length)})
    }
}


struct TxToken {

}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R> where F: FnOnce(&mut [u8]) -> smoltcp::Result<R> {

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
        match message::rcall(&self.handle, message::READ,
                             0.into(), 0.into(), None) {
            Ok((message::DATA, length, data)) => {
                Some(RxToken{length:length.value() as usize,
                             data:data.memory()},
                     TxToken{})
            }
            Ok((message::EMPTY, _, _)) => None,
            value => {
                debug_println!("[tcp] received unexpected {:?}", value);
                None
            }
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken{})
    }
}

pub type Interface = smoltcp::iface::Interface<'static, EthernetDevice>;

#[no_mangle]
fn main() {
    debug_println!("[tcp] Starting");

    let handle = syscalls::open("/dev/nic").expect("Couldn't open /dev/nic");
    syscalls::send(&handle,
                   syscalls::Message::Short(
                       syscalls::MESSAGE_TYPE_CHAR,
                       'X' as u64, 0));

    let device = EthernetDevice{handle};

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let routes = Routes::new(BTreeMap::new());

    let mut builder = InterfaceBuilder::new(device, vec![]);
}
