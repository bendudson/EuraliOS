//! Network related data structures and functions

use core::fmt;

/// Represent a Media Access Control (MAC) address
///
/// Interface similar to mac_address crate
/// <https://docs.rs/mac_address/latest/mac_address/struct.MacAddress.html>
pub struct MacAddress {
    octet: [u8; 6]
}

impl MacAddress {
    /// Create a new MacAddress from bytes
    pub fn new(octet: [u8; 6]) -> Self {
        MacAddress{octet}
    }

    /// Return the address as an array of bytes
    pub fn bytes(&self) -> [u8; 6] {
        self.octet
    }

    pub fn from_u64(value: u64) -> Self {
        MacAddress{octet:[
            (value & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 24) & 0xFF) as u8,
            ((value >> 32) & 0xFF) as u8,
            ((value >> 40) & 0xFF) as u8
        ]}
    }

    pub fn as_u64(&self) -> u64 {
        (self.octet[0] as u64) |
        ((self.octet[1] as u64) << 8)  |
        ((self.octet[2] as u64) << 16) |
        ((self.octet[3] as u64) << 24) |
        ((self.octet[4] as u64) << 32) |
        ((self.octet[5] as u64) << 40)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..5 {
            write!(f, "{:02X}:", self.octet[i])?;
        }
        write!(f, "{:02X}", self.octet[5])
    }
}
