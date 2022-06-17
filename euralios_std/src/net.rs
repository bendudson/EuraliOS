//! Network related data structures and functions

use core::fmt;

/// Represent a Media Access Control (MAC) address
///
/// Interface similar to mac_address crate
/// https://docs.rs/mac_address/latest/mac_address/struct.MacAddress.html
pub struct MacAddress {
    octet: [u8; 6]
}

impl MacAddress {
    /// Create a new MacAddress from bytes
    pub fn new(octet: [u8; 6]) -> MacAddress {
        MacAddress{octet}
    }

    /// Return the address as an array of bytes
    pub fn bytes(&self) -> [u8; 6] {
        self.octet
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
