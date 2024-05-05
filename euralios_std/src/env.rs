extern crate alloc;
use alloc::string::String;

use crate::get_args;

pub fn args() -> impl Iterator<Item = String> {
    // Convert bytes into a vector of owned strings
    get_args()
        .split(|&b| b == 0x03)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
}
