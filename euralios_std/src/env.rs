extern crate alloc;
use alloc::string::String;

pub struct Args {
}

pub fn args() -> Args {
    Args{}
}

impl Iterator for Args {
    type Item = String;
    fn next(&mut self) -> Option<String> {
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}
