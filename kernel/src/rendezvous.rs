

use alloc::boxed::Box;
use crate::process::Thread;

/// A Rendezvous is in one of three states:
///  1. Empty
///  2. Receiving (or Reading)
///  3. Sending (or Writing)
/// In state 2 and 3 there is a Thread waiting
/// for a matching call.
pub enum Rendezvous {
    Empty,
    Sending(Box<Thread>),
    Receiving(Box<Thread>)
}

