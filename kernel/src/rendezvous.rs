use alloc::{boxed::Box, sync::Arc};
use crate::process::Thread;
use crate::syscalls;
use core::mem;
use spin::RwLock;

// Standard message types
pub const MESSAGE_TYPE_CHAR: u64 = 0;

pub enum MessageData {
    Value(u64),
    Rendezvous(Arc<RwLock<Rendezvous>>),
}

pub enum Message {
    Short(u64, u64, u64),
    Long(u64, MessageData, MessageData),
}

/// A Rendezvous is in one of three states:
///  1. Empty
///  2. Receiving (or Reading)
///  3. Sending (or Writing)
/// In state 2 and 3 there is a Thread waiting
/// for a matching call.
pub enum Rendezvous {
    Empty,
    Sending(Option<Box<Thread>>, Message),
    Receiving(Box<Thread>)
}

impl Rendezvous {
    ///
    /// 1. Empty -> Sending, return (None, None)
    /// 3. Sending -> Sending, return (sending thread, None)
    ///    Error returned to thread
    /// 2. Receiving -> Empty, return (receiving thread, sending thread)
    pub fn send(&mut self, thread: Option<Box<Thread>>, message: Message)
                -> (Option<Box<Thread>>, Option<Box<Thread>>) {
        match &*self {
            Rendezvous::Empty => {
                *self = Rendezvous::Sending(thread, message);
                (None, None)
            }
            Rendezvous::Sending(_, _) => {
                // Signal error to thread: Can't have two sending threads
                if let Some(t) = &thread {
                    t.return_error(syscalls::SYSCALL_ERROR_SEND_BLOCKING);
                }
                (thread, None)
            }
            Rendezvous::Receiving(_) => {
                // Complete the message transfer
                // core::mem::replace https://doc.rust-lang.org/beta/core/mem/fn.replace.html
                if let Rendezvous::Receiving(rec_thread) = mem::replace(self, Rendezvous::Empty) {
                    rec_thread.return_message(message);
                    if let Some(ref t) = thread {
                        t.return_error(0);
                    }
                    return (Some(rec_thread), thread);
                }
                (None, None) // This should never be reached
            }
        }
    }

    ///
    /// 1. Empty -> Receiving, return (None, None)
    /// 2. Sending -> Empty, return (receiving thread, sending thread)
    /// 3. Receiving -> return (receiving thread, None)
    ///                 Error returned to thread
    ///
    /// Returns
    /// -------
    ///
    /// Zero, one or two threads (thread1, thread2)
    ///
    /// thread1  should be started asap
    /// thread2  should be scheduled
    pub fn receive(&mut self, thread: Box<Thread>)
                   -> (Option<Box<Thread>>, Option<Box<Thread>>) {
        match &*self {
            Rendezvous::Empty => {
                *self = Rendezvous::Receiving(thread);
                (None, None)
            }
            Rendezvous::Sending(_, _) => {
                // Complete the message transfer
                if let Rendezvous::Sending(snd_thread, message) = mem::replace(self, Rendezvous::Empty) {
                    thread.return_message(message);
                    if let Some(ref t) = snd_thread {
                        t.return_error(0);
                    }
                    return (Some(thread), snd_thread);
                }
                (None, None) // This should never be reached
            }
            Rendezvous::Receiving(_) => {
                // Already receiving
                thread.return_error(syscalls::SYSCALL_ERROR_RECV_BLOCKING);
                (Some(thread), None)
            }
        }
    }
}
