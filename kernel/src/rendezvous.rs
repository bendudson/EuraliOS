use alloc::boxed::Box;
use crate::process::Thread;
use crate::syscalls;
use crate::message::Message;
use core::mem;

// Standard message types
pub const MESSAGE_TYPE_CHAR: u64 = 0;

/// A Rendezvous is in one of three states:
///  1. Empty
///  2. Receiving (or Reading). Optionally from a specific thread
///  3. Sending (or Writing)
///  4. Sending, expecting a reply
/// In states 2-5 there is a Thread waiting
/// for a matching call.
pub enum Rendezvous {
    Empty,
    Sending(Option<Box<Thread>>, Message),
    Receiving(Box<Thread>, Option<u64>),
    SendReceiving(Box<Thread>, Message),
}

impl Rendezvous {
    ///
    /// 1. Empty -> Sending, return (None, None)
    /// 3. Sending -> Sending, return (sending thread, None)
    ///    Error returned to thread
    /// 2. Receiving -> Empty, return (receiving thread, sending thread)
    /// 3. SendReceiving -> SendReceiving, return (sending thread, None)
    ///    Error returned to thread
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
            Rendezvous::Receiving(_, some_tid) => {
                if let Some(tid) = some_tid {
                    // Restricted to a single thread
                    if let Some(t) = &thread {
                        if t.tid() != *tid {
                            // Wrong thread ID
                            t.return_error(syscalls::SYSCALL_ERROR_RECV_BLOCKING);
                            return (thread, None);
                        }
                        // else keep going
                    } else {
                        // No sender thread => error
                        return (thread, None);
                    }
                }

                // Complete the message transfer
                // core::mem::replace https://doc.rust-lang.org/beta/core/mem/fn.replace.html
                if let Rendezvous::Receiving(rec_thread, _) = mem::replace(self, Rendezvous::Empty) {
                    rec_thread.return_message(message);
                    if let Some(ref t) = thread {
                        t.return_error(0);
                    }
                    return (Some(rec_thread), thread);
                }
                (None, None) // This should never be reached
            }
            Rendezvous::SendReceiving(_, _) => {
                // Signal error to thread: Can't have two sending threads
                if let Some(t) = &thread {
                    t.return_error(syscalls::SYSCALL_ERROR_SEND_BLOCKING);
                }
                (thread, None)
            }
        }
    }

    ///
    /// 1. Empty -> Receiving, return (None, None)
    /// 2. Sending -> Empty, return (receiving thread, sending thread)
    /// 3. Receiving -> return (receiving thread, None)
    ///                 Error returned to thread
    /// 4. SendReceiving -> Receiving, return (receiving thread, None)
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
                // Can receive from any thread
                *self = Rendezvous::Receiving(thread, None);
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
            Rendezvous::Receiving(_, _) => {
                // Already receiving
                thread.return_error(syscalls::SYSCALL_ERROR_RECV_BLOCKING);
                (Some(thread), None)
            }
            Rendezvous::SendReceiving(_, _) => {
                // Sending, expecting a reply from the same thread
                if let Rendezvous::SendReceiving(snd_thread, message) = mem::replace(self, Rendezvous::Empty) {
                    thread.return_message(message);
                    // Wait for a reply from the receiving thread
                    *self = Rendezvous::Receiving(snd_thread, Some(thread.tid()));
                    return (Some(thread), None);
                }
                (None, None)
            }
        }
    }

    ///
    /// 1. Empty -> SendReceiving, return (None, None)
    /// 3. Sending -> Sending, return (sending thread, None)
    ///    Error returned to thread
    /// 2. Receiving -> Receiving, return (receiving thread, None)
    /// 3. SendReceiving -> SendReceiving, return (sending thread, None)
    ///    Error returned to thread
    pub fn send_receive(&mut self, thread: Box<Thread>, message: Message)
                        -> (Option<Box<Thread>>, Option<Box<Thread>>) {
        match &*self {
            Rendezvous::Empty => {
                *self = Rendezvous::SendReceiving(thread, message);
                (None, None)
            }
            Rendezvous::Sending(_, _) => {
                // Signal error to thread: Can't have two sending threads
                thread.return_error(syscalls::SYSCALL_ERROR_SEND_BLOCKING);
                (Some(thread), None)
            }
            Rendezvous::Receiving(_, some_tid) => {
                if let Some(tid) = some_tid {
                    // Restricted to a single thread
                    if thread.tid() != *tid {
                        // Wrong thread ID
                        thread.return_error(syscalls::SYSCALL_ERROR_RECV_BLOCKING);
                        return (Some(thread), None);
                    }
                }

                // Complete the message transfer
                if let Rendezvous::Receiving(rec_thread, _) = mem::replace(self, Rendezvous::Empty) {
                    rec_thread.return_message(message);

                    // Calling thread waits for a reply
                    *self = Rendezvous::Receiving(thread, Some(rec_thread.tid()));

                    return (Some(rec_thread), None);
                }
                (None, None) // This should never be reached
            }
            Rendezvous::SendReceiving(_, _) => {
                // Signal error to thread: Can't have two sending threads
                thread.return_error(syscalls::SYSCALL_ERROR_SEND_BLOCKING);
                (Some(thread), None)
            }
        }
    }
}
