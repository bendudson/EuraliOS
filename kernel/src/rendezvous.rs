//! Non-buffering communication mechanism

use alloc::boxed::Box;
use crate::process::Thread;
use crate::syscalls;
use crate::message::Message;
use core::mem;

/// Represents a blocking communication channel
///
/// A Rendezvous is in one of three states:
///  1. Empty
///  2. Receiving (or Reading). Optionally from a specific thread
///  3. Sending (or Writing)
///  4. Sending, expecting a reply
/// In states 2 and 4 there is a Thread waiting
/// for a matching call, and in state 3 the sender may wait.
pub enum Rendezvous {
    Empty,
    Sending(Option<Box<Thread>>, Message),
    Receiving(Box<Thread>, Option<u64>),
    SendReceiving(Box<Thread>, Message),
}

impl Rendezvous {
    /// Send a message to a Rendezvous. Blocking or non-blocking
    ///
    /// If a `Box<Thread>` is provided then it is suspended until
    /// the message is received i.e. blocking.
    ///
    /// Causes state transition:
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
                    // Return message, so that any handles are not lost
                    t.return_error_message(syscalls::SYSCALL_ERROR_SEND_BLOCKING, message);
                }
                (thread, None)
            }
            Rendezvous::Receiving(_, some_tid) => {
                if let Some(tid) = some_tid {
                    // Restricted to a single thread
                    if let Some(t) = &thread {
                        if t.tid() != *tid {
                            // Wrong thread ID
                            t.return_error_message(syscalls::SYSCALL_ERROR_RECV_BLOCKING, message);
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
                        t.return_error(0); // Success
                    }
                    return (Some(rec_thread), thread);
                }
                (None, None) // This should never be reached
            }
            Rendezvous::SendReceiving(_, _) => {
                // Signal error to thread: Can't have two sending threads
                if let Some(t) = &thread {
                    t.return_error_message(syscalls::SYSCALL_ERROR_SEND_BLOCKING, message);
                }
                (thread, None)
            }
        }
    }

    /// Blocking receive a message
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
                        t.return_error(0); // Success
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

    /// Send a message and block on receive from the same thread
    ///
    /// When a Rendezvous is shared between multiple threads, for example
    /// a server, this ensures that the reply goes to the correct thread.
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
                thread.return_error_message(syscalls::SYSCALL_ERROR_SEND_BLOCKING, message);
                (Some(thread), None)
            }
            Rendezvous::Receiving(_, some_tid) => {
                if let Some(tid) = some_tid {
                    // Restricted to a single thread
                    if thread.tid() != *tid {
                        // Wrong thread ID
                        thread.return_error_message(syscalls::SYSCALL_ERROR_RECV_BLOCKING, message);
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
                thread.return_error_message(syscalls::SYSCALL_ERROR_SEND_BLOCKING, message);
                (Some(thread), None)
            }
        }
    }

    /// Close a Rendezvous.
    ///
    /// If a thread was waiting then it is returned and should be scheduled.
    /// An error SYSCALL_ERROR_CLOSED will be returned to the waiting thread.
    pub fn close(&mut self) -> Option<Box<Thread>> {
        match &*self {
            Rendezvous::Empty => None,
            Rendezvous::Sending(_, _) => {
                // Cannot complete the message transfer
                if let Rendezvous::Sending(Some(snd_thread), message) = mem::replace(self, Rendezvous::Empty) {
                    snd_thread.return_error_message(syscalls::SYSCALL_ERROR_CLOSED, message);
                    Some(snd_thread)
                } else {
                    None
                }
            }
            Rendezvous::Receiving(_, _) => {
                // Will never receive a message
                if let Rendezvous::Receiving(rec_thread, _) = mem::replace(self, Rendezvous::Empty) {
                    rec_thread.return_error(syscalls::SYSCALL_ERROR_CLOSED);
                    Some(rec_thread)
                } else {
                    None
                }
            }
            Rendezvous::SendReceiving(_, _) => {
                // Cannot complete the message transfer
                if let Rendezvous::SendReceiving(snd_thread, message) = mem::replace(self, Rendezvous::Empty) {
                    snd_thread.return_error_message(syscalls::SYSCALL_ERROR_CLOSED, message);
                    Some(snd_thread)
                } else {
                    None
                }
            }
        }
    }
}
