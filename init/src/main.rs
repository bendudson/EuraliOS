#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   fprint,
                   syscalls::{self, STDIN, STDOUT},
                   message::{self, rcall, Message, MessageData}};

#[no_mangle]
fn main() {
    debug_println!("[init] Hello, world!");

    // Open a VGA screen writer
    let (com_handle, writer_id) = match rcall(
        &STDOUT,
        message::OPEN, 0.into(), 0.into(), None) {
        Ok((message::COMM_HANDLE,
            MessageData::CommHandle(handle),
            MessageData::Value(id))) => (handle, id),
        Ok(message) => {
            panic!("[init] Received unexpected message {:?}", message);
        }
        Err(code) => {
            panic!("[init] Received error {:?}", code);
        }
    };
    
    // Activate writer
    syscalls::send(
        &STDOUT,
        Message::Short(message::WRITE, writer_id, 0));

    fprint!(&com_handle, "Hello World!!");
}
