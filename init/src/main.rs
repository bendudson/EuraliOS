#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   fprint,
                   syscalls::{self, STDIN, STDOUT},
                   message::{self, rcall, Message, MessageData}};

#[no_mangle]
fn main() {
    debug_println!("[init] Starting");

    // Expect a video memory buffer from the kernel
    // Note: Sent to STDOUT channel to avoid conflict with keyboard
    let (vmem_length, vmem_handle) = match syscalls::receive(&STDOUT) {
        Ok(Message::Long(
            message::VIDEO_MEMORY,
            MessageData::Value(length),
            MessageData::MemoryHandle(handle))) => {
            (length, handle)
        },
        m => {
            panic!("[init] Expected video memory message. Received {:?}", m);
        }
    };

    // Create a communication handle for the VGA input
    let (vga_com, vga_com2) = syscalls::new_rendezvous().unwrap();

    // Start the VGA driver
    syscalls::exec(
        include_bytes!("../../user/vga_driver"),
        syscalls::EXEC_PERM_IO, // I/O permissions
        vga_com2.clone(),
        vga_com2).expect("[init] Couldn't start VGA program");

    // Send the video memory
    syscalls::send(&vga_com,
                   Message::Long(
                       message::VIDEO_MEMORY,
                       MessageData::Value(vmem_length),
                       MessageData::MemoryHandle(vmem_handle)));

    // Open a VGA screen writer for system programs
    let (writer_sys, writer_sys_id) = match rcall(
        &vga_com,
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
        &vga_com,
        Message::Short(message::WRITE, writer_sys_id, 0));

    fprint!(&writer_sys, "Hello World!!");
}
