#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   fprintln,
                   fs::File,
                   syscalls::{self, STDIN, STDOUT, CommHandle},
                   message::{self, rcall, Message, MessageData}};

fn new_writer(vga_com: &CommHandle) -> (CommHandle, u64) {
    match rcall(
        vga_com,
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
    }
}

fn activate_writer(vga_com: &CommHandle, writer_id: u64) {
    syscalls::send(
        &vga_com,
        Message::Short(message::WRITE, writer_id, 0));
}

fn mount(
    path: &str,
    bin: &[u8],
    flags: u8,
    stdout: CommHandle) {

    fprintln!(&stdout, "[init] Starting program mounted at {} with flags {}", path, flags);

    // Make a new Rendezvous for the process input
    let (input, input2) = syscalls::new_rendezvous().unwrap();

    // Start the process
    syscalls::exec(
        bin,
        flags,
        input,
        stdout).expect("[init] Couldn't start program");

    // Mount in filesystem
    syscalls::mount(path, input2);
}


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
    let (writer_sys, writer_sys_id) = new_writer(&vga_com);

    // Activate writer
    activate_writer(&vga_com, writer_sys_id);

    fprintln!(&writer_sys, "[init] Starting EuraliOS...");

    // Mount a ramdisk to read/write files
    mount("/ramdisk", include_bytes!("../../user/ramdisk"),
          0, // No I/O privileges
          writer_sys.clone());

    // Write some data to the ramdisk
    if let Ok(mut file) = File::create("/ramdisk/gopher") {
        file.write(include_bytes!("../../user/gopher"));
    }
    if let Ok(mut file) = File::create("/ramdisk/system_test") {
        file.write(include_bytes!("../../user/system_test"));
    }

    mount("/pci", include_bytes!("../../user/pci"),
          syscalls::EXEC_PERM_IO, // I/O permissions
          writer_sys.clone());

    mount("/dev/nic", include_bytes!("../../user/rtl8139"),
          syscalls::EXEC_PERM_IO,
          writer_sys.clone());

    mount("/tcp", include_bytes!("../../user/tcp"),
          0, // No I/O permissions
          writer_sys.clone());

    // New screen for user program
    let (writer_user, writer_user_id) = new_writer(&vga_com);
    // New Rendezvous for user program input
    let (input_user, input_user2) = syscalls::new_rendezvous().unwrap();

    // Start the process
    syscalls::exec(
        include_bytes!("../../user/shell"),
        0,
        input_user2,
        writer_user).expect("[init] Couldn't start user program");

    // Activate user writer
    activate_writer(&vga_com, writer_user_id);

    loop {
        // Wait for keyboard input
        match syscalls::receive(&STDIN) {
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {
                // Received a character

                if ch == 9 { // TAB
                    activate_writer(&vga_com, writer_user_id);
                } else if ch == 27 { // ESC
                    activate_writer(&vga_com, writer_sys_id);
                } else {
                    syscalls::send(&input_user,
                                   syscalls::Message::Short(
                                       message::CHAR, ch, 0));
                }
            }
            _ => {
                // Ignore
            }
        }
    }
}
