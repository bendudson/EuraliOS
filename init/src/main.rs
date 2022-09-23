#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   console::sequences,
                   fprintln,
                   fs::File,
                   syscalls::{self, STDIN, STDOUT, CommHandle},
                   message::{self, rcall, Message, MessageData}};


struct Console<'a> {
    /// VGA communicator
    vga: &'a CommHandle,
    /// The VGA writer ID
    writer_id: u64,
    /// Handle that input should be sent to
    input: Option<CommHandle>,
    /// Handle for writing output to screen
    output: CommHandle
}

impl<'a> Console<'a> {
    pub fn new(vga_com: &'a CommHandle) -> Self {
        match rcall(
            vga_com,
            message::OPEN_READWRITE, 0.into(), 0.into(), None) {
            Ok((message::COMM_HANDLE,
                MessageData::CommHandle(handle),
                MessageData::Value(id))) => Console {vga: vga_com,
                                                     writer_id: id,
                                                     input: None,
                                                     output:handle},
            Ok(message) => {
                panic!("[init] Received unexpected message {:?}", message);
            }
            Err(code) => {
                panic!("[init] Received error {:?}", code);
            }
        }
    }

    ///
    pub fn new_shell(vga_com: &'a CommHandle) -> Self {
        let mut console = Self::new(vga_com);

        // New Rendezvous for shell input
        let (input, input2) = syscalls::new_rendezvous().unwrap();
        console.input = Some(input);

        // Start the process
        syscalls::exec(
            include_bytes!("../../user/shell"),
            0,
            input2,
            console.output.clone()).expect("[init] Couldn't start user program");
        console
    }

    pub fn activate(&self) {
        syscalls::send(
            self.vga,
            Message::Short(message::WRITE, self.writer_id, 0));
    }
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

    // Start the keyboard input, configuring it to send to this
    // process' input
    syscalls::exec(
        include_bytes!("../../user/keyboard"),
        syscalls::EXEC_PERM_IO, // I/O permissions
        STDIN.clone(),
        STDIN.clone()).expect("[init] Couldn't start keyboard program");

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

    // Send the video memory to the video driver
    syscalls::send(&vga_com,
                   Message::Long(
                       message::VIDEO_MEMORY,
                       MessageData::Value(vmem_length),
                       MessageData::MemoryHandle(vmem_handle)));

    // Can have a console for each F key
    let mut consoles: [Option<Console>; 12] = Default::default();

    // Make a Console for system programs
    consoles[0] = {
        let console = Console::new(&vga_com);
        console.activate(); // Activate it so that errors are displayed
        Some(console)
    };
    let writer_sys = &consoles[0].as_ref().unwrap().output;

    fprintln!(writer_sys, "[init] Starting EuraliOS...");

    // Mount a ramdisk to read/write files
    mount("/ramdisk", include_bytes!("../../user/ramdisk"),
          0, // No I/O privileges
          writer_sys.clone());

    // Write some data to the ramdisk
    if let Ok(mut file) = File::create("/ramdisk/gopher") {
        file.write(include_bytes!("../../user/gopher"));
    }
    if let Ok(mut file) = File::create("/ramdisk/edit") {
        file.write(include_bytes!("../../user/edit"));
    }
    if let Ok(mut file) = File::create("/ramdisk/system_test") {
        file.write(include_bytes!("../../user/system_test"));
    }
    if let Ok(mut file) = File::create("/ramdisk/std_test") {
        file.write(include_bytes!("../../user/std_test"));
    }
    if let Ok(mut file) = File::create("/ramdisk/keyboard") {
        file.write(include_bytes!("../../user/keyboard"));
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

    // Start a user shell on new Console
    consoles[1] = {
        let console = Console::new_shell(&vga_com);
        console.activate();
        Some(console)
    };

    let mut current_console: &Console = &consoles[1].as_ref().unwrap();
    loop {
        // Wait for keyboard input
        match syscalls::receive(&STDIN) {
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {
                // Received a character
                match ch {
                    sequences::F1 => {
                        current_console = consoles[0].as_ref().unwrap();
                        current_console.activate()
                    }
                    sequences::F2 => {
                        current_console = consoles[1].as_ref().unwrap();
                        current_console.activate()
                    }
                    sequences::F3 => {
                        if consoles[2].is_none() {
                            consoles[2] = Some(Console::new_shell(&vga_com));
                        }
                        current_console = consoles[2].as_ref().unwrap();
                        current_console.activate()
                    }
                    ch => {
                        if let Some(input) = &current_console.input {
                            syscalls::send(input,
                                           syscalls::Message::Short(
                                               message::CHAR, ch, 0));
                        }
                    },
                }
            }
            _ => {
                // Ignore
            }
        }
    }
}
