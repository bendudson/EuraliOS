#![no_std]
#![no_main]

extern crate alloc;
use alloc::{vec::Vec, sync::Arc, string::String};
use spin::RwLock;
use lazy_static::lazy_static;

use euralios_std::{debug_println,
                   syscalls::{self, CommHandle, STDIN},
                   thread,
                   message::{self, Message, MessageData}};

use vga;
use vga::colors::{Color16, TextModeColor};
use vga::writers::{Screen, ScreenCharacter,
                   TextWriter, Text80x25};

/// Represents a writer for rendering text
///
/// Interprets a subset of ANSI escape sequences
/// <https://en.wikipedia.org/wiki/ANSI_escape_code>
///
/// Always renders to a buffer in memory. If active then also writes
/// to video (VGA) memory. This is to avoid having to read from video
/// memory when deactivating.  When activated the contents of the
/// memory buffer are copied to video memory.
///
/// # Notes
///
///  * LF '\n' moves the cursor to the start of the new line
///    i.e. includes a CR.
///
pub struct Writer<'a, S: Screen + TextWriter> {
    row: usize,
    column: usize,
    color: TextModeColor,
    blank: ScreenCharacter,

    /// Represents the physical device
    screen: &'a S,

    /// A buffer in host memory, of the same size as video memory
    buffer: Vec<ScreenCharacter>,

    /// Is this writer writing to the screen?
    active: bool,

    /// Is the cursor visible?
    cursor_visible: bool
}

const DEFAULT_FOREGROUND: Color16 = Color16::Black;
const DEFAULT_BACKGROUND: Color16 = Color16::White;

impl<'a, S: Screen + TextWriter> Writer<'a, S> {

    /// Create a new Writer
    ///
    /// Will be inactive; call `activate()` method to write to video
    /// memory.
    fn new(screen: &'a S) -> Self {
        screen.set_cursor_position(0, 1);
        screen.enable_cursor();

        let blank = ScreenCharacter::new(
            b' ',
            TextModeColor::new(Color16::White, Color16::White));

        let mut buffer = Vec::with_capacity(S::SIZE);
        for _ in 0..S::SIZE {
            buffer.push(blank.clone());
        }

        Writer{column: 0,
               row: 1,
               color: Self::default_color(),
               blank,
               screen,
               buffer,
               active: false,
               cursor_visible: true}
    }

    fn default_color() -> TextModeColor {
        TextModeColor::new(DEFAULT_FOREGROUND, DEFAULT_BACKGROUND)
    }

    /// Write to video memory
    fn activate(&mut self) {
        // Copy buffer into video memory
        let (_lock, frame_buffer) = self.screen.get_frame_buffer();
        for i in 0..self.buffer.len() {
            unsafe {
                frame_buffer.add(i).write_volatile(self.buffer[i]);
            }
        }
        self.active = true;

        // Show or hide cursor
        if self.cursor_visible {
            //self.screen.enable_cursor();
        } else {
            self.screen.disable_cursor();
        }
    }

    /// Stop writing to video memory
    ///
    /// Further updates are only made to the memory buffer, and then
    /// copied to video memory when `activate()` is called.
    fn deactivate(&mut self) {
        self.active = false;
    }

    /// Move all characters from row to row-1
    ///
    /// Fills the lowest row with the blank character
    fn scroll_up(&self, buffer: *mut ScreenCharacter) {
        for row in 1..S::HEIGHT {
            for col in 0..S::WIDTH {
                unsafe {
                    let character = buffer.add(row * S::WIDTH + col).read();
                    buffer.add((row - 1) * S::WIDTH + col).write_volatile(character);
                }
            }
        }
        // Clear the new row
        for col in 0..S::WIDTH {
            unsafe {
                buffer.add((S::HEIGHT - 1) * S::WIDTH + col).write_volatile(self.blank);
            }
        }
    }

    /// Write a string to the buffer and (if active) video memory
    ///
    /// Interprets a subset of the ANSI escape codes
    /// <https://en.wikipedia.org/wiki/ANSI_escape_code>
    /// List of Xterm control sequences
    /// <https://www.xfree86.org/current/ctlseqs.html>
    pub fn write_string(&mut self, s: &[u8]) {
        {
            // Contains a lock on the buffer, and a pointer to the data
            let lock_buffer = if self.active {
                Some(self.screen.get_frame_buffer())
            } else { None };

            let mut bytes = s.iter(); // Iterator over bytes
            loop {
                match bytes.next() {
                    Some(byte) => {
                        match byte {
                            0x20..=0x7e => {
                                // printable ASCII byte
                                let screen_character = ScreenCharacter::new(*byte, self.color);
                                let offset = S::WIDTH * self.row + self.column;
                                // Modify this writer's buffer (in host memory)
                                self.buffer[offset] = screen_character;
                                if let Some((_, frame_buffer)) = lock_buffer {
                                    // Write to VGA memory
                                    unsafe {
                                        frame_buffer.add(offset).write_volatile(screen_character);
                                    }
                                }
                                self.column += 1;
                                if self.column == S::WIDTH {
                                    self.column = 0;
                                    self.row += 1;
                                    if self.row == S::HEIGHT {
                                        // Shift upwards
                                        let mut_buffer = self.buffer.as_mut_ptr();
                                        self.scroll_up(mut_buffer);
                                        if let Some((_, frame_buffer)) = lock_buffer {
                                            self.scroll_up(frame_buffer);
                                        }
                                        self.row = S::HEIGHT - 1;
                                    }
                                }
                            }
                            //////////////////////////////////////////
                            // C0 control codes
                            0x8 => { // Backspace
                                if self.column != 0 {
                                    self.column -= 1;
                                }
                            }
                            b'\t' => { // Tab
                                // Move to next multiple of 8
                                self.column += 8 - (self.column % 8);
                                if self.column >= S::WIDTH {
                                    // Next line
                                    self.row += 1;
                                    if self.row == S::HEIGHT {
                                        // Shift upwards
                                        let mut_buffer = self.buffer.as_mut_ptr();
                                        self.scroll_up(mut_buffer);
                                        if let Some((_, frame_buffer)) = lock_buffer {
                                            self.scroll_up(frame_buffer);
                                        }
                                        self.row = S::HEIGHT - 1;
                                    }
                                    self.column = 0;
                                }
                            }
                            b'\n' => { // New line / Line Feed (LF)
                                self.row += 1;
                                if self.row == S::HEIGHT {
                                    // Shift upwards
                                    let mut_buffer = self.buffer.as_mut_ptr();
                                    self.scroll_up(mut_buffer);
                                    if let Some((_, frame_buffer)) = lock_buffer {
                                        self.scroll_up(frame_buffer);
                                    }
                                    self.row = S::HEIGHT - 1;
                                }
                                self.column = 0; // NOTE: Also CR
                            }
                            b'\r' => { // Carriage Return (CR)
                                self.column = 0;
                            }
                            0x1b => { // Escape. Start of escape sequence
                                match bytes.next() {
                                    Some(b'[') => {
                                        // Control Sequence Introducer (CSI)
                                        // <https://en.wikipedia.org/wiki/ANSI_escape_code#CSIsection>
                                        // The ESC [ is followed by any number (including none) of
                                        // "parameter bytes" in the range 0x30–0x3F (ASCII 0–9:;<=>?),
                                        // then by any number of "intermediate bytes" in the range 0x20–0x2F
                                        // (ASCII space and !"#$%&'()*+,-./), then finally by a single
                                        // "final byte" in the range 0x40–0x7E (ASCII @A–Z[\]^_`a–z{|}~).

                                        let mut sequence = String::with_capacity(10);
                                        let mut byte: u8 = match bytes.next() {
                                            Some(byte) => *byte,
                                            None => {return;}
                                        };
                                        // parameter bytes
                                        while byte >= 0x30 && byte <= 0x3F {
                                            sequence.push(byte as char);
                                            byte = match bytes.next() {
                                                Some(byte) => *byte,
                                                None => {return;}
                                            };
                                        }
                                        // intermediate bytes
                                        while byte >= 0x20 && byte <= 0x2F {
                                            sequence.push(byte as char);
                                            byte = match bytes.next() {
                                                Some(byte) => *byte,
                                                None => {return;}
                                            };
                                        }
                                        // Final byte
                                        if byte >= 0x40 && byte <= 0x7E {
                                            sequence.push(byte as char);
                                        } else {
                                            return;
                                        }

                                        // These mainly based on Xterm control sequences
                                        // https://www.xfree86.org/current/ctlseqs.html
                                        match sequence.as_str() {
                                            "@" => { // Blank character

                                            }
                                            "G" => { // Absolute column
                                                self.column = 0;
                                            }
                                            "H" => { // Home (0,0)
                                                self.column = 0;
                                                self.row = 0;
                                            }
                                            "J" | "0J" => { // Erase below
                                                let offset = self.row * S::WIDTH + self.column;
                                                for p in offset..S::SIZE {
                                                    self.buffer[p] = self.blank;
                                                }
                                                if let Some((_, buffer)) = lock_buffer {
                                                    for p in offset..S::SIZE {
                                                        unsafe {
                                                            buffer.add(p).write_volatile(self.blank);
                                                        }
                                                    }
                                                }
                                            }
                                            "1J" => { // Erase above
                                                let offset = self.row * S::WIDTH + self.column;
                                                for p in 0..offset {
                                                    self.buffer[p] = self.blank;
                                                }
                                                if let Some((_, buffer)) = lock_buffer {
                                                    for p in 0..offset {
                                                        unsafe {
                                                            buffer.add(p).write_volatile(self.blank);
                                                        }
                                                    }
                                                }
                                            }
                                            "2J" => { // Erase all
                                                for p in 0..S::SIZE {
                                                    self.buffer[p] = self.blank;
                                                }
                                                if let Some((_, buffer)) = lock_buffer {
                                                    for p in 0..S::SIZE {
                                                        unsafe {
                                                            buffer.add(p).write_volatile(self.blank);
                                                        }
                                                    }
                                                }
                                            }
                                            "K" | "0K" => { // Clear right of cursor

                                                let blank = ScreenCharacter::new(
                                                    b' ', self.color);

                                                for col in self.column..S::WIDTH {
                                                    self.buffer[self.row * S::WIDTH + col] = blank;
                                                }
                                                if let Some((_, buffer)) = lock_buffer {
                                                    for col in self.column..S::WIDTH {
                                                        unsafe {
                                                            buffer.add(self.row * S::WIDTH + col)
                                                                .write_volatile(blank);
                                                        }
                                                    }
                                                }
                                            }
                                            "1K" => { // Clear left of cursor
                                                for col in 0..self.column {
                                                    self.buffer[self.row * S::WIDTH + col] = self.blank;
                                                }
                                                if let Some((_, buffer)) = lock_buffer {
                                                    for col in 0..self.column {
                                                        unsafe {
                                                            buffer.add(self.row * S::WIDTH + col)
                                                                .write_volatile(self.blank);
                                                        }
                                                    }
                                                }
                                            }
                                            "2K" => { // Clear line
                                                for col in 0..S::WIDTH {
                                                    self.buffer[self.row * S::WIDTH + col] = self.blank;
                                                }
                                                if let Some((_, buffer)) = lock_buffer {
                                                    for col in 0..S::WIDTH {
                                                        unsafe {
                                                            buffer.add(self.row * S::WIDTH + col)
                                                                .write_volatile(self.blank);
                                                        }
                                                    }
                                                }
                                            }
                                            "25l" => { // Show cursor (DEC Private Mode Set)
                                                self.cursor_visible = true;
                                                if self.active {
                                                    self.screen.enable_cursor();
                                                }
                                            }
                                            "25h" => { // Hide cursor (DEC Private Mode Reset)
                                                self.cursor_visible = false;
                                                if self.active {
                                                    self.screen.disable_cursor();
                                                }
                                            }
                                            "m" | "0m" => { self.color = Self::default_color(); }
                                            "30m" => { self.color.set_foreground(Color16::Black); }
                                            "31m" => { self.color.set_foreground(Color16::Red); }
                                            "32m" => { self.color.set_foreground(Color16::Green); }
                                            "33m" => { self.color.set_foreground(Color16::Yellow); }
                                            "34m" => { self.color.set_foreground(Color16::Blue); }
                                            "35m" => { self.color.set_foreground(Color16::Magenta); }
                                            "36m" => { self.color.set_foreground(Color16::Cyan); }
                                            "37m" => { self.color.set_foreground(Color16::White); }
                                            "39m" => { self.color.set_foreground(DEFAULT_FOREGROUND); }
                                            "40m" => { self.color.set_background(Color16::Black); }
                                            "41m" => { self.color.set_background(Color16::Red); }
                                            "42m" => { self.color.set_background(Color16::Green); }
                                            "43m" => { self.color.set_background(Color16::Yellow); }
                                            "44m" => { self.color.set_background(Color16::Blue); }
                                            "45m" => { self.color.set_background(Color16::Magenta); }
                                            "46m" => { self.color.set_background(Color16::Cyan); }
                                            "47m" => { self.color.set_background(Color16::White); }
                                            "49m" => { self.color.set_background(DEFAULT_BACKGROUND); }
                                            _ => { }
                                        }
                                    }
                                    _ => {
                                        // Unknown escape sequence
                                        continue;
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                    None => { break; }
                }
            }
        } // Release framebuffer lock
        if self.active {
            self.screen.set_cursor_position(self.row, self.column);
        }
    }
}

lazy_static! {
    /// The text mode handle. This is static because references to it
    /// are held by Writer objects, and those are sent to handler
    /// threads which might outlive the main thread
    static ref TEXT_MODE: Text80x25 = Text80x25::new();
}

#[no_mangle]
fn main() {
    debug_println!("[vga] Hello, world!");

    let mem_handle = match syscalls::receive(&STDIN) {
        Ok(Message::Long(
            message::VIDEO_MEMORY,
            MessageData::Value(length),
            MessageData::MemoryHandle(handle))) => {

            if length != 0x20000 {
                panic!("[vga] Expected 128k video memory buffer. Received {} bytes", length);
            }
            handle
        },
        m => {
            panic!("[vga] Expected video memory message. Received {:?}", m);
        }
    };

    // Set the start of video memory
    vga::vga::VGA.lock().set_memory_start(mem_handle.as_u64() as usize);

    (*TEXT_MODE).set_mode();

    // Make a set of writers. These will be shared with handler threads
    // so that multiple writers can run in parallel
    let mut writers: Vec<Arc<RwLock<Writer<Text80x25>>>> = Vec::new();

    // Pointer to the currently active writer
    let mut active_writer: Option<Arc<RwLock<Writer<Text80x25>>>> = None;

    // Main message loop
    loop {
        match syscalls::receive(&STDIN) {
            // Open a new writer
            Ok(Message::Long(
                message::OPEN_READWRITE, _, _)) |
            Ok(Message::Short(
                message::OPEN_READWRITE, _, _)) => {

                // Make a pair of Rendezvous for communication
                let (handle, client_handle) = syscalls::new_rendezvous()
                    .map_err(|e| {debug_println!("[vga] Couldn't create Rendezvous {:?}", e);}).unwrap();

                // Create a new Writer with buffer etc
                let new_writer = Arc::new(RwLock::new(Writer::new(&*TEXT_MODE)));
                let writer_id = writers.len();
                writers.push(new_writer.clone());

                // Start a new thread to wait on this handle
                thread::spawn(move || {
                    writer_handler(new_writer, handle);
                });

                // Send the handle and ID to the client
                syscalls::send(&STDIN,
                               Message::Long(
                                   message::COMM_HANDLE,
                                   client_handle.into(), (writer_id as u64).into()));
            },

            // Activate a writer
            Ok(Message::Short(
                message::WRITE,
                writer_id, _)) => {

                // Deactivate the current writer (if any)
                if let Some(writer) = active_writer.as_ref() {
                    writer.write().deactivate();
                }

                if let Some(writer) = writers.get(writer_id as usize) {
                    writer.write().activate();
                    active_writer = Some(writer.clone());
                }
            },
            Ok(message) => {
                debug_println!("[vga] unknown message {:?}", message);
            },
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&STDIN,
                               Message::Short(
                                   message::ERROR, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(code) => {
                debug_println!("[vga] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}

fn writer_handler(
    writer: Arc<RwLock<Writer<Text80x25>>>,
    comm_handle: CommHandle) {

    loop {
        match syscalls::receive(&comm_handle) {
            Ok(syscalls::Message::Long(
                message::WRITE,
                MessageData::Value(length),
                MessageData::MemoryHandle(data_handle))) => {

                let data = data_handle.as_slice::<u8>(length as usize);
                writer.write().write_string(data);

                // Done, send reply
                syscalls::send(&comm_handle,
                               syscalls::Message::Short(
                                   message::OK, 0, 0));
            },
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {

                let s : [u8; 1] = [ch as u8];
                writer.write().write_string(&s);
            },
            Ok(message) => {
                // Unknown message => Return error
                syscalls::send(&comm_handle,
                               syscalls::Message::Short(
                                   message::ERROR_UNKNOWN_MESSAGE, 0, 0));
            },
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&STDIN,
                               Message::Short(
                                   message::ERROR, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(code) => {
                debug_println!("[vga] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}
