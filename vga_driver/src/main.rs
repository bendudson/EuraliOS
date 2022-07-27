#![no_std]
#![no_main]

use euralios_std::{debug_println,
                   syscalls, syscalls::STDIN,
                   message, message::MessageData};

use vga;

#[no_mangle]
fn main() {
    debug_println!("[vga] Hello, world!");

    let mem_handle = match syscalls::receive(&STDIN) {
        Ok(syscalls::Message::Long(
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

    use vga::colors::{Color16, TextModeColor};
    use vga::writers::{ScreenCharacter, TextWriter, Text80x25};

    let blank_character = ScreenCharacter::new(
        b' ',
        TextModeColor::new(Color16::White, Color16::White));

    let text_mode = Text80x25::new();
    let color = TextModeColor::new(Color16::Black, Color16::White);
    let screen_character = ScreenCharacter::new(b'T', color);

    text_mode.set_mode();
    text_mode.fill_screen(blank_character);

    text_mode.write_character(10, 11, screen_character);

    text_mode.enable_cursor();
    text_mode.set_cursor_position(10,11);

    loop {
        syscalls::thread_yield();
    }
}
