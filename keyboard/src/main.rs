#![no_std]
#![no_main]

use euralios_std::{debug_print,
                   console::sequences,
                   syscalls::{self, STDOUT},
                   message, ports};
use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1, KeyCode};

#[no_mangle]
fn main() {
    let mut keyboard = Keyboard::new(layouts::Us104Key, ScancodeSet1,
                                     HandleControl::Ignore);

    loop {
        // Wait for an interrupt to occur
        syscalls::await_interrupt();

        let scancode: u8 = ports::inportb(0x60);
        if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
            if let Some(key) = keyboard.process_keyevent(key_event) {
                let chars_be: u64 = match key {
                    DecodedKey::Unicode(character) => {
                        character as u64 // A single character
                    },
                    DecodedKey::RawKey(key) => {
                        match key {
                            // These escape sequences follow the VT convention
                            KeyCode::F1 => sequences::F1,
                            KeyCode::F2 => sequences::F2,
                            KeyCode::F3 => sequences::F3,
                            KeyCode::F4 => sequences::F4,
                            KeyCode::F5 => sequences::F5,
                            KeyCode::F6 => sequences::F6,
                            KeyCode::F7 => sequences::F7,
                            KeyCode::F8 => sequences::F8,
                            KeyCode::F9 => sequences::F9,
                            KeyCode::F10 => sequences::F10,
                            KeyCode::F11 => sequences::F11,
                            KeyCode::F12 => sequences::F12,

                            KeyCode::PageUp   => 0x1b_9b_35_7e, // ESC [ 5 ~
                            KeyCode::PageDown => 0x1b_9b_36_7e, // ESC [ 6 ~
                            KeyCode::Home     => 0x1b_9b_37_7e, // ESC [ 7 ~
                            KeyCode::End      => 0x1b_9b_38_7e, // ESC [ 8 ~
                            _ => {
                                debug_print!("{:?}", key);
                                continue;
                            }
                        }
                    }
                };
                // Send the character(s) in a short message
                syscalls::send(&STDOUT,
                               message::Message::Short(
                                   message::CHAR,
                                   chars_be, 0));
            }
        }
    }
}
