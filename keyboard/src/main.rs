#![no_std]
#![no_main]

use euralios_std::{println, debug_print,
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
                match key {
                    DecodedKey::Unicode(character) => {
                        syscalls::send(&STDOUT,
                                       message::Message::Short(
                                           message::CHAR,
                                           character as u64, 0));
                    },
                    DecodedKey::RawKey(key) => {
                        debug_print!("{:?}", key);
                    }
                }
            }
        }
    }
}
