#![no_std]
#![no_main]

extern crate alloc;
use alloc::boxed::Box;
use core::str;
use alloc::vec::Vec;

use euralios_std::{debug_println, debug_print,
                   syscalls::{self, MemoryHandle, STDIN},
                   message::{self, rcall, MessageData},
                   thread};

fn gopher(host: &str, path: &str) -> Result<(MemoryHandle, usize), ()> {
    let handle = syscalls::open(host).expect("Couldn't open");

    let mut path: Vec<u8> = path
        .as_bytes()           // Convert to u8
        .to_vec();
    path.extend_from_slice(&[0x0D, 0x0A]); // Append CR LF

    let result = rcall(&handle,
                       message::WRITE, (path.len() as u64).into(),
                       syscalls::MemoryHandle::from_u8_slice(path.as_slice()).into(),
                       None);

    debug_println!("[gopher] Write returned: {:?}", result);

    match rcall(&handle,
                message::READ, 0.into(),
                0.into(),
                None) {
        Ok((message::DATA,
            MessageData::Value(length),
            MessageData::MemoryHandle(mem_handle))) => {
            syscalls::send(&handle,
                           syscalls::Message::Short(
                               message::CLOSE, 0, 0));
            return Ok((mem_handle, length as usize));
        }
        result => {
            debug_println!("[gopher] Read returned: {:?}", result);
            syscalls::send(&handle,
                           syscalls::Message::Short(
                               message::CLOSE, 0, 0));
            return Err(());
        }
    }
}

enum Command<'a> {
    Quit,
    Back,
    Forward,
    Link(&'a str)
}

/// Display gophermap or text
///
/// Returns a Command, which may be a Link containing a reference
/// to part of the input data.
fn display_text<'a>(
    data: &'a str,   // The text to display in pages
    title: &str,     // A short document title
    gophermap: bool  // True if data should consist of links
) -> Command<'a> {
    let lines_per_page = 24; // Last line for status
    let lines_paginate = 20; // How many lines to move each page
    
    // Split data into lines
    let lines = data.lines().collect::<Vec<&str>>();
    let mut start_line = 0; // First line to display
    loop {
        let end_line = if start_line + lines_per_page > lines.len() {lines.len()} else {
            start_line + lines_per_page
        };

        // Links shown on the page
        let mut links: Vec<&str> = Vec::new();

        // Draw the page
        if gophermap {
            // Indent lines, add numbers, type to links
            for (line_nr, line) in
                (&lines[start_line..end_line])
                .iter()
                .enumerate() {
                    // First character determines type
                    match line.chars().nth(0) {
                        Some('i') => {
                            // Print text up to the first tab
                            debug_println!("      {}", line[1..].split('\t').next().unwrap_or(""));
                        }
                        Some('0') => {
                            // Text file
                            debug_print!("{}-TXT ", links.len());
                            links.push(line);
                            debug_println!("{}", line[1..].split('\t').next().unwrap_or(""));
                        }
                        Some('1') => {
                            // Gopher menu
                            debug_print!("{}-DIR ", links.len());
                            links.push(line);
                            debug_println!("{}", line[1..].split('\t').next().unwrap_or(""));
                        }
                        Some(c) => {
                            debug_println!("{:?}", line);
                        }
                        None => {
                        }
                    }
                }
        } else {
            // A text file, no links. Just print lines and line number at the end
            for line in (&lines[start_line..end_line]).iter() {
                debug_println!("{}", line);
            }
            debug_println!("Line {}-{}/{} ---- {} ----", start_line, end_line, lines.len(), title);
        }

        // Get user input
        let mut selected_link: Option<&str> = None;
        loop {
            match syscalls::receive(&STDIN) {
                Ok(syscalls::Message::Short(
                    syscalls::MESSAGE_TYPE_CHAR, ch, _)) => {
                    // Received a character
                    match char::from_u32(ch as u32) {
                        // up/down => Change page
                        // WASD or IJKL
                        Some('w') | Some('i') => {
                            // Shift page up
                            if start_line < lines_paginate {
                                start_line = 0;
                            } else {
                                start_line -= lines_paginate;
                            }
                            break; // Need to re-draw
                        }
                        Some('s') | Some('k') => {
                            if start_line + lines_per_page < lines.len() {
                                start_line += lines_paginate;
                            }
                            break; // Could just print extra lines
                        }
                        // Enter => Select
                        Some('\n') => {
                            // Confirm selection
                            if let Some(line) = selected_link {
                                return Command::Link(line);
                            }
                        }
                        // Left/right => history forward/back
                        Some('a') | Some('j') => {
                            return Command::Back;
                        }
                        Some('d') | Some('l') => {
                            return Command::Forward;
                        }
                        // q => quit
                        Some('q') => {
                            return Command::Quit;
                        }
                        Some('h') | Some('?') => {
                            // Help
                            debug_println!("Help: Page up (w or i); Page down (s or k); Select link (0-9); Confirm (Enter)");
                            debug_println!("      Go back (a or j); Forward (d or l); Quit (q)");
                        }
                        Some(c) => {
                            // Character between 0 and 9 selects a link
                            let selected = ((c as u32) - ('0' as u32)) as usize;
                            if selected >= 0 && selected < links.len() {
                                debug_println!("Link {}: {}", selected, links[selected]);
                                selected_link = Some(&links[selected]);
                            }
                        }
                        None => {
                            // Unknown code. Ignore
                        }
                    }
                }
                _ => {
                    // Ignore
                }
            }
        }
    }
}

#[no_mangle]
fn main() {
    debug_println!("[gopher] Hello, world!");

    let mut back_data: Option<(MemoryHandle, usize)> = None;
    let mut forward_data: Option<(MemoryHandle, usize)> = None;
    loop {

        let (mem_handle, length) = gopher("/tcp/192.80.49.99/70", "").expect("Couldn't gopher");
        let data = str::from_utf8(mem_handle.as_slice::<u8>(length as usize)).expect("invalid utf8");
        display_text(data, "gopher.floodgap.com", true);

    }
}
