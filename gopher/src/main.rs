#![no_std]
#![no_main]

extern crate alloc;
use core::str;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::string::ToString;

use euralios_std::{println, print,
                   syscalls::{self, MemoryHandle, STDIN},
                   message::{self, rcall, MessageData}};

fn gopher(host: &str, selector: &str) -> Result<(MemoryHandle, usize), ()> {
    let handle = syscalls::open(host, message::O_READ + message::O_WRITE).expect("Couldn't open");

    let mut path: Vec<u8> = selector
        .as_bytes()           // Convert to u8
        .to_vec();
    path.extend_from_slice(&[0x0D, 0x0A]); // Append CR LF

    let result = rcall(&handle,
                       message::WRITE, (path.len() as u64).into(),
                       syscalls::MemoryHandle::from_u8_slice(path.as_slice()).into(),
                       None);

    println!("[gopher] Write returned: {:?}", result);

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
            println!("[gopher] Read returned: {:?}", result);
            _ = syscalls::send(&handle,
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
            for line in
                (&lines[start_line..end_line])
                .iter() {
                    // First character determines type
                    match line.chars().nth(0) {
                        Some('i') => {
                            // Print text up to the first tab
                            println!("      {}", line[1..].split('\t').next().unwrap_or(""));
                        }
                        Some('0') => {
                            // Text file
                            print!("{}-TXT ", links.len());
                            links.push(line);
                            println!("{}", line[1..].split('\t').next().unwrap_or(""));
                        }
                        Some('1') => {
                            // Gopher menu
                            print!("{}-DIR ", links.len());
                            links.push(line);
                            println!("{}", line[1..].split('\t').next().unwrap_or(""));
                        }
                        Some(_) => {
                            println!("{:?}", line);
                        }
                        None => {
                        }
                    }
                }
        } else {
            // A text file, no links. Just print lines and line number at the end
            for line in (&lines[start_line..end_line]).iter() {
                println!("{}", line);
            }
            println!("Line {}-{}/{} ---- {} ----", start_line, end_line, lines.len(), title);
        }

        // Get user input
        let mut selected_link: Option<&str> = None;
        let mut selected_id: usize = 0;
        loop {
            match syscalls::receive(&STDIN) {
                Ok(syscalls::Message::Short(
                    message::CHAR, ch, _)) => {
                    // Received a character

                    if ch >= ('0' as u64) && ch <= ('9' as u64) {
                        // Character between 0 and 9 selects a link
                        // Successive characters allow choosing links > 9

                        selected_id = (10 * selected_id) +
                            ((ch as usize) - ('0' as usize));

                        if selected_id < links.len() {
                            println!("Link {}: {}", selected_id, links[selected_id]);
                            selected_link = Some(&links[selected_id]);
                        } else {
                            println!("Link {} not on page.", selected_id);
                            selected_link = None;
                        }
                        continue;
                    }

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
                            println!("Enter a number to select a link");
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
                        Some(_) => {
                            // Unrecognised character -> Print help
                            println!("Help: Page up (w or i); Page down (s or k); Select link (0-9); Confirm (Enter)");
                            println!("      Go back (a or j); Forward (d or l); Quit (q)");
                        }
                        None => {
                            // Unknown code. Ignore
                        }
                    }
                    // Reset link ID
                    selected_id = 0;
                    selected_link = None;
                }
                _ => {
                    // Ignore
                }
            }
        }
    }
}

/// Describes a page which can be visited
struct Page {
    host: String, // e.g. "gopher.floodgap.com"
    selector: String, // e.g. ""
    port: u16, // e.g. 70
    is_map: bool // Is this a gophermap?
}

impl Page {
    fn new(host: &str, selector: &str, port: u16, is_map: bool)
           -> Self {
        Page{host: String::from(host),
             selector: String::from(selector),
             port,
             is_map}
    }
}

#[no_mangle]
fn main() {
    // A vector of previous pages visited
    let mut back: Vec<Page> = Vec::new();

    // Pages in the forward direction
    let mut forward: Vec<Page> = Vec::new();

    // Set the landing page
    let mut current_page = Page::new(
        "gopher.floodgap.com", "", 70, true);
    loop {
        let mut path: String = String::from("/tcp/");
        path.push_str(&current_page.host);
        path.push_str("/");
        path.push_str(&current_page.port.to_string());

        let (mem_handle, length) = gopher(&path, &current_page.selector).expect("Couldn't gopher");
        let data = str::from_utf8(mem_handle.as_slice::<u8>(length as usize)).expect("invalid utf8");

        current_page = match display_text(data,
                                          &current_page.host,
                                          current_page.is_map) {
            Command::Quit => {
                println!("[gopher] Bye!");
                return;
            }
            Command::Back => {
                // Remove last page from history
                if let Some(page) = back.pop() {
                    // Save the current page so we can go forward
                    forward.push(current_page);
                    page
                } else {
                    // Can't go back
                    current_page
                }
            }
            Command::Forward => {
                if let Some(page) = forward.pop() {
                    back.push(current_page);
                    page
                } else {
                    // Can't go forward
                    current_page
                }
            }
            Command::Link(link_str) => {
                // Link
                let (_display, selector, hostname, port_str) = {
                    let mut sections = link_str[1..].split('\t');
                    (sections.next().unwrap_or(""),
                     sections.next().unwrap_or(""),
                     sections.next().unwrap_or(""),
                     sections.next().unwrap_or(""))};

                if let Ok(port) = port_str.parse::<u16>() {
                    // Save the curent page and reset forward pages
                    back.push(current_page);
                    forward.clear();

                    Page::new(hostname,
                              selector,
                              port,
                              // Is it a gophermap?
                              link_str.chars().nth(0) == Some('1'))
                } else {
                    // Invalid port => Stay on current page
                    println!("[gopher] invalid port {}", port_str);
                    current_page
                }
            }
        }

    }
}
