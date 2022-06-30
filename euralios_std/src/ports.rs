//! Functions for input and output to I/O ports

use core::arch::asm;

pub fn outportb(ioaddr: u16, value: u8) {
    unsafe {
        asm!("out dx, al",
             in("dx") ioaddr,
             in("al") value,
             options(nomem, nostack));
    }
}

/// Write a word (16 bits) to a port
pub fn outportw(ioaddr: u16, value: u16) {
    unsafe {
        asm!("out dx, ax",
             in("dx") ioaddr,
             in("ax") value,
             options(nomem, nostack));
    }
}

/// Write a double word (32 bits) to a port
pub fn outportd(ioaddr: u16, value: u32) {
    unsafe {
        asm!("out dx, eax",
             in("dx") ioaddr,
             in("eax") value,
             options(nomem, nostack));
    }
}

/// Read a byte from a port
pub fn inportb(ioaddr: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx",
             in("dx") ioaddr,
             lateout("al") value,
             options(nomem, nostack));
    }
    value
}

/// Read a word (16 bits) from a port
pub fn inportw(ioaddr: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx",
             in("dx") ioaddr,
             lateout("ax") value,
             options(nomem, nostack));
    }
    value
}

pub fn inportd(ioaddr: u16) -> u32 {
    let value: u32;
    unsafe {
        asm!("in eax, dx",
             in("dx") ioaddr,
             lateout("eax") value,
             options(nomem, nostack));
    }
    value
}
