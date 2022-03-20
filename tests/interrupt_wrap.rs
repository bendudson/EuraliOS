// Test that the interrupt wrap! macro enables handler
// functions to access and modify process registers.

#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(blog_os::test_runner)]
#![reexport_test_harness_main = "test_main"]
#![feature(abi_x86_interrupt)]
#![feature(naked_functions)]
#![feature(asm_sym)]

use core::arch::asm;
use core::panic::PanicInfo;

use bootloader::{entry_point, BootInfo};

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use lazy_static::lazy_static;

use blog_os::gdt;
use blog_os::interrupts::{Context, InterruptIndex, PICS};
use blog_os::interrupt_wrap;

entry_point!(main);

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt[InterruptIndex::Timer.as_usize()]
            .set_handler_fn(timer_handler_naked);
        idt
    };
}

fn main(_boot_info: &'static BootInfo) -> ! {
    gdt::init();

    IDT.load();

    unsafe { PICS.lock().initialize() }; // Configure hardware interrupt controller
    x86_64::instructions::interrupts::enable(); // CPU starts listening for hardware interrupts

    test_main();
    loop {}
}

extern "C" fn timer_handler(context: &mut Context) {
    context.r11 = context.rdi + 0x5321;
    context.rcx = 0xdeadbeef;

    // Tell the PIC that the interrupt has been processed
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

interrupt_wrap!(timer_handler => timer_handler_naked);

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    blog_os::test_panic_handler(info)
}

// Tests

#[test_case]
fn handler_changes_regs() {
    unsafe {
        asm!("mov r11, 0x4242",
             "mov rcx, 0x93",
             "mov rdi, 0x22"
        );
    }

    // Wait for an interrupt
    unsafe {asm!("hlt");}

    // Get the register values
    let (r11, rdi, rcx): (i64, i64, i64);
    unsafe {asm!("nop",
                 lateout("r11") r11,
                 lateout("rcx") rcx,
                 lateout("rdi") rdi);}

    assert_eq!(rdi, 0x22);
    assert_eq!(r11, rdi + 0x5321);
    assert_eq!(rcx, 0xdeadbeef);
}
