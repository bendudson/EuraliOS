

use core::arch::asm;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use lazy_static::lazy_static;

use crate::println;
use crate::gdt;
use crate::print;

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault.set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
            idt.page_fault.
                set_handler_fn(page_fault_handler).
                set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
            idt.general_protection_fault.
                set_handler_fn(general_protection_fault_handler).
                set_stack_index(gdt::GENERAL_PROTECTION_FAULT_IST_INDEX);
        }
        idt[InterruptIndex::Timer.as_usize()]
            .set_handler_fn(timer_handler_naked);
        idt[InterruptIndex::Keyboard.as_usize()]
            .set_handler_fn(keyboard_interrupt_handler);
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

/// Structure representing values pushed on the stack when an interrupt occurs
#[derive(Debug)]
#[repr(packed)]
pub struct Context {
    // These are pushed in the handler function
    fs: usize,
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    rsi: usize,
    rdi: usize,
    rdx: usize,
    rcx: usize,
    rax: usize,
    // Below is the exception stack frame pushed by the CPU on interrupt
    // Note: For some interrupts (e.g. Page fault), an error code is pushed here
    rip: usize,     // Instruction pointer
    cs: usize,      // Code segment
    rflags: usize,  // Processor flags
    rsp: usize,     // Stack pointer
    ss: usize,      // Stack segment
    // Here the CPU may push values to align the stack on a 16-byte boundary (for SSE)
}

extern "C" fn timer_handler(context: &mut Context) {
    print!("<0x{:x}, 0x{:x}>", context.r11, context.rcx);
    context.r11 = context.rdi + 0x5321;
    context.rcx = 0xdeadbeef;

    // Tell the PIC that the interrupt has been processed
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

/// Handler for the timer interrupt.
///
/// This handler is different from other handlers because it is where
/// context switching is done. This means that we need to push the
/// state of registers on one kernel stack, change kernel stack,
/// and then pop the registers from the new stack.
///
/// Notes:
///  - The calling convention ("x86-interrupt") doesn't have any effect,
///    apart from satisfying the type checker in IDT `set_stack_index`,
///    because the function is [naked].
///  - A naked function is used so that we can control which registers
///    are read and written. During a context switch we want to pop
///    different values to those pushed.
///
#[naked]
pub extern "x86-interrupt" fn timer_handler_naked (_stack_frame: InterruptStackFrame) {
    // Naked functions must consist of a single asm! block
    unsafe{
    asm!(
        // Disable interrupts
        "cli",
        // Push registers
        "push rax
         push rcx
         push rdx
         push rdi
         push rsi
         push r8
         push r9
         push r10
         push r11
         push fs",

        // First argument in rdi with C calling convention
        "mov rdi, rsp",
        // Call the hander function. Note that this might switch stack.
        "call {handler}",

        // Pop scratch registers
        "pop fs
         pop r11
         pop r10
         pop r9
         pop r8
         pop rsi
         pop rdi
         pop rdx
         pop rcx
         pop rax",
        // Enable interrupts
        "sti",
        // Interrupt return
         "iretq",
        // Note: Getting the handler pointer here using `sym` operand, because
        // an `in` operand would clobber a register that we need to save, and we
        // can't have two asm blocks
        handler = sym timer_handler,
        options(noreturn)
    );
    }
}

extern "x86-interrupt" fn breakpoint_handler(
    stack_frame: InterruptStackFrame)
{
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

// Check that execution continues after a breakpoint exception
#[test_case]
fn test_breakpoint_exception() {
    // invoke a breakpoint exception
    x86_64::instructions::interrupts::int3();
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame, _error_code: u64) -> !
{
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

use x86_64::structures::idt::PageFaultErrorCode;
use crate::hlt_loop;

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    println!("EXCEPTION: PAGE FAULT");
    println!("Accessed Address: {:?}", Cr2::read());
    println!("Error Code: {:?}", error_code);
    println!("{:#?}", stack_frame);
    hlt_loop();
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64) {
    panic!("EXCEPTION: GENERAL PROTECTION FAULT\n{:#?}", stack_frame);
}

// PIC 8259 configuration

use pic8259::ChainedPics;
use spin;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

// Hardware interrupts

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use spin::Mutex;
    use x86_64::instructions::port::Port;

    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(layouts::Us104Key, ScancodeSet1,
                HandleControl::Ignore)
            );
    }

    let mut keyboard = KEYBOARD.lock();
    let mut port = Port::new(0x60);

    let scancode: u8 = unsafe { port.read() };
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => print!("{}", character),
                DecodedKey::RawKey(key) => print!("{:?}", key),
            }
        }
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
