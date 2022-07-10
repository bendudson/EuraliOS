

use core::arch::asm;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use lazy_static::lazy_static;

use crate::println;
use crate::gdt;
use crate::print;
use crate::process;
use crate::memory;

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
            idt[InterruptIndex::Timer.as_usize()]
                .set_handler_fn(timer_handler_naked)
                .set_stack_index(gdt::TIMER_INTERRUPT_INDEX);
            idt[InterruptIndex::Keyboard.as_usize()]
                .set_handler_fn(keyboard_interrupt_handler)
                .set_stack_index(gdt::KEYBOARD_INTERRUPT_INDEX);
        }
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

/// Structure representing values pushed on the stack when an interrupt occurs
///
/// CPU registers in x86-64 mode
///   https://wiki.osdev.org/CPU_Registers_x86-64
///
/// Note: Is repr(packed) needed? No padding should be inserted
///       since all fields are usize.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Context {
    // These are pushed in the handler function
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,

    pub r12: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,

    pub r8: usize,
    pub rbp: usize,
    pub rsi: usize,
    pub rdi: usize,

    pub rdx: usize,
    pub rcx: usize,
    pub rbx: usize,
    pub rax: usize,
    // Below is the exception stack frame pushed by the CPU on interrupt
    // Note: For some interrupts (e.g. Page fault), an error code is pushed here
    pub rip: usize,     // Instruction pointer
    pub cs: usize,      // Code segment
    pub rflags: usize,  // Processor flags
    pub rsp: usize,     // Stack pointer
    pub ss: usize,      // Stack segment
    // Here the CPU may push values to align the stack on a 16-byte boundary (for SSE)
}

/// Number of bytes needed to store a Context struct
pub const INTERRUPT_CONTEXT_SIZE: usize = 20 * 8;

extern "C" fn timer_handler(context_addr: usize) -> usize {
    // Process scheduler decides which process to schedule
    // Returns the stack pointer to switch to.
    let next_stack = process::schedule_next(context_addr);

    // Tell the PIC that the interrupt has been processed
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
    next_stack
}

/// Interrupt handler wrapper which captures a Context
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
///  - If a handler uses this wrapper then the TSS index (gdt.rs)
///    should be the same as TIMER_INTERRUPT_INDEX, unique to each thread.
///
/// Macro wrapper adapted from MOROS by Vincent Ollivier
/// https://github.com/vinc/moros/blob/trunk/src/sys/idt.rs#L123
#[macro_export]
macro_rules! interrupt_wrap {
    ($func: ident => $wrapper:ident) => {
        #[naked]
        pub extern "x86-interrupt" fn $wrapper (_stack_frame: InterruptStackFrame) {
            // Naked functions must consist of a single asm! block
            unsafe{
                asm!(
                    // Disable interrupts
                    "cli",
                    // Push registers
                    "push rax",
                    "push rbx",
                    "push rcx",
                    "push rdx",

                    "push rdi",
                    "push rsi",
                    "push rbp",
                    "push r8",

                    "push r9",
                    "push r10",
                    "push r11",
                    "push r12",

                    "push r13",
                    "push r14",
                    "push r15",

                    // First argument in rdi with C calling convention
                    "mov rdi, rsp",
                    // Call the hander function
                    "call {handler}",

                    // New stack pointer is in RAX
                    // (C calling convention return value)
                    "cmp rax, 0",
                    "je 2f", // If RAX is zero, keep stack
                    "mov rsp, rax",
                     "2:",

                    // Pop scratch registers from new stack
                    "pop r15",
                    "pop r14",
                    "pop r13",

                    "pop r12",
                    "pop r11",
                    "pop r10",
                    "pop r9",

                    "pop r8",
                    "pop rbp",
                    "pop rsi",
                    "pop rdi",

                    "pop rdx",
                    "pop rcx",
                    "pop rbx",
                    "pop rax",
                    // Enable interrupts
                    "sti",
                    // Interrupt return
                    "iretq",
                    // Note: Getting the handler pointer here using `sym` operand, because
                    // an `in` operand would clobber a register that we need to save, and we
                    // can't have two asm blocks
                    handler = sym $func,
                    options(noreturn)
                );
            }
        }
    };
}

interrupt_wrap!(timer_handler => timer_handler_naked);

/// Run a thread by using `iret`
pub fn launch_thread(context_addr: usize) -> ! {
    unsafe {
        asm!("mov rsp, rdi", // Set the stack to the Context address

             // Pop scratch registers from new stack
             "pop r15",
             "pop r14",
             "pop r13",

             "pop r12",
             "pop r11",
             "pop r10",
             "pop r9",

             "pop r8",
             "pop rbp",
             "pop rsi",
             "pop rdi",

             "pop rdx",
             "pop rcx",
             "pop rbx",
             "pop rax",
             // Enable interrupts
             "sti",
             // Interrupt return
             "iretq",
             in("rdi") context_addr,
             options(noreturn));
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
    let accessed_virtaddr = Cr2::read();

    if error_code == (PageFaultErrorCode::PROTECTION_VIOLATION |
                      PageFaultErrorCode::CAUSED_BY_WRITE |
                      PageFaultErrorCode::USER_MODE) {
        // User code tried to access a read-only page
        // Missing stack or heap frame

        if let Err(msg) = memory::allocate_missing_ondemand_frame(accessed_virtaddr) {
            println!("Page fault error: {}", msg);
            hlt_loop();
        }
    } else {
        println!("EXCEPTION: PAGE FAULT");
        println!("Accessed Address: {:?}", accessed_virtaddr);
        println!("Error Code: {:?}", error_code);
        println!("{:#?}", stack_frame);

        hlt_loop();
    }
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
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

use alloc::sync::Arc;
use spin::RwLock;
use crate::rendezvous::{Rendezvous, MESSAGE_TYPE_CHAR};
use crate::message::Message;

lazy_static! {
    static ref KEYBOARD_RENDEZVOUS: Arc<RwLock<Rendezvous>> =
        Arc::new(RwLock::new(Rendezvous::Empty));
}

/// Get a shared reference to the keyboard Rendezvous object.
/// The keyboard interrupt handler will send messages to this.
pub fn keyboard_rendezvous() -> Arc<RwLock<Rendezvous>> {
    KEYBOARD_RENDEZVOUS.clone()
}

interrupt_wrap!(keyboard_handler_inner => keyboard_interrupt_handler);

extern "C" fn keyboard_handler_inner(context_addr: usize)
                                     -> usize
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

    let mut returning = true; // Back to original thread?

    let scancode: u8 = unsafe { port.read() };
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => {
                    let (thread1, thread2) =
                        KEYBOARD_RENDEZVOUS.write().send(
                            None,
                            Message::Short(MESSAGE_TYPE_CHAR,
                                           character as u64, 0));
                    // thread1 should be scheduled to run next
                    if let Some(t) = thread2 {
                        process::schedule_thread(t);
                    }
                    if let Some(t) = thread1 {
                        process::schedule_thread(t);
                        returning = false;
                    }
                },
                DecodedKey::RawKey(key) => print!("{:?}", key),
            }
        }
    }

    let next_context = if returning {context_addr} else {
        // Schedule a different thread to run
        process::schedule_next(context_addr)
    };

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
    next_context
}
