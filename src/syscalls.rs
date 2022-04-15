use crate::println;
use core::arch::asm;
use core::{slice, str};

// register for address of syscall handler
const MSR_STAR: usize = 0xc0000081;
const MSR_LSTAR: usize = 0xc0000082;
const MSR_FMASK: usize = 0xc0000084;

/// Syscall handler jump table
const SYSCALL_NUMBER: usize = 2;
static mut SYSCALL_HANDLERS : [u64; SYSCALL_NUMBER] = [0; SYSCALL_NUMBER];

/// Set up syscall handler
///
/// Note: This depends on the order of the GDT table
///
/// https://nfil.dev/kernel/rust/coding/rust-kernel-to-userspace-and-back/
pub fn init() {
    let handler_addr = handle_syscall as *const () as u64;
    unsafe {
        // Enable System Call Extensions (SCE) to be able to use the
        // syscall/sysret opcodes by setting the last bit in the MSR
        // IA32_EFER
        asm!("mov ecx, 0xC0000080",
             "rdmsr",
             "or eax, 1",
             "wrmsr");

        // clear Trap and Interrupt flag on syscall with AMD's
        // MSR_FMASK register
        asm!("xor rdx, rdx",
             "mov rax, 0x300",
             "wrmsr",
             in("rcx") MSR_FMASK);

        // write handler address to AMD's MSR_LSTAR register
        asm!("mov rdx, rax",
             "shr rdx, 32",
             "wrmsr",
             in("rax") handler_addr,
             in("rcx") MSR_LSTAR);

        // write segments to use on syscall/sysret to AMD'S MSR_STAR register
        asm!(
            "xor rax, rax",
            "mov rdx, 0x230008", // use seg selectors 8, 16 for syscall and 43, 51 for sysret
            "wrmsr",
            in("rcx") MSR_STAR);
    }
    // Insert function pointers into the handler table
    unsafe {
        SYSCALL_HANDLERS = [
            sys_read as u64,
            sys_write as u64
        ];
    }
}

/// Syscall entry point
///
/// This sets up the environment and then calls rust code
/// to perform the actual work.
///
/// Notes:
///  - RBX, RSP, RBP, and R12–R15 should be saved
///  - Caller's RIP is in RCX
///  - Caller's RFLAGS is in R11
///
#[naked]
extern "C" fn handle_syscall() {
    unsafe {
        asm!(
            // Here should switch stack to avoid messing with user stack
            // swapgs seems to be a way to do this
            // - https://github.com/redox-os/kernel/blob/master/src/arch/x86_64/interrupt/syscall.rs#L65
            // - https://www.felixcloutier.com/x86/swapgs
            // backup registers for sysretq
            "push rcx",
            "push r11",
            "push rbp",
            "push rbx", // save callee-saved registers
            "push r12",
            "push r13",
            "push r14",
            "push r15",

            // Call the rust handler function
            "cmp rax, {syscall_max}",
            "jge 1f",  // Out of range
            "mov rax, [{syscall_handlers} + 8*rax]", // Lookup handler address
            "call rax",
            "1: ",

            "pop r15", // restore callee-saved registers
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "pop rbp", // restore stack and registers for sysretq
            "pop r11",
            "pop rcx",
            "sysretq", // back to userland
            syscall_handlers = sym SYSCALL_HANDLERS,
            syscall_max = const SYSCALL_NUMBER,
            options(noreturn));
    }
}

extern "C" fn sys_read() {
    println!("read");
}

extern "C" fn sys_write(ptr: *mut u8, len:usize) {
    // Check all inputs: Does ptr -> ptr+len lie entirely in user address space?
    if len == 0 {
        return;
    }
    // Convert raw pointer to a slice
    let u8_slice = unsafe {slice::from_raw_parts(ptr, len)};

    if let Ok(s) = str::from_utf8(u8_slice) {
        println!("Write '{}'", s);
    } // else error
}
