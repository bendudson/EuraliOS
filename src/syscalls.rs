use crate::println;
use core::arch::asm;
use core::{slice, str};

// register for address of syscall handler
const MSR_STAR: usize = 0xc0000081;
const MSR_LSTAR: usize = 0xc0000082;
const MSR_FMASK: usize = 0xc0000084;

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

        // clear Interrupt flag on syscall with AMD's MSR_FSTAR register
        asm!("xor rdx, rdx",
             "mov rax, 0x200",
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
            // backup registers for sysretq
            "push rcx",
            "push r11",
            "push rbp",
            "push rbx", // save callee-saved registers
            "push r12",
            "push r13",
            "push r14",
            "push r15",

            // Call the rust handler
            // Note: Here we should use a jump table, but first need to figure out how to
            //       do that in rust.
            "cmp rax, 0",
            "jne 1f",
            "call {sys_read}",
            "1: cmp rax, 1",
            "jne 2f",
            "call {sys_write}",
            "2: ", // Invalid
            "pop r15", // restore callee-saved registers
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "pop rbp", // restore stack and registers for sysretq
            "pop r11",
            "pop rcx",
            "sysretq", // back to userland
            sys_read = sym sys_read,
            sys_write = sym sys_write,
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
