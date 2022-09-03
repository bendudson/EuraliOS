#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use euralios_std::{print, println};

#[no_mangle]
fn main() {
    println!("EuraliOS system test");
    println!("====================");
    #[cfg(test)]
    test_main();
}

#[cfg(test)]
mod tests {
    #[test_case]
    fn empty_test() {
    }
}

// Custom test framework

pub trait Testable {
    fn run(&self) -> ();
}

// Implement Testable trait for all types with Fn() trait
impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        print!("{}...\t", core::any::type_name::<T>());
        self();
        println!("[ok]");
    }
}

pub fn test_runner(tests: &[&dyn Testable]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
}
