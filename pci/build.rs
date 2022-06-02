fn main() {
    println!("cargo:rustc-link-arg=-Ttext-segment=5000000");
    println!("cargo:rustc-link-arg=-Trodata-segment=5100000");
}
