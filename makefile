
.PHONY: all build user

all: build

# Build all user programs then kernel
build: user
	cargo build --release --bin kernel

# Build everything then run with QEMU
run : user
	cargo run --release --bin kernel

# List of user programs to build
user: user/pci user/rtl8139 user/arp user/tcp user/gopher user/timing_test

user/% : FORCE
	cargo build --release --bin $*
	mkdir -p user
	cp target/x86_64-euralios/release/$* user/

FORCE:
