
.PHONY: all build user

all: build

# Build all user programs then kernel
build: user
	cargo build --release --bin kernel

# Build everything then run with QEMU
run : user
	cargo run --release --bin kernel

# List of user programs to build
# Note: init includes many others so should be last
user: user/pci user/rtl8139 user/arp user/tcp user/gopher \
      user/timing_test user/vga_driver user/ramdisk user/shell \
      user/system_test user/init

user/% : FORCE
	cargo build --release --bin $*
	mkdir -p user
	cp target/x86_64-euralios/release/$* user/

# This builds both unit test "user/std_test" and integration test "system_test"
user/system_test: FORCE
	cd euralios_std; cargo test --test system_test --no-run
	@cp $(shell find target/x86_64-euralios/debug/deps/ -maxdepth 1 -name "system_test-*" -executable -print | head -n 1) $@
	@strip $@  # Can't use debugging symbols anyway
	@cp $(shell find target/x86_64-euralios/debug/deps/ -maxdepth 1 -name "euralios_std-*" -executable -print | head -n 1) user/std_test
	@strip user/std_test

FORCE:

# Some shortcuts which build all documentation
doc: FORCE
	cargo doc --document-private-items

doc-open:
	cargo doc --document-private-items --open
