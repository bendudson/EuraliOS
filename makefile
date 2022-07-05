
user/% : FORCE
	cargo build --release --bin $*
	mkdir -p user
	cp target/x86_64-euralios/release/$* user/

FORCE:

.PHONY: run
run : user/pci user/rtl8139 user/arp user/tcp user/gopher
	cargo run --release --bin kernel

