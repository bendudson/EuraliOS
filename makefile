
user/% : FORCE
	cargo build --release --bin $*
	mkdir -p user
	cp target/x86_64-euralios/release/$* user/

FORCE:

.PHONY: run
run : user/hello user/pci user/rtl8139
	cargo run --release --bin kernel
