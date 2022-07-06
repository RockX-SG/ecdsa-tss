.PHONY: build
build:
	cargo build --verbose --release
	cp target/release/libecdsa_tss.a lib/linux/amd64

.PHONY: clean
clean:
	rm -rf target

.PHONY: purge
purge:
	rm -rf lib/*
