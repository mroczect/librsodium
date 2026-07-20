.PHONY: all build release check test test-verbose fmt fmt-check clippy lint clean run install uninstall ci rebuild snap

all: build

build:
	cargo build

release:
	cargo build --release

check:
	cargo check --workspace

test:
	cargo test --workspace

test-verbose:
	cargo test --workspace -- --nocapture

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy -- -D warnings

lint: fmt clippy

clean:
	cargo clean

run:
	cargo run

install:
	cargo install --path .

uninstall:
	cargo uninstall librsodium

ci: fmt-check clippy test

rebuild:
	make release && make install

snap:
	snapcat tests -f markdown -o dev/tests.snapcat.md && snapcat src -f markdown -o dev/src.snapcat.md

# CLeanCoDe
clcd:
	uncomment -f -r -d src && uncomment -f -r -d tests

reci:
	make fmt && make clcd && make ci && velodiff check