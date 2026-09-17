.PHONY: build test lint clean coverage fuzz update-mac-vendors

BUNDLED_MAC_VENDOR_FILE ?= tests/fixtures/ieee-mac-registry.txt

build: clean
	cargo build --release

test:
	cargo test --workspace
	cargo test --tests
	NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=$(BUNDLED_MAC_VENDOR_FILE) cargo test --workspace --features bundled-mac-vendors

lint:
	cargo fmt --all
	cargo clippy --all-targets -- -D warnings
	NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=$(BUNDLED_MAC_VENDOR_FILE) cargo clippy --all-targets --all-features -- -D warnings

coverage:
	cargo llvm-cov --workspace --all-targets --summary-only
	NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=$(BUNDLED_MAC_VENDOR_FILE) cargo llvm-cov --workspace --all-targets --features bundled-mac-vendors --summary-only

# Manual, like privileged live ARP scans: needs `cargo install cargo-fuzz` and a nightly
# toolchain, neither of which the stable CI jobs have. FUZZ_SECONDS overrides the duration.
fuzz:
	mkdir -p fuzz/corpus/parse_ethernet_arp
	cp -n fuzz/seeds/parse_ethernet_arp/* fuzz/corpus/parse_ethernet_arp/ || true
	cargo +nightly fuzz run parse_ethernet_arp -- -max_total_time=$(or $(FUZZ_SECONDS),60)

# Fetches IEEE MA-L, MA-M, MA-S, and IAB CSVs with system curl and atomically writes ieee-oui.txt.
# Not run in CI. Requires network plus curl (and date -u).
update-mac-vendors:
	cargo run -p mac-vendor-updater -- --output ieee-oui.txt

clean:
	cargo clean

all: build test lint
