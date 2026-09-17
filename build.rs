//! Copies the IEEE mapping file into `OUT_DIR` when `bundled-mac-vendors` is enabled.

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_BUNDLED_MAC_VENDORS");
    println!("cargo:rerun-if-env-changed=NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE");

    if env::var_os("CARGO_FEATURE_BUNDLED_MAC_VENDORS").is_none() {
        return;
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("INVARIANT: Cargo sets CARGO_MANIFEST_DIR for build.rs");
    let configured = env::var("NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE")
        .unwrap_or_else(|_| "ieee-oui.txt".to_string());
    let source = resolve_source(&manifest_dir, &configured);
    println!("cargo:rerun-if-changed={}", source.display());
    if !source.is_file() {
        eprintln!(
            "feature `bundled-mac-vendors` requires a mapping file at {} \
             (run `make update-mac-vendors` or set NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE)",
            source.display()
        );
        std::process::exit(1);
    }

    let out_dir = env::var("OUT_DIR").expect("INVARIANT: Cargo sets OUT_DIR for build.rs");
    let destination = PathBuf::from(&out_dir).join("bundled-ieee-oui.txt");
    if let Err(error) = fs::copy(&source, &destination) {
        eprintln!(
            "failed to copy bundled MAC vendor file from {} to {}: {error}",
            source.display(),
            destination.display()
        );
        std::process::exit(1);
    }
    println!(
        "cargo:rustc-env=NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE={}",
        destination.display()
    );
}

fn resolve_source(manifest_dir: &str, configured: &str) -> PathBuf {
    let path = Path::new(configured);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(manifest_dir).join(path)
    }
}
