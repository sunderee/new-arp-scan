//! Integration tests for command-line behavior when no arguments are supplied.

use std::path::PathBuf;

fn new_arp_scan_binary_path() -> PathBuf {
    for environment_key in ["CARGO_BIN_EXE_new_arp_scan", "CARGO_BIN_EXE_new-arp-scan"] {
        if let Some(path) = std::env::var_os(environment_key) {
            return PathBuf::from(path);
        }
    }

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push(profile);
    path.push(if cfg!(target_os = "windows") {
        "new-arp-scan.exe"
    } else {
        "new-arp-scan"
    });
    path
}

/// When the binary is invoked with only the program name, it should print help and exit with
/// success, matching the product requirement for agent-friendly defaults.
#[test]
fn binary_prints_help_and_exits_successfully_when_invoked_with_no_arguments() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .output()
        .expect("spawning the binary without arguments should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "no-argument invocation should exit successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scan")
            && stdout.contains("monitor")
            && stdout.contains("interface")
            && stdout.contains("interfaces"),
        "help output should describe scan, monitor, interfaces, and interface flag, got stdout: {stdout}"
    );
}
