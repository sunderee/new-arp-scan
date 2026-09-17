//! Integration tests for `scan` subcommand help (binary subprocess).

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

#[test]
fn binary_scan_help_exits_successfully_and_mentions_interface_flag() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["scan", "--help"])
        .output()
        .expect("spawning scan --help should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "scan --help should exit successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lower = stdout.to_lowercase();
    assert!(
        (stdout.contains("--interface") || stdout.contains("--iface"))
            && stdout.contains("--timeout-ms")
            && stdout.contains("--pacing-ms")
            && stdout.contains("--attempts")
            && stdout.contains("--host")
            && stdout.contains("--mac-vendor-file")
            && stdout.contains("IAB")
            && stdout.contains("--vlan")
            && stdout.contains("--pcp")
            && stdout.contains("--dei")
            && stdout.contains("--padding")
            && stdout.contains("--arpspa")
            && stdout.contains("--llc")
            && stdout.contains("--destaddr")
            && lower.contains("millisecond")
            && lower.contains("round"),
        "scan help should document interface, host, timing, attempts flags with millisecond and inter-round pacing semantics, got: {stdout}"
    );
}
