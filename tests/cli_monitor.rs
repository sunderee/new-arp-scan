//! Integration tests for the listen-only `monitor` subcommand.

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

fn binary_path() -> PathBuf {
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, run `cargo test` from the crate root",
        binary_path.display()
    );
    binary_path
}

#[test]
fn binary_monitor_help_documents_listen_only_behavior_and_privileges() {
    // Arrange
    let binary_path = binary_path();

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["monitor", "--help"])
        .output()
        .expect("spawning monitor --help should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "monitor help should exit successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lowered = stdout.to_lowercase();
    assert!(
        lowered.contains("listen-only") && lowered.contains("without transmitting"),
        "monitor help should say the command is listen-only, got stdout: {stdout}"
    );
    assert!(
        stdout.contains("CAP_NET_RAW") && lowered.contains("root"),
        "monitor help should document the same privileges as scan, got stdout: {stdout}"
    );
    assert!(
        stdout.contains("30000") && stdout.contains("--interface"),
        "monitor help should document the default timeout and interface flag, got stdout: {stdout}"
    );
    assert!(
        stdout.contains("RFC 5227") && lowered.contains("not"),
        "monitor help should say this is not RFC 5227 address conflict detection, got stdout: {stdout}"
    );
}

#[test]
fn binary_monitor_rejects_unknown_flags_and_a_zero_timeout() {
    // Arrange
    let binary_path = binary_path();

    // Act
    let unknown = std::process::Command::new(&binary_path)
        .args(["monitor", "--not-a-real-flag"])
        .output()
        .expect("spawning monitor with an unknown flag should succeed");
    let zero = std::process::Command::new(&binary_path)
        .args(["monitor", "--timeout-ms", "0"])
        .output()
        .expect("spawning monitor with a zero timeout should succeed");

    // Assert
    assert_eq!(
        unknown.status.code(),
        Some(2),
        "an unknown monitor flag should be a usage error, stderr: {}",
        String::from_utf8_lossy(&unknown.stderr)
    );
    assert_eq!(
        zero.status.code(),
        Some(2),
        "a zero monitor timeout should be a usage error, stderr: {}",
        String::from_utf8_lossy(&zero.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn binary_monitor_rejects_loopback_without_transmitting() {
    // Arrange
    let binary_path = binary_path();

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["monitor", "--interface", "lo", "--timeout-ms", "1"])
        .output()
        .expect("spawning monitor on loopback should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(1),
        "loopback must be an operational rejection, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a rejected monitor must not print a listen report, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
