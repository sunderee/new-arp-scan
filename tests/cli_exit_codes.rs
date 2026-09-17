//! Integration tests for binary exit codes (minimal contract: success, library failure, usage).

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
fn binary_exits_with_usage_error_code_for_unknown_root_flag() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["--not-a-real-flag"])
        .output()
        .expect("spawning the binary with an unknown root flag should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown root flag should map to usage exit code 2, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn binary_exits_with_usage_error_code_for_unknown_subcommand() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["not-a-subcommand"])
        .output()
        .expect("spawning the binary with an unknown subcommand should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown subcommand should map to usage exit code 2, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn binary_interfaces_exits_with_operational_failure_on_unsupported_os() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .arg("interfaces")
        .output()
        .expect("spawning interfaces subcommand should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(1),
        "interfaces on an unsupported OS should exit with operational failure code 1, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported") || stderr.contains("Unsupported"),
        "stderr should describe unsupported platform, got: {stderr}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn binary_interfaces_exits_successfully_on_macos() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .arg("interfaces")
        .output()
        .expect("spawning interfaces subcommand should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "interfaces enumeration on macOS needs no privileges and should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn binary_root_help_exits_successfully() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .arg("--help")
        .output()
        .expect("spawning the binary with root --help should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "root help should exit successfully, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("scan") && stdout.contains("interfaces"),
        "root help should mention subcommands, got stdout: {stdout}"
    );
}

#[test]
fn binary_scan_exits_with_operational_failure_for_missing_mac_vendor_file() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args([
            "scan",
            "--mac-vendor-file",
            "/no/such/new-arp-scan-ieee-oui.txt",
        ])
        .output()
        .expect("spawning scan with a missing MAC vendor file should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing --mac-vendor-file must fail before the platform scan path, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to load MAC vendor file")
            && stderr.contains("/no/such/new-arp-scan-ieee-oui.txt"),
        "stderr should name the vendor-file load failure, got: {stderr}"
    );
}

#[test]
fn binary_scan_exits_with_operational_failure_for_invalid_mac_vendor_file() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );
    let path = std::env::temp_dir().join(format!(
        "new-arp-scan-invalid-mac-vendor-cli-{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, "not a mapping line\n").expect("write invalid mapping");

    // Act
    let output = std::process::Command::new(&binary_path)
        .args([
            "scan",
            "--mac-vendor-file",
            path.to_str().expect("temp mapping path should be UTF-8"),
        ])
        .output()
        .expect("spawning scan with an invalid MAC vendor file should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(1),
        "an invalid --mac-vendor-file must fail closed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to load MAC vendor file")
            && stderr.contains("missing a tab separator"),
        "stderr should report the mapping parse error, got: {stderr}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_exits_with_usage_error_code_when_scan_subcommand_receives_unknown_flag() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["scan", "--not-a-real-flag"])
        .output()
        .expect("spawning scan with an unknown flag should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown scan flag should map to usage exit code 2, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn binary_scan_loopback_interface_exits_with_operational_failure_before_raw_socket() {
    // Arrange
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );

    // Act
    let output = std::process::Command::new(&binary_path)
        .args(["scan", "--interface", "lo"])
        .output()
        .expect("spawning scan on loopback should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(1),
        "loopback scan should fail with operational exit code 1 before raw socket, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not suitable")
            || stderr.to_ascii_lowercase().contains("loopback")
            || stderr.contains("CAP_NET_RAW")
            || stderr.contains("permission"),
        "expected loopback rejection or capability denial, not a silent success, stderr: {stderr}"
    );
}

#[test]
fn binary_exits_with_usage_error_code_when_service_vlan_flags_lack_prerequisites() {
    // Arrange: `--svlan` requires `--vlan` to wrap, and `--spcp` / `--sdei` require `--svlan`.
    // Each must be a clap usage error (exit 2), never an operational failure or a silent scan.
    let binary_path = new_arp_scan_binary_path();
    assert!(
        binary_path.is_file(),
        "expected binary at {}, set CARGO_BIN_EXE or run `cargo test` from the crate root",
        binary_path.display()
    );
    let cases: [(&str, &[&str]); 3] = [
        ("--svlan without --vlan", &["scan", "--svlan", "100"]),
        (
            "--spcp without --svlan",
            &["scan", "--vlan", "10", "--spcp", "5"],
        ),
        (
            "--sdei without --svlan",
            &["scan", "--vlan", "10", "--sdei"],
        ),
    ];

    for (name, arguments) in cases {
        // Act
        let output = std::process::Command::new(&binary_path)
            .args(arguments)
            .output()
            .expect("spawning scan with incomplete service VLAN flags should succeed");

        // Assert
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} should map to usage exit code 2, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
