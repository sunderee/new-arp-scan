//! Integration smoke tests for repository bootstrap.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use new_arp_scan::ApplicationOutcome;
use new_arp_scan::{
    AppError, ApplicationCommand, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING, DEFAULT_SCAN_TIMEOUT,
    ScanWireOptions, run,
};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn run_scan_returns_unsupported_platform_on_unsupported_os() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: Some("eth0".to_string()),
        target_ipv4_address: None,
        timeout: DEFAULT_SCAN_TIMEOUT,
        pacing: DEFAULT_SCAN_PACING,
        attempts: DEFAULT_SCAN_ATTEMPTS,
        rate_limit: None,
        wire: ScanWireOptions::default(),
    };

    // Act
    let outcome = run(command);

    // Assert
    match outcome {
        Err(AppError::UnsupportedPlatform { operating_system }) => {
            assert_eq!(
                operating_system,
                std::env::consts::OS,
                "unsupported platform error should name the actual host operating system"
            );
        }
        Ok(value) => {
            panic!("expected unsupported platform error, got success: {value:?}");
        }
        Err(other) => {
            panic!("expected unsupported platform error, got: {other:?}");
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn run_scan_resolves_a_backend_and_fails_for_unknown_interface_on_macos() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: Some("narp_absent0".to_string()),
        target_ipv4_address: None,
        timeout: DEFAULT_SCAN_TIMEOUT,
        pacing: DEFAULT_SCAN_PACING,
        attempts: DEFAULT_SCAN_ATTEMPTS,
        rate_limit: None,
        wire: ScanWireOptions::default(),
    };

    // Act
    let outcome = run(command);

    // Assert
    match outcome {
        Err(AppError::InterfaceLookupFailed { interface_name, .. }) => {
            assert_eq!(
                interface_name, "narp_absent0",
                "macOS scan should fail to find the unknown interface it was asked to scan"
            );
        }
        Ok(value) => {
            panic!("expected lookup failure for an unknown interface, got success: {value:?}")
        }
        Err(other) => panic!(
            "macOS should resolve a backend (not report unsupported) and fail to find the unknown \
             interface, got: {other:?}"
        ),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn run_usable_interfaces_list_returns_unsupported_platform_on_unsupported_os() {
    // Arrange
    let command = ApplicationCommand::UsableInterfacesList;

    // Act
    let outcome = run(command);

    // Assert
    match outcome {
        Err(AppError::UnsupportedPlatform { operating_system }) => {
            assert_eq!(
                operating_system,
                std::env::consts::OS,
                "unsupported platform error should name the actual host operating system"
            );
        }
        Ok(value) => {
            panic!("expected unsupported platform error, got success: {value:?}");
        }
        Err(other) => {
            panic!("expected unsupported platform error, got: {other:?}");
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn run_usable_interfaces_list_returns_outcome_on_macos() {
    // Arrange
    let command = ApplicationCommand::UsableInterfacesList;

    // Act
    let outcome = run(command);

    // Assert
    let outcome = outcome.expect("usable interfaces listing should succeed on macOS");
    match outcome {
        ApplicationOutcome::UsableInterfacesList(listing) => {
            let table = listing.format_plain_columns_table();
            assert!(
                table.contains("no usable interfaces found")
                    || (table.contains("NAME") && table.contains("INDEX")),
                "public listing should print either the empty-operator message or a header row, got:\n{table}"
            );
        }
        ApplicationOutcome::Scan(_) => {
            panic!("expected usable interfaces list outcome, got scan outcome");
        }
        ApplicationOutcome::Monitor(_) => {
            panic!("expected usable interfaces list outcome, got monitor outcome");
        }
        _ => {
            panic!("expected usable interfaces list outcome");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn run_usable_interfaces_list_returns_outcome_on_linux() {
    // Arrange
    let command = ApplicationCommand::UsableInterfacesList;

    // Act
    let outcome = run(command);

    // Assert
    let outcome = outcome.expect("usable interfaces listing should succeed on Linux");
    match outcome {
        ApplicationOutcome::UsableInterfacesList(listing) => {
            let table = listing.format_plain_columns_table();
            assert!(
                table.contains("no usable interfaces found")
                    || (table.contains("NAME") && table.contains("INDEX")),
                "public listing should print either the empty-operator message or a header row, got:\n{table}"
            );
        }
        ApplicationOutcome::Scan(_) => {
            panic!("expected usable interfaces list outcome, got scan outcome");
        }
        ApplicationOutcome::Monitor(_) => {
            panic!("expected usable interfaces list outcome, got monitor outcome");
        }
        _ => {
            panic!("expected usable interfaces list outcome");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn run_scan_rejects_loopback_interface_on_linux() {
    // Arrange
    let command = ApplicationCommand::Scan {
        interface_name: Some("lo".to_string()),
        target_ipv4_address: None,
        timeout: DEFAULT_SCAN_TIMEOUT,
        pacing: DEFAULT_SCAN_PACING,
        attempts: DEFAULT_SCAN_ATTEMPTS,
        rate_limit: None,
        wire: ScanWireOptions::default(),
    };

    // Act
    let outcome = run(command);

    // Assert
    match outcome {
        Err(AppError::InterfaceRejectedForScanning {
            interface_name,
            reason,
        }) => {
            assert_eq!(
                interface_name, "lo",
                "rejection should name the loopback interface the operator selected"
            );
            assert!(
                reason.to_ascii_lowercase().contains("loopback"),
                "rejection reason should mention loopback, got: {reason}"
            );
        }
        Ok(value) => {
            panic!("expected loopback rejection, got success: {value:?}");
        }
        Err(other) => {
            panic!("expected loopback rejection, got: {other:?}");
        }
    }
}
