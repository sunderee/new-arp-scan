//! Library entry points for the new ARP scan tool.

pub mod application_command;
pub mod application_outcome;
pub mod cli;
pub mod error;
pub mod mac_address;
pub mod mac_vendor_registry;

mod address_resolution_protocol;
mod ethernet_frame;
mod interface_validation;
mod ipv4_cidr;
mod ipv4_subnet;
mod link_layer_backend;
mod monitor;
mod scan_timing;
mod scanner;

#[cfg(test)]
mod protocol_conformance;

#[cfg(target_os = "linux")]
mod linux_interface_discovery;
#[cfg(target_os = "linux")]
mod linux_monitor;
#[cfg(target_os = "linux")]
mod linux_packet;
#[cfg(target_os = "linux")]
mod linux_scanner;
#[cfg(target_os = "linux")]
mod linux_socket;
#[cfg(target_os = "linux")]
mod linux_system_call;

#[cfg(target_os = "macos")]
mod macos_bpf_socket;
#[cfg(target_os = "macos")]
mod macos_interface_discovery;
#[cfg(target_os = "macos")]
mod macos_monitor;
#[cfg(target_os = "macos")]
mod macos_packet;
#[cfg(target_os = "macos")]
mod macos_scanner;
#[cfg(target_os = "macos")]
mod macos_system_call;

pub use address_resolution_protocol::{
    build_address_resolution_announcement_ethernet_frame,
    build_address_resolution_probe_ethernet_frame, build_address_resolution_request_ethernet_frame,
    build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag,
    try_parse_address_resolution_reply_ipv4_over_ethernet,
};
pub use application_command::{
    ApplicationCommand, ArpSenderProtocolAddress, DEFAULT_MONITOR_TIMEOUT,
    DEFAULT_RETRY_BACKOFF_FACTOR, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING, DEFAULT_SCAN_TIMEOUT,
    InterTargetSendRate, PositiveDuration, RateLimitedScanTiming, RetryBackoffFactor,
    ScanWireOptions,
};
pub use application_outcome::ApplicationOutcome;
pub use application_outcome::DiscoveredHost;
pub use application_outcome::MonitorOutcome;
pub use application_outcome::ScanOutcome;
pub use application_outcome::ScanTimingSummary;
pub use application_outcome::UsableInterfaceListingRow;
pub use application_outcome::UsableInterfacesListOutcome;
pub use error::AppError;
pub use error::ScanTimingLimit;
pub use ethernet_frame::{
    Ieee8021qPriorityCodePoint, Ieee8021qTagControlInformation, Ieee8021qVlanIdentifier,
};
pub use ipv4_cidr::Ipv4Cidr;
pub use ipv4_cidr::Ipv4HostAddressIterator;
pub use mac_address::{MacAddress, MacAddressParseError};
pub use mac_vendor_registry::{
    DEFAULT_MAC_VENDOR_FILE_NAME, MacVendorRegistry, MacVendorRegistryParseError,
    UNKNOWN_MAC_VENDOR_NAME,
};
pub use monitor::{DuplicateIpClaim, MonitorListenOutcome, PassiveArpClass, PassiveArpRecord};

#[cfg(target_os = "linux")]
pub use linux_scanner::perform_arp_probe;

/// Runs the application logic for a parsed [`ApplicationCommand`].
///
/// On Linux, [`ApplicationCommand::Scan`] performs address resolution scanning on the resolved
/// interface and returns discovered hosts. When `target_ipv4_address` is [`None`], the library
/// scans the full interior host set for that interface subnet. When it is [`Some`], the library
/// sends requests only for that address (which must be strictly interior on the subnet) and
/// records replies only from that sender IPv4. The `timeout` field bounds the global receive
/// window after the last request is sent; the `pacing` field sleeps after each full round of target
/// sends except the last round; the `attempts` field is how many such rounds run. `rate_limit`
/// opts into strict inter-target spacing and per-round retry backoff; when it is [`None`], each
/// round still bursts every target. The `wire` field
/// selects IEEE 802.1Q tagging, RFC 826 `ar$spa` (including RFC 5227 Probe/Announcement),
/// Ethernet `--destaddr`/`--srcaddr`, remaining RFC 826 `ar$*` fields, RFC 1042 LLC/SNAP
/// framing, IEEE 802.1Q PCP/DEI, and custom `--padding`. When the scan
/// command omits an interface name, the library selects an interface automatically only when
/// exactly one usable interface exists. On Linux, successful scans populate
/// [`application_outcome::ScanOutcome::timing_summary`] with wall-clock timing, the resolved
/// interface name, round count, and discovered host count for operator-facing summaries.
///
/// On Linux and macOS, [`ApplicationCommand::Monitor`] listens on the resolved interface without
/// transmitting. `timeout` must be greater than zero. The outcome reports local-address conflicts,
/// ordinary ARP observations, and third-party duplicate claims. It is not an RFC 5227 address
/// conflict detection implementation.
///
/// On Linux, [`ApplicationCommand::UsableInterfacesList`] returns interfaces that pass the same
/// usability rules as automatic scan selection.
///
/// On other operating systems, Linux-only commands return [`AppError::UnsupportedPlatform`].
///
/// # Errors
///
/// Returns [`AppError`] for invalid input, unsupported platforms, interface validation failures,
/// discovery failures, socket failures, and fatal receive or poll failures. A monitor timeout of
/// zero is [`AppError::MonitorTimeoutRejected`] before discovery or a socket is opened.
///
/// # Examples
///
/// ```
/// use new_arp_scan::{
///     run, ApplicationCommand, AppError, ApplicationOutcome, DEFAULT_SCAN_ATTEMPTS,
///     DEFAULT_SCAN_PACING, DEFAULT_SCAN_TIMEOUT, ScanWireOptions,
/// };
///
/// let outcome = run(ApplicationCommand::Scan {
///     interface_name: Some("eth0".to_string()),
///     target_ipv4_address: None,
///     timeout: DEFAULT_SCAN_TIMEOUT,
///     pacing: DEFAULT_SCAN_PACING,
///     attempts: DEFAULT_SCAN_ATTEMPTS,
///     rate_limit: None,
///     wire: ScanWireOptions::default(),
/// });
///
/// // On Linux and macOS this attempts a real scan (which may fail without privileges or for an
/// // unknown interface); only operating systems without a raw link-layer backend report
/// // `UnsupportedPlatform`.
/// # #[cfg(not(any(target_os = "linux", target_os = "macos")))]
/// assert!(
///     matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
///     "expected unsupported platform on operating systems without a backend, got: {outcome:?}"
/// );
/// # #[cfg(any(target_os = "linux", target_os = "macos"))]
/// # {
/// #     let _ = outcome;
/// # }
/// ```
pub fn run(command: ApplicationCommand) -> Result<ApplicationOutcome, AppError> {
    match command {
        ApplicationCommand::Scan {
            interface_name,
            target_ipv4_address,
            timeout,
            pacing,
            attempts,
            rate_limit,
            wire,
        } => run_address_resolution_scan(
            interface_name.as_deref(),
            target_ipv4_address,
            timeout,
            pacing,
            attempts,
            wire,
            rate_limit,
        ),
        ApplicationCommand::Monitor {
            interface_name,
            timeout,
        } => run_passive_arp_monitor(interface_name.as_deref(), timeout),
        ApplicationCommand::UsableInterfacesList => {
            #[cfg(target_os = "linux")]
            {
                let candidates =
                    linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates()?;
                Ok(usable_interfaces_outcome_from_candidates(candidates))
            }

            #[cfg(target_os = "macos")]
            {
                let candidates =
                    macos_interface_discovery::enumerate_usable_arp_scan_interface_candidates()?;
                Ok(usable_interfaces_outcome_from_candidates(candidates))
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Err(AppError::UnsupportedPlatform {
                    operating_system: std::env::consts::OS.to_string(),
                })
            }
        }
    }
}

fn run_passive_arp_monitor(
    interface_name: Option<&str>,
    timeout: std::time::Duration,
) -> Result<ApplicationOutcome, AppError> {
    monitor::monitor_deadline(&scan_timing::SystemScanClock, timeout)?;
    if let Some(name) = interface_name {
        interface_validation::validate_interface_name_for_linux_packet_socket(name)?;
    }

    #[cfg(target_os = "linux")]
    {
        let resolved_interface_name =
            linux_interface_discovery::resolve_scan_interface_name(interface_name)?;
        let started = std::time::Instant::now();
        let report = linux_monitor::perform_passive_arp_monitor(&resolved_interface_name, timeout)?;
        Ok(ApplicationOutcome::Monitor(MonitorOutcome::from_listen(
            resolved_interface_name,
            started.elapsed(),
            report,
        )))
    }

    #[cfg(target_os = "macos")]
    {
        let resolved_interface_name =
            macos_interface_discovery::resolve_scan_interface_name(interface_name)?;
        let started = std::time::Instant::now();
        let report = macos_monitor::perform_passive_arp_monitor(&resolved_interface_name, timeout)?;
        Ok(ApplicationOutcome::Monitor(MonitorOutcome::from_listen(
            resolved_interface_name,
            started.elapsed(),
            report,
        )))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface_name;
        Err(AppError::UnsupportedPlatform {
            operating_system: std::env::consts::OS.to_string(),
        })
    }
}

fn run_address_resolution_scan(
    interface_name: Option<&str>,
    target_ipv4_address: Option<std::net::Ipv4Addr>,
    timeout: std::time::Duration,
    pacing: std::time::Duration,
    attempts: std::num::NonZeroU64,
    wire: ScanWireOptions,
    rate_limit: Option<crate::application_command::RateLimitedScanTiming>,
) -> Result<ApplicationOutcome, AppError> {
    wire.validate_ieee_8021q_tag_stack()?;
    wire.validate_ieee_8023_mac_client_data()?;
    scan_timing::validate_scan_timing_before_socket(timeout, pacing, attempts, &wire, rate_limit)?;
    if let Some(interface_name) = interface_name {
        interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    }

    #[cfg(target_os = "linux")]
    {
        let resolved_interface_name =
            linux_interface_discovery::resolve_scan_interface_name(interface_name)?;
        let scan_wall_clock_started = std::time::Instant::now();
        let scan_outcome = match target_ipv4_address {
            Some(target_ipv4_address) => linux_scanner::perform_arp_probe(
                &resolved_interface_name,
                target_ipv4_address,
                timeout,
                pacing,
                attempts,
                wire,
                rate_limit,
            )?,
            None => linux_scanner::perform_arp_scan(
                &resolved_interface_name,
                timeout,
                pacing,
                attempts,
                wire,
                rate_limit,
            )?,
        };
        let scan_outcome = scan_outcome.with_scan_timing_summary(
            resolved_interface_name,
            scan_wall_clock_started.elapsed(),
            attempts,
        );
        Ok(ApplicationOutcome::Scan(scan_outcome))
    }

    #[cfg(target_os = "macos")]
    {
        let resolved_interface_name =
            macos_interface_discovery::resolve_scan_interface_name(interface_name)?;
        let scan_wall_clock_started = std::time::Instant::now();
        let scan_outcome = match target_ipv4_address {
            Some(target_ipv4_address) => macos_scanner::perform_arp_probe(
                &resolved_interface_name,
                target_ipv4_address,
                timeout,
                pacing,
                attempts,
                wire,
                rate_limit,
            )?,
            None => macos_scanner::perform_arp_scan(
                &resolved_interface_name,
                timeout,
                pacing,
                attempts,
                wire,
                rate_limit,
            )?,
        };
        let scan_outcome = scan_outcome.with_scan_timing_summary(
            resolved_interface_name,
            scan_wall_clock_started.elapsed(),
            attempts,
        );
        Ok(ApplicationOutcome::Scan(scan_outcome))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // No raw link-layer backend on this operating system; the timing and target
        // parameters are intentionally unused on the unsupported path.
        let _ = (
            &target_ipv4_address,
            &timeout,
            &pacing,
            &attempts,
            &wire,
            &rate_limit,
        );
        Err(AppError::UnsupportedPlatform {
            operating_system: std::env::consts::OS.to_string(),
        })
    }
}

/// Builds a [`UsableInterfacesList`](ApplicationOutcome::UsableInterfacesList) outcome from the
/// shared interface candidates produced by a platform discovery backend.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn usable_interfaces_outcome_from_candidates(
    candidates: Vec<link_layer_backend::ArpScanInterfaceCandidate>,
) -> ApplicationOutcome {
    let entries = candidates
        .into_iter()
        .map(|candidate| application_outcome::UsableInterfaceListingRow {
            interface_name: candidate.interface_name,
            interface_index: candidate.interface_index,
            ipv4_address: candidate.source_ipv4_address,
            ipv4_netmask: candidate.ipv4_netmask,
            media_access_control_address: candidate.source_mac_address,
        })
        .collect();

    ApplicationOutcome::UsableInterfacesList(application_outcome::UsableInterfacesListOutcome {
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use super::ApplicationCommand;
    use super::DEFAULT_SCAN_ATTEMPTS;
    use super::DEFAULT_SCAN_PACING;
    use super::DEFAULT_SCAN_TIMEOUT;
    use super::InterTargetSendRate;
    use super::PositiveDuration;
    use super::RateLimitedScanTiming;
    use super::RetryBackoffFactor;
    use super::ScanTimingLimit;
    use super::ScanWireOptions;
    use super::run;

    #[test]
    fn rejects_an_unrepresentable_retry_window_before_interface_discovery() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: None,
            timeout: std::time::Duration::from_secs(3),
            pacing: DEFAULT_SCAN_PACING,
            attempts: std::num::NonZeroU64::new(10_000).expect("ten thousand rounds"),
            rate_limit: Some(RateLimitedScanTiming::new(
                InterTargetSendRate::Interval(
                    PositiveDuration::new(std::time::Duration::from_millis(1))
                        .expect("one millisecond is positive"),
                ),
                RetryBackoffFactor::new(1.5).expect("1.5 is a valid backoff"),
            )),
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::RetryReceiveWindow
                })
            ),
            "overflowing backoff must fail before interface discovery or a raw socket, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_invalid_interface_name_when_interface_name_is_empty_on_non_linux_even_with_target() {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some(String::new()),
            target_ipv4_address: Some(Ipv4Addr::new(1, 1, 1, 1)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty interface name should be rejected before platform checks even with a target, got: {outcome:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn returns_invalid_interface_name_when_interface_name_is_empty_on_non_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some(String::new()),
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
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty interface name should be rejected before platform checks, got: {outcome:?}"
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn returns_unsupported_platform_when_scanning_on_unsupported_os() {
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
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "unsupported hosts should report unsupported platform, got: {outcome:?}"
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn returns_unsupported_platform_when_scanning_on_unsupported_os_even_with_custom_scan_timing() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: std::time::Duration::from_mins(1),
            pacing: std::time::Duration::from_millis(999),
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "custom scan timing must not bypass unsupported platform handling, got: {outcome:?}"
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn returns_unsupported_platform_when_scanning_on_unsupported_os_with_target_ipv4_address_set() {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(9, 9, 9, 9)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "unsupported hosts should reject scan before backend dispatch, got: {outcome:?}"
        );
    }

    #[test]
    fn monitor_rejects_an_unrepresentable_deadline_before_discovery() {
        // Arrange
        let command = ApplicationCommand::Monitor {
            interface_name: Some("eth0".to_string()),
            timeout: std::time::Duration::MAX,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::MonotonicDeadline,
                })
            ),
            "Duration::MAX must fail the monotonic deadline check, got: {outcome:?}"
        );
    }

    #[test]
    fn monitor_rejects_zero_timeout_before_using_the_interface_name() {
        // Arrange
        let command = ApplicationCommand::Monitor {
            interface_name: Some(String::new()),
            timeout: std::time::Duration::ZERO,
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::MonitorTimeoutRejected)),
            "a zero monitor timeout must fail before interface validation, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monitor_rejects_loopback_and_unknown_interfaces_on_linux() {
        // Arrange
        let loopback = ApplicationCommand::Monitor {
            interface_name: Some("lo".to_string()),
            timeout: std::time::Duration::from_millis(1),
        };
        let unknown = ApplicationCommand::Monitor {
            interface_name: Some("narp_none____".to_string()),
            timeout: std::time::Duration::from_millis(1),
        };

        // Act
        let loopback_outcome = run(loopback);
        let unknown_outcome = run(unknown);

        // Assert
        assert!(
            matches!(
                loopback_outcome,
                Err(AppError::InterfaceRejectedForScanning { .. })
            ),
            "loopback must be rejected before a monitor socket opens, got: {loopback_outcome:?}"
        );
        assert!(
            matches!(unknown_outcome, Err(AppError::InterfaceLookupFailed { .. })),
            "an unknown interface must fail lookup, got: {unknown_outcome:?}"
        );
    }

    #[test]
    fn monitor_rejects_an_empty_interface_name_when_the_timeout_is_positive() {
        // Arrange
        let command = ApplicationCommand::Monitor {
            interface_name: Some(String::new()),
            timeout: std::time::Duration::from_millis(1),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "a positive timeout must still reject an empty interface name, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monitor_without_an_interface_name_follows_usable_candidate_count() {
        // Arrange
        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidate_count = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts")
            .len();
        let command = ApplicationCommand::Monitor {
            interface_name: None,
            timeout: std::time::Duration::from_millis(1),
        };

        // Act
        let outcome = run(command);

        // Assert
        match candidate_count {
            0 => assert!(
                matches!(outcome, Err(AppError::AutomaticInterfaceSelectionNoneFound)),
                "zero usable interfaces should reject automatic monitor selection, got: {outcome:?}"
            ),
            1 => assert!(
                !matches!(
                    &outcome,
                    Err(AppError::AutomaticInterfaceSelectionNoneFound
                        | AppError::AutomaticInterfaceSelectionAmbiguous { .. })
                ),
                "exactly one usable interface must pass automatic monitor selection, got: {outcome:?}"
            ),
            _ => assert!(
                matches!(
                    outcome,
                    Err(AppError::AutomaticInterfaceSelectionAmbiguous { .. })
                ),
                "multiple usable interfaces should make automatic monitor selection ambiguous, got: {outcome:?}"
            ),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn returns_unsupported_platform_when_listing_interfaces_on_unsupported_os() {
        // Arrange
        let command = ApplicationCommand::UsableInterfacesList;

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "unsupported hosts should report unsupported platform, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lists_usable_interfaces_without_error_on_macos() {
        // Arrange
        let command = ApplicationCommand::UsableInterfacesList;

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(
                outcome,
                Ok(super::ApplicationOutcome::UsableInterfacesList(_))
            ),
            "macOS should enumerate usable interfaces without privileges, got: {outcome:?}"
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn returns_unsupported_platform_when_scanning_without_interface_name_on_unsupported_os() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: None,
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
        assert!(
            matches!(outcome, Err(AppError::UnsupportedPlatform { .. })),
            "automatic selection should still hit unsupported platform on unsupported OSes, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn returns_lookup_failure_when_scanning_unknown_interface_on_macos() {
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
        assert!(
            matches!(outcome, Err(AppError::InterfaceLookupFailed { .. })),
            "macOS should resolve a real backend (not report unsupported) and fail to find an \
             unknown interface, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn returns_lookup_failure_when_probing_unknown_interface_on_macos() {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some("narp_absent0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 2)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceLookupFailed { .. })),
            "macOS single-target scan of an unknown interface should fail to find it, not report \
             unsupported, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_interface_on_linux() {
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
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback should be rejected before opening a raw socket, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_on_linux_even_with_non_default_scan_timing() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: None,
            timeout: std::time::Duration::from_millis(1),
            pacing: std::time::Duration::from_millis(5),
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "custom scan timing must not bypass loopback rejection, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_on_linux_even_with_high_attempt_count() {
        // Arrange
        use std::num::NonZeroU64;

        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: NonZeroU64::new(99).expect("ninety-nine is non-zero"),
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "high attempt count must not bypass loopback rejection, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scan_outcome_struct_round_trips_for_documentation() {
        // Arrange
        use super::ApplicationOutcome;
        use std::net::Ipv4Addr;

        let host = super::application_outcome::DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
            media_access_control_address: super::MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
        };
        let scan = super::application_outcome::ScanOutcome {
            discovered_hosts: vec![host],
            warnings: vec!["fixture warning".to_string()],
            timing_summary: None,
        };

        // Act
        let outcome = ApplicationOutcome::Scan(scan.clone());

        // Assert
        assert_eq!(
            outcome,
            ApplicationOutcome::Scan(scan),
            "scan outcome should round-trip for equality"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_scan_without_interface_name_follows_usable_candidate_count() {
        // Arrange
        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidate_count = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts")
            .len();

        let command = ApplicationCommand::Scan {
            interface_name: None,
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
        match candidate_count {
            0 => assert!(
                matches!(outcome, Err(AppError::AutomaticInterfaceSelectionNoneFound)),
                "zero usable interfaces should make automatic selection fail deterministically, got: {outcome:?}"
            ),
            1 => assert!(
                !matches!(
                    &outcome,
                    Err(AppError::AutomaticInterfaceSelectionNoneFound
                        | AppError::AutomaticInterfaceSelectionAmbiguous { .. })
                ),
                "exactly one usable interface must pass automatic selection (scan may still fail for capabilities or I/O), got: {outcome:?}"
            ),
            _ => assert!(
                matches!(
                    outcome,
                    Err(AppError::AutomaticInterfaceSelectionAmbiguous { .. })
                ),
                "multiple usable interfaces should make automatic selection ambiguous, got: {outcome:?}"
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_invalid_interface_name_when_scan_interface_name_is_empty_on_linux() {
        // Arrange
        let command = ApplicationCommand::Scan {
            interface_name: Some(String::new()),
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
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty interface name should be rejected before raw socket setup, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_rejection_when_scanning_loopback_on_linux_even_with_single_target_ipv4_address_set()
    {
        // Arrange
        use std::net::Ipv4Addr;

        let command = ApplicationCommand::Scan {
            interface_name: Some("lo".to_string()),
            target_ipv4_address: Some(Ipv4Addr::LOCALHOST),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback should be rejected before single-target validation, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_single_scan_target_rejected_when_probe_target_is_subnet_network_on_linux() {
        // Arrange
        use std::net::Ipv4Addr;

        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidates = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts");
        let Some(first) = candidates.first() else {
            // No Ethernet+IPv4 usable interfaces in this environment (for example CI without a
            // configured LAN): nothing to exercise against a real interface name.
            return;
        };
        let mask_bits = first.ipv4_netmask.to_bits();
        let network_ipv4_address =
            Ipv4Addr::from_bits(first.source_ipv4_address.to_bits() & mask_bits);
        let command = ApplicationCommand::Scan {
            interface_name: Some(first.interface_name.clone()),
            target_ipv4_address: Some(network_ipv4_address),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::SingleScanTargetRejected { .. })),
            "network address as single target should be rejected before socket, got: {outcome:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn returns_single_scan_target_rejected_when_probe_target_is_subnet_broadcast_on_linux() {
        // Arrange
        use std::net::Ipv4Addr;

        use crate::linux_interface_discovery::enumerate_usable_arp_scan_interface_candidates;

        let candidates = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts");
        let Some(first) = candidates.first() else {
            // No usable interfaces in this environment: see network-address probe test.
            return;
        };
        let mask_bits = first.ipv4_netmask.to_bits();
        let network_bits = first.source_ipv4_address.to_bits() & mask_bits;
        let broadcast_ipv4_address = Ipv4Addr::from_bits(network_bits | !mask_bits);
        let command = ApplicationCommand::Scan {
            interface_name: Some(first.interface_name.clone()),
            target_ipv4_address: Some(broadcast_ipv4_address),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let outcome = run(command);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::SingleScanTargetRejected { .. })),
            "broadcast address as single target should be rejected before socket, got: {outcome:?}"
        );
    }
}
