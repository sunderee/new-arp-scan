//! macOS entry points for address resolution scanning.
//!
//! These thin wrappers discover and validate the interface and target, open a macOS Berkeley
//! Packet Filter [`crate::link_layer_backend::LinkLayerEndpoint`], and delegate the OS-agnostic
//! scheduling and reply collection to [`crate::scanner`].

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::application_command::{RateLimitedScanTiming, ScanWireOptions};
use crate::application_outcome::ScanOutcome;
use crate::error::AppError;
use crate::ipv4_subnet::validate_strict_interior_scan_target_ipv4_address;
use crate::macos_bpf_socket::open_macos_link_layer_endpoint;
use crate::macos_interface_discovery::discover_interface_scan_addresses;
use crate::scanner::{self, ArpReplyAcceptance, ScanTransmitContext};

/// Performs a full-subnet IPv4 address resolution scan on `interface_name`.
///
/// Timing semantics match the Linux backend: `receive_timeout_after_last_request` bounds the
/// receive window after the last request, `pacing_between_scan_rounds` sleeps after each round
/// except the last, and `scan_round_count` is how many rounds run. `wire` selects IEEE 802.1Q
/// tagging, RFC 826 header fields, Ethernet addressing, and RFC 1042 LLC/SNAP framing.
/// `rate_limit` opts into strict inter-target spacing; `None` keeps the burst path. An
/// unrepresentable schedule is rejected before discovery or the Berkeley Packet Filter device.
///
/// # Errors
///
/// Returns [`AppError`] when interface discovery, subnet validation, Berkeley Packet Filter setup,
/// or the receive poll loop fails fatally.
///
/// # Panics
///
/// This function does not panic.
pub fn perform_arp_scan(
    interface_name: &str,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
    wire: ScanWireOptions,
    rate_limit: Option<RateLimitedScanTiming>,
) -> Result<ScanOutcome, AppError> {
    crate::scan_timing::validate_scan_timing_before_socket(
        receive_timeout_after_last_request,
        pacing_between_scan_rounds,
        scan_round_count,
        &wire,
        rate_limit,
    )?;
    // Discovery validates interface usability (loopback / down / NOARP / non-Ethernet) and the
    // subnet plan is built before opening the Berkeley Packet Filter device.
    let addresses = discover_interface_scan_addresses(interface_name)?;
    let plan = scanner::full_subnet_scan_plan(&addresses)?;

    let mut endpoint = open_macos_link_layer_endpoint(interface_name)?;
    let transmit = ScanTransmitContext {
        source_mac_address: addresses.source_mac_address,
        interface_ipv4_address: addresses.source_ipv4_address,
        wire,
    };
    scanner::collect_scan_over_endpoint_with_rate_and_clock(
        &mut endpoint,
        &scanner::EndpointScanRequest {
            targets: &plan.targets,
            transmit: &transmit,
            acceptance: &plan.acceptance,
            receive_timeout_after_last_request,
            pacing_between_scan_rounds,
            scan_round_count,
            rate_limit,
        },
        &crate::scan_timing::SystemScanClock,
    )
}

/// Performs address resolution probing for a single strictly interior IPv4 target on
/// `interface_name`.
///
/// Only replies whose sender IPv4 equals `target_ipv4_address` are recorded; timing semantics match
/// [`perform_arp_scan`].
///
/// # Errors
///
/// Returns [`AppError`] when the target is not strictly interior on the interface subnet, when
/// interface discovery or Berkeley Packet Filter setup fails, or when the receive poll loop fails
/// fatally.
///
/// # Panics
///
/// This function does not panic.
pub fn perform_arp_probe(
    interface_name: &str,
    target_ipv4_address: Ipv4Addr,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
    wire: ScanWireOptions,
    rate_limit: Option<RateLimitedScanTiming>,
) -> Result<ScanOutcome, AppError> {
    crate::scan_timing::validate_scan_timing_before_socket(
        receive_timeout_after_last_request,
        pacing_between_scan_rounds,
        scan_round_count,
        &wire,
        rate_limit,
    )?;
    let addresses = discover_interface_scan_addresses(interface_name)?;
    validate_strict_interior_scan_target_ipv4_address(
        interface_name,
        target_ipv4_address,
        addresses.source_ipv4_address,
        addresses.ipv4_netmask,
    )?;

    let mut endpoint = open_macos_link_layer_endpoint(interface_name)?;
    let acceptance = ArpReplyAcceptance::ExactTarget {
        target_ipv4_address,
    };
    let transmit = ScanTransmitContext {
        source_mac_address: addresses.source_mac_address,
        interface_ipv4_address: addresses.source_ipv4_address,
        wire,
    };
    scanner::collect_scan_over_endpoint_with_rate_and_clock(
        &mut endpoint,
        &scanner::EndpointScanRequest {
            targets: &[target_ipv4_address],
            transmit: &transmit,
            acceptance: &acceptance,
            receive_timeout_after_last_request,
            pacing_between_scan_rounds,
            scan_round_count,
            rate_limit,
        },
        &crate::scan_timing::SystemScanClock,
    )
}
