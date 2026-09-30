//! Linux entry point for passive ARP monitoring.
//!
//! Discovers every IPv4 address on the interface, opens an `ETH_P_ALL` packet socket, and delegates
//! classification to [`crate::monitor`]. The socket can transmit, but the listen loop never sends.

use std::time::Duration;

use crate::error::AppError;
use crate::linux_interface_discovery::discover_monitor_interface_identity;
use crate::linux_socket::open_linux_monitor_link_layer_endpoint;
use crate::monitor::{
    MonitorListenOutcome, MonitorListenRequest, listen_for_passive_arp, monitor_deadline,
};
use crate::scan_timing::SystemScanClock;

/// Listens for ARP on `interface_name` for `timeout` without transmitting.
///
/// A zero or unrepresentable timeout is rejected before interface discovery or the raw socket.
///
/// # Errors
///
/// Returns [`AppError`] when the timeout is rejected, the interface is unusable, the packet socket
/// cannot be opened, or the receive wait fails.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn perform_passive_arp_monitor(
    interface_name: &str,
    timeout: Duration,
) -> Result<MonitorListenOutcome, AppError> {
    let clock = SystemScanClock;
    monitor_deadline(&clock, timeout)?;
    let identity = discover_monitor_interface_identity(interface_name)?;
    let mut endpoint = open_linux_monitor_link_layer_endpoint(interface_name)?;
    listen_for_passive_arp(
        &mut endpoint,
        &clock,
        &MonitorListenRequest {
            local_ipv4_addresses: &identity.ipv4_addresses,
            local_mac_address: identity.source_mac_address,
            timeout,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::perform_passive_arp_monitor;
    use crate::error::{AppError, ScanTimingLimit};
    use std::time::Duration;

    #[test]
    fn zero_timeout_is_rejected_before_interface_validation() {
        // Act
        let outcome = perform_passive_arp_monitor("", Duration::ZERO);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::MonitorTimeoutRejected)),
            "a zero timeout must fail before the empty interface name is validated, got: {outcome:?}"
        );
    }

    #[test]
    fn unrepresentable_timeout_is_rejected_before_interface_validation() {
        // Act
        let outcome = perform_passive_arp_monitor("", Duration::MAX);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::MonotonicDeadline
                })
            ),
            "an unrepresentable timeout must fail before interface validation, got: {outcome:?}"
        );
    }

    #[test]
    fn unknown_interface_fails_lookup_for_a_positive_timeout() {
        // Act
        let outcome = perform_passive_arp_monitor("narp_none____", Duration::from_millis(1));

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceLookupFailed { .. })),
            "an unknown interface should fail lookup, got: {outcome:?}"
        );
    }

    #[test]
    fn loopback_is_rejected_for_a_positive_timeout() {
        // Act
        let outcome = perform_passive_arp_monitor("lo", Duration::from_millis(1));

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback must be rejected before a monitor socket is opened, got: {outcome:?}"
        );
    }
}
