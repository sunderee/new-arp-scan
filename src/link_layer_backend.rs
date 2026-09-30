//! Portable link-layer backend boundary shared by platform-specific scanners.
//!
//! Scan scheduling and Ethernet/ARP framing are platform-neutral; only interface discovery and
//! raw frame input/output differ between Linux `AF_PACKET` sockets and macOS Berkeley Packet
//! Filter devices. This module defines the narrow surface those platforms implement: the value
//! types produced by interface discovery and the [`LinkLayerEndpoint`] trait for sending and
//! receiving complete Ethernet II frames. See the 2026-06-03 `DECISIONS.md` entry.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use crate::error::AppError;
use crate::mac_address::MacAddress;

/// IPv4 configuration and Ethernet hardware address discovered for scanning one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceScanAddresses {
    /// Primary IPv4 address selected for scanning (first address returned by the kernel).
    pub source_ipv4_address: Ipv4Addr,
    /// IPv4 netmask associated with [`Self::source_ipv4_address`].
    pub ipv4_netmask: Ipv4Addr,
    /// Source Ethernet hardware address used in outgoing frames.
    pub source_mac_address: MacAddress,
}

/// Every IPv4 address configured on one interface, plus that interface's Ethernet address.
///
/// Scan discovery keeps a single primary address in [`InterfaceScanAddresses`]. Passive monitoring
/// matches `ar$spa` against this full set. Addresses are sorted and unique.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Constructed by monitor discovery in the following change.
pub struct MonitorInterfaceIdentity {
    /// Configured IPv4 addresses, in ascending address order, with duplicates removed.
    pub ipv4_addresses: Vec<Ipv4Addr>,
    /// Ethernet hardware address of the monitored interface.
    pub source_mac_address: MacAddress,
}

#[allow(dead_code)] // Used by monitor discovery and the listen loop in the following change.
impl MonitorInterfaceIdentity {
    /// Builds an identity from `ipv4_addresses`, sorting and removing duplicates.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub(crate) fn from_addresses(
        ipv4_addresses: impl IntoIterator<Item = Ipv4Addr>,
        source_mac_address: MacAddress,
    ) -> Self {
        Self {
            ipv4_addresses: sorted_unique_ipv4_addresses(ipv4_addresses),
            source_mac_address,
        }
    }

    /// Returns `true` when `address` is one of the configured IPv4 addresses.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub(crate) fn contains_ipv4(&self, address: Ipv4Addr) -> bool {
        self.ipv4_addresses.binary_search(&address).is_ok()
    }
}

/// Returns `ipv4_addresses` in ascending order with duplicates removed.
#[allow(dead_code)] // Called by `MonitorInterfaceIdentity::from_addresses`.
fn sorted_unique_ipv4_addresses(
    ipv4_addresses: impl IntoIterator<Item = Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    ipv4_addresses
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// One local interface that satisfies the ARP scan filtering rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpScanInterfaceCandidate {
    /// Operating system interface name (for example `eth0` or `en0`).
    pub interface_name: String,
    /// Operating system interface index (`ifindex`).
    pub interface_index: u32,
    /// Primary IPv4 address on this interface.
    pub source_ipv4_address: Ipv4Addr,
    /// IPv4 netmask associated with [`Self::source_ipv4_address`].
    pub ipv4_netmask: Ipv4Addr,
    /// Ethernet hardware address for this interface.
    pub source_mac_address: MacAddress,
}

/// A link-layer endpoint bound to one interface for Ethernet II ARP frames.
///
/// Implementations own the underlying operating system descriptor and close it on drop. The
/// destination of an outgoing frame is the broadcast address already encoded in the frame, so the
/// platform address structure (Linux `sockaddr_ll`, macOS none) stays inside the implementation.
pub trait LinkLayerEndpoint {
    /// Sends one complete Ethernet II frame on the bound interface.
    ///
    /// # Errors
    ///
    /// Returns the underlying operating system error when the send fails. Callers treat a failed
    /// send as a non-fatal, per-target warning rather than aborting the scan.
    fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()>;

    /// Waits for the endpoint to become readable, up to `timeout_milliseconds`.
    ///
    /// Returns `Ok(true)` when at least one frame is ready, `Ok(false)` on timeout or a benign
    /// interruption (the caller re-evaluates its own deadline).
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the readiness wait fails fatally.
    fn wait_until_readable(&self, timeout_milliseconds: libc::c_int) -> Result<bool, AppError>;

    /// Receives the next currently buffered Ethernet II frame into `buffer` without blocking.
    ///
    /// Returns `Ok(Some(length))` for a frame written to `buffer[..length]`, or `Ok(None)` when no
    /// frame is currently available (the endpoint is drained or the read would block). Benign
    /// interruptions are retried internally.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when receiving fails fatally.
    fn try_receive_ethernet_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, AppError>;
}

#[cfg(test)]
mod tests {
    use super::MonitorInterfaceIdentity;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;

    #[test]
    fn monitor_identity_sorts_and_deduplicates_ipv4_addresses() {
        // Arrange
        let mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x11]);
        let primary = Ipv4Addr::new(192, 168, 1, 20);
        let secondary = Ipv4Addr::new(10, 1, 2, 3);
        let broadcast = Ipv4Addr::BROADCAST;

        // Act
        let identity = MonitorInterfaceIdentity::from_addresses(
            [
                primary,
                secondary,
                primary,
                Ipv4Addr::UNSPECIFIED,
                broadcast,
            ],
            mac,
        );

        // Assert
        assert_eq!(
            identity.ipv4_addresses,
            vec![
                Ipv4Addr::UNSPECIFIED,
                secondary,
                primary,
                Ipv4Addr::BROADCAST,
            ],
            "configured addresses should be unique and in ascending order"
        );
        assert_eq!(identity.source_mac_address, mac);
        assert!(identity.contains_ipv4(primary));
        assert!(identity.contains_ipv4(Ipv4Addr::UNSPECIFIED));
        assert!(!identity.contains_ipv4(Ipv4Addr::new(192, 168, 1, 21)));
    }

    #[test]
    fn monitor_identity_from_no_addresses_is_empty() {
        // Arrange
        let mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x22]);

        // Act
        let identity = MonitorInterfaceIdentity::from_addresses([], mac);

        // Assert
        assert!(
            identity.ipv4_addresses.is_empty(),
            "an empty address iterator should stay empty, got: {identity:?}"
        );
        assert!(!identity.contains_ipv4(Ipv4Addr::LOCALHOST));
    }
}
