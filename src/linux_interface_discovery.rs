//! Discovers Linux network interfaces and IPv4 configuration for ARP scanning.

use std::mem::zeroed;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

use crate::error::AppError;
use crate::interface_validation;
use crate::link_layer_backend::{
    ArpScanInterfaceCandidate, InterfaceScanAddresses, MonitorInterfaceIdentity,
};
use crate::linux_packet::{INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP};
use crate::linux_socket::validated_interface_index_for_arp_scanning;
use crate::linux_system_call;
use crate::mac_address::MacAddress;

fn read_ipv4_from_sockaddr(
    sockaddr: &libc::sockaddr,
    wrong_family_error: impl FnOnce(libc::sa_family_t) -> AppError,
) -> Result<Ipv4Addr, AppError> {
    if libc::c_int::from(sockaddr.sa_family) != libc::AF_INET {
        return Err(wrong_family_error(sockaddr.sa_family));
    }

    // SAFETY: `sockaddr` was validated as `AF_INET` and can be reinterpreted as `sockaddr_in`.
    let socket_address_internet = unsafe {
        std::ptr::from_ref(sockaddr)
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };

    // POSIX stores `in_addr.s_addr` in network byte order: the four bytes at `&s_addr` are the
    // IPv4 octets in order. Do not use `s_addr.to_be_bytes()` — that re-encodes the `u32` value in
    // host-endian form and swaps octets on little-endian targets (breaking real `ioctl` results).
    let octets: [u8; 4] = unsafe {
        std::ptr::from_ref(&socket_address_internet.sin_addr.s_addr)
            .cast::<[u8; 4]>()
            .read_unaligned()
    };
    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

fn read_hardware_address_from_sockaddr(
    interface_name: &str,
    sockaddr: &libc::sockaddr,
) -> Result<MacAddress, AppError> {
    if sockaddr.sa_family != libc::ARPHRD_ETHER {
        return Err(AppError::InterfaceHardwareAddressUnsupported {
            interface_name: interface_name.to_string(),
            reason: format!(
                "hardware address family is not Ethernet (expected {}, got {})",
                libc::ARPHRD_ETHER,
                sockaddr.sa_family
            ),
        });
    }

    let mut hardware_address_octets = [0u8; 6];
    let sockaddr_data_bytes = unsafe {
        // SAFETY: `sa_data` is the fixed-size byte payload in the POSIX `sockaddr` ABI. Reading it
        // as bytes preserves the kernel-provided address regardless of signed character exposure.
        std::slice::from_raw_parts(
            sockaddr.sa_data.as_ptr().cast::<u8>(),
            sockaddr.sa_data.len(),
        )
    };
    let hardware_address_length = hardware_address_octets.len();
    hardware_address_octets.copy_from_slice(&sockaddr_data_bytes[..hardware_address_length]);

    let address = MacAddress::from_octets(hardware_address_octets);
    if address.is_zero() {
        return Err(AppError::InterfaceHardwareAddressUnsupported {
            interface_name: interface_name.to_string(),
            reason: "hardware address is all zero".to_string(),
        });
    }

    Ok(address)
}

fn read_interface_flags_with_control_socket(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<i32, AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    interface_validation::copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFFLAGS_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceFlagsQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    Ok(i32::from(unsafe { request.ifr_ifru.ifru_flags }))
}

fn read_interface_ipv4_address_with_control_socket(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<Ipv4Addr, AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    interface_validation::copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFADDR_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceIpv4AddressQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    // SAFETY: `ioctl` populated `ifr_addr` for this interface name.
    let sockaddr = unsafe { request.ifr_ifru.ifru_addr };
    read_ipv4_from_sockaddr(&sockaddr, |address_family| {
        AppError::InterfaceIpv4AddressInvalidFamily { address_family }
    })
}

fn read_interface_ipv4_netmask_with_control_socket(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<Ipv4Addr, AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    interface_validation::copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFNETMASK_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceIpv4NetmaskQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    // SAFETY: `ioctl` populated `ifr_netmask` for this interface name.
    let sockaddr = unsafe { request.ifr_ifru.ifru_netmask };
    read_ipv4_from_sockaddr(&sockaddr, |address_family| {
        AppError::InterfaceIpv4NetmaskInvalidFamily {
            interface_name: interface_name.to_string(),
            address_family,
        }
    })
}

fn read_interface_hardware_address_with_control_socket(
    control_socket: &OwnedFd,
    interface_name: &str,
) -> Result<MacAddress, AppError> {
    let mut request: libc::ifreq = unsafe { zeroed() };
    interface_validation::copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        control_socket,
        linux_system_call::SIOCGIFHWADDR_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceHardwareAddressQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    // SAFETY: `ioctl` populated `ifr_hwaddr` for this interface name.
    let sockaddr = unsafe { request.ifr_ifru.ifru_hwaddr };
    read_hardware_address_from_sockaddr(interface_name, &sockaddr)
}

/// Attempts to build an [`ArpScanInterfaceCandidate`] for `interface_name` using one control socket.
///
/// Returns [`None`] when the interface is not usable for ARP scanning under the current rules.
fn try_build_arp_scan_interface_candidate(
    control_socket: &OwnedFd,
    interface_name: &str,
    interface_index: libc::c_uint,
) -> Option<ArpScanInterfaceCandidate> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name).ok()?;

    let flags = read_interface_flags_with_control_socket(control_socket, interface_name).ok()?;
    if !interface_flags_allow_arp_scanning(flags) {
        return None;
    }

    let source_ipv4_address =
        read_interface_ipv4_address_with_control_socket(control_socket, interface_name).ok()?;
    let ipv4_netmask =
        read_interface_ipv4_netmask_with_control_socket(control_socket, interface_name).ok()?;
    let source_mac_address =
        read_interface_hardware_address_with_control_socket(control_socket, interface_name).ok()?;

    Some(ArpScanInterfaceCandidate {
        interface_name: interface_name.to_string(),
        interface_index,
        source_ipv4_address,
        ipv4_netmask,
        source_mac_address,
    })
}

/// Enumerates local interfaces that are usable for ARP scanning.
///
/// # Errors
///
/// Returns [`AppError::InterfaceEnumerationFailed`] when `if_nameindex(3)` fails, or [`AppError::Io`]
/// when opening the control socket fails.
///
/// # Panics
///
/// This function does not panic.
pub fn enumerate_usable_arp_scan_interface_candidates()
-> Result<Vec<ArpScanInterfaceCandidate>, AppError> {
    let name_index_pairs = linux_system_call::list_interface_name_and_index_pairs()
        .map_err(|source| AppError::InterfaceEnumerationFailed { source })?;

    let control_socket = linux_system_call::open_inet_datagram_socket().map_err(AppError::Io)?;

    let mut candidates = Vec::new();
    for (interface_name, interface_index) in name_index_pairs {
        if let Some(candidate) = try_build_arp_scan_interface_candidate(
            &control_socket,
            &interface_name,
            interface_index,
        ) {
            candidates.push(candidate);
        }
    }

    candidates.sort_by(|left, right| {
        left.interface_index
            .cmp(&right.interface_index)
            .then_with(|| left.interface_name.cmp(&right.interface_name))
    });

    Ok(candidates)
}

/// Resolves which interface name to use for scanning.
///
/// When `explicit_interface_name` is [`Some`], that name is validated the same way as a direct
/// scan request. When it is [`None`], this function requires exactly one usable interface.
///
/// # Errors
///
/// Returns [`AppError`] for invalid names, interface rejection, discovery failures, or ambiguous
/// automatic selection.
///
/// # Panics
///
/// This function does not panic.
pub fn resolve_scan_interface_name(
    explicit_interface_name: Option<&str>,
) -> Result<String, AppError> {
    if let Some(interface_name) = explicit_interface_name {
        interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
        validated_interface_index_for_arp_scanning(interface_name)?;
        discover_interface_scan_addresses(interface_name)?;
        return Ok(interface_name.to_string());
    }

    let candidates = enumerate_usable_arp_scan_interface_candidates()?;
    match candidates.len() {
        0 => Err(AppError::AutomaticInterfaceSelectionNoneFound),
        1 => Ok(candidates[0].interface_name.clone()),
        _ => Err(AppError::AutomaticInterfaceSelectionAmbiguous {
            interface_names: candidates
                .into_iter()
                .map(|candidate| candidate.interface_name)
                .collect(),
        }),
    }
}

/// Reads [`InterfaceScanAddresses`] for `interface_name` using `ioctl(2)` on an `AF_INET` datagram
/// control socket.
///
/// # Errors
///
/// Returns [`AppError`] when the interface name is invalid, when any `ioctl` fails, when the
/// address family is unexpected, or when the hardware address is not Ethernet.
///
/// # Panics
///
/// This function does not panic.
pub fn discover_interface_scan_addresses(
    interface_name: &str,
) -> Result<InterfaceScanAddresses, AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    let control_socket = linux_system_call::open_inet_datagram_socket().map_err(AppError::Io)?;

    let source_ipv4_address =
        read_interface_ipv4_address_with_control_socket(&control_socket, interface_name)?;
    let ipv4_netmask =
        read_interface_ipv4_netmask_with_control_socket(&control_socket, interface_name)?;
    let source_mac_address =
        read_interface_hardware_address_with_control_socket(&control_socket, interface_name)?;

    Ok(InterfaceScanAddresses {
        source_ipv4_address,
        ipv4_netmask,
        source_mac_address,
    })
}

/// Reads every IPv4 address configured on `interface_name`, plus its Ethernet address.
///
/// The primary address from `SIOCGIFADDR` is always included. Additional addresses come from
/// `getifaddrs(3)` entries whose `ifa_name` equals `interface_name`. Alias interface names such as
/// `eth0:1` are separate kernel names and are not included. Scan discovery continues to use only
/// [`discover_interface_scan_addresses`].
///
/// # Errors
///
/// Returns [`AppError`] when the name is invalid, the interface is loopback, down, or `NOARP`, an
/// `ioctl` or `getifaddrs(3)` call fails, or the hardware address is not Ethernet.
///
/// # Panics
///
/// This function does not panic.
pub fn discover_monitor_interface_identity(
    interface_name: &str,
) -> Result<MonitorInterfaceIdentity, AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    validated_interface_index_for_arp_scanning(interface_name)?;
    let primary = discover_interface_scan_addresses(interface_name)?;
    let records = linux_system_call::list_interface_ipv4_addresses()
        .map_err(|source| AppError::InterfaceEnumerationFailed { source })?;
    let identity = MonitorInterfaceIdentity::from_addresses(
        configured_ipv4_addresses(interface_name, primary.source_ipv4_address, &records),
        primary.source_mac_address,
    );
    if identity.ipv4_addresses.is_empty() {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "interface has no IPv4 address".to_string(),
        });
    }
    Ok(identity)
}

/// Unions `primary_ipv4_address` with every `getifaddrs(3)` address for `interface_name`.
fn configured_ipv4_addresses(
    interface_name: &str,
    primary_ipv4_address: Ipv4Addr,
    records: &[linux_system_call::InterfaceIpv4AddressRecord],
) -> Vec<Ipv4Addr> {
    std::iter::once(primary_ipv4_address)
        .chain(records.iter().filter_map(|record| {
            (record.interface_name == interface_name).then_some(record.ipv4_address)
        }))
        .collect()
}

/// Returns `true` when `flags` indicate an interface that is administratively up, not loopback, and
/// does not have `NOARP` set.
///
/// This mirrors [`crate::linux_socket::validate_interface_flags_for_arp_scanning`] without
/// allocating [`AppError`] strings.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
fn interface_flags_allow_arp_scanning(flags: i32) -> bool {
    (flags & INTERFACE_FLAG_LOOPBACK) == 0
        && (flags & INTERFACE_FLAG_NO_ARP) == 0
        && (flags & INTERFACE_FLAG_UP) != 0
}

#[cfg(test)]
mod tests {
    use super::configured_ipv4_addresses;
    use super::discover_monitor_interface_identity;
    use super::enumerate_usable_arp_scan_interface_candidates;
    use super::interface_flags_allow_arp_scanning;
    use super::read_hardware_address_from_sockaddr;
    use super::read_ipv4_from_sockaddr;
    use super::resolve_scan_interface_name;
    use crate::error::AppError;
    use crate::linux_packet::{INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP};
    use crate::linux_system_call::InterfaceIpv4AddressRecord;
    use crate::mac_address::MacAddress;
    use std::mem::zeroed;
    use std::net::Ipv4Addr;

    #[test]
    fn reads_ipv4_from_sockaddr_in_fixture() {
        // Arrange
        let expected = Ipv4Addr::new(198, 51, 100, 7);
        let mut socket_address_internet: libc::sockaddr_in = unsafe { zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET should fit sa_family_t");
        // Match the kernel: `s_addr` memory is wire-order octets, not `u32::from_be_bytes(...)`
        // stored in native endian (which would not match `read_ipv4_from_sockaddr`).
        unsafe {
            std::ptr::addr_of_mut!(socket_address_internet.sin_addr.s_addr)
                .cast::<[u8; 4]>()
                .write(expected.octets());
        }

        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_in` for the lifetime of this test.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = read_ipv4_from_sockaddr(sockaddr_ref, |family| {
            AppError::InterfaceIpv4AddressInvalidFamily {
                address_family: family,
            }
        });

        // Assert
        assert_eq!(
            outcome.expect("fixture sockaddr_in should parse"),
            expected,
            "parsed IPv4 should match fixture"
        );
    }

    #[test]
    fn reads_slash_22_netmask_fixture_from_sockaddr() {
        // Arrange
        let expected = Ipv4Addr::new(255, 255, 252, 0);
        let mut socket_address_internet: libc::sockaddr_in = unsafe { zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET should fit sa_family_t");
        unsafe {
            std::ptr::addr_of_mut!(socket_address_internet.sin_addr.s_addr)
                .cast::<[u8; 4]>()
                .write(expected.octets());
        }
        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = read_ipv4_from_sockaddr(sockaddr_ref, |family| {
            AppError::InterfaceIpv4NetmaskInvalidFamily {
                interface_name: "eth0".to_string(),
                address_family: family,
            }
        });

        // Assert
        assert_eq!(
            outcome.expect("netmask fixture should parse"),
            expected,
            "parsed netmask should match kernel-style wire-order octets"
        );
    }

    #[test]
    fn read_ipv4_from_sockaddr_returns_error_when_family_is_not_inet() {
        // Arrange
        let mut socket_address_internet: libc::sockaddr_in = unsafe { zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 should fit sa_family_t");
        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = read_ipv4_from_sockaddr(sockaddr_ref, |family| {
            AppError::InterfaceIpv4AddressInvalidFamily {
                address_family: family,
            }
        });

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::InterfaceIpv4AddressInvalidFamily { .. })
            ),
            "non-AF_INET sockaddr should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn read_hardware_address_accepts_ethernet_sockaddr_fixture() {
        // Arrange
        let mut sockaddr: libc::sockaddr = unsafe { zeroed() };
        sockaddr.sa_family = libc::ARPHRD_ETHER;
        let expected_mac = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        unsafe {
            // SAFETY: `expected_mac` is six bytes, which fits inside `sockaddr.sa_data`.
            std::ptr::copy_nonoverlapping(
                expected_mac.as_ptr(),
                sockaddr.sa_data.as_mut_ptr().cast::<u8>(),
                expected_mac.len(),
            );
        }

        // Act
        let outcome = read_hardware_address_from_sockaddr("eth0", &sockaddr);

        // Assert
        assert_eq!(
            outcome.expect("Ethernet sockaddr should yield MAC octets"),
            MacAddress::from_octets(expected_mac)
        );
    }

    #[test]
    fn read_hardware_address_rejects_non_ethernet_family() {
        // Arrange
        let mut sockaddr: libc::sockaddr = unsafe { zeroed() };
        sockaddr.sa_family =
            libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET should fit sa_family_t");

        // Act
        let outcome = read_hardware_address_from_sockaddr("eth0", &sockaddr);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::InterfaceHardwareAddressUnsupported { .. })
            ),
            "AF_INET sockaddr should not be treated as Ethernet hardware, got: {outcome:?}"
        );
    }

    #[test]
    fn read_hardware_address_rejects_all_zero_mac_even_when_family_is_ethernet() {
        // Arrange
        let mut sockaddr: libc::sockaddr = unsafe { zeroed() };
        sockaddr.sa_family = libc::ARPHRD_ETHER;

        // Act
        let outcome = read_hardware_address_from_sockaddr("eth0", &sockaddr);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::InterfaceHardwareAddressUnsupported { .. })
            ),
            "all-zero MAC should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn interface_flags_allow_arp_scanning_accepts_up_non_loopback_without_no_arp() {
        // Arrange
        let flags = INTERFACE_FLAG_UP;

        // Act
        let outcome = interface_flags_allow_arp_scanning(flags);

        // Assert
        assert!(
            outcome,
            "UP without loopback or NOARP should be acceptable, got: {outcome}"
        );
    }

    #[test]
    fn interface_flags_allow_arp_scanning_rejects_loopback() {
        // Arrange
        let flags = INTERFACE_FLAG_UP | INTERFACE_FLAG_LOOPBACK;

        // Act
        let outcome = interface_flags_allow_arp_scanning(flags);

        // Assert
        assert!(
            !outcome,
            "loopback flag should disqualify the interface, got: {outcome}"
        );
    }

    #[test]
    fn interface_flags_allow_arp_scanning_rejects_no_arp() {
        // Arrange
        let flags = INTERFACE_FLAG_UP | INTERFACE_FLAG_NO_ARP;

        // Act
        let outcome = interface_flags_allow_arp_scanning(flags);

        // Assert
        assert!(
            !outcome,
            "NOARP should disqualify the interface, got: {outcome}"
        );
    }

    #[test]
    fn interface_flags_allow_arp_scanning_rejects_not_up() {
        // Arrange
        let flags = 0;

        // Act
        let outcome = interface_flags_allow_arp_scanning(flags);

        // Assert
        assert!(
            !outcome,
            "interfaces that are not UP should be rejected, got: {outcome}"
        );
    }

    #[test]
    fn enumerate_usable_arp_scan_interface_candidates_succeeds_on_linux() {
        // Act
        let outcome = enumerate_usable_arp_scan_interface_candidates();

        // Assert
        let candidates = outcome.expect("enumeration should succeed on Linux test hosts");
        for candidate in &candidates {
            assert!(
                !candidate.interface_name.is_empty(),
                "every candidate should carry a non-empty interface name, got: {candidate:?}"
            );
        }
    }

    #[test]
    fn resolve_scan_interface_name_rejects_empty_explicit_name() {
        // Arrange
        let explicit_name = Some("");

        // Act
        let outcome = resolve_scan_interface_name(explicit_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty explicit name should fail validation before syscalls, got: {outcome:?}"
        );
    }

    #[test]
    fn resolve_scan_interface_name_returns_lookup_failure_for_unknown_interface() {
        // Arrange
        let explicit_name = Some("narp_none____");

        // Act
        let outcome = resolve_scan_interface_name(explicit_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceLookupFailed { .. })),
            "unknown interface should fail lookup after name validation, got: {outcome:?}"
        );
    }

    #[test]
    fn configured_ipv4_addresses_unions_primary_with_same_name_records_only() {
        // Arrange
        let primary = Ipv4Addr::new(192, 168, 1, 10);
        let secondary = Ipv4Addr::new(192, 168, 1, 11);
        let records = [
            InterfaceIpv4AddressRecord {
                interface_name: "eth0".to_string(),
                ipv4_address: secondary,
            },
            InterfaceIpv4AddressRecord {
                interface_name: "eth0".to_string(),
                ipv4_address: primary,
            },
            InterfaceIpv4AddressRecord {
                interface_name: "eth0:1".to_string(),
                ipv4_address: Ipv4Addr::new(10, 0, 0, 8),
            },
            InterfaceIpv4AddressRecord {
                interface_name: "eth1".to_string(),
                ipv4_address: Ipv4Addr::BROADCAST,
            },
        ];

        // Act
        let addresses = configured_ipv4_addresses("eth0", primary, &records);

        // Assert
        assert_eq!(
            addresses,
            vec![primary, secondary, primary],
            "alias and other interface names must stay out of the selected interface"
        );
    }

    #[test]
    fn configured_ipv4_addresses_keeps_primary_when_getifaddrs_has_no_match() {
        // Arrange
        let primary = Ipv4Addr::UNSPECIFIED;
        let records = [InterfaceIpv4AddressRecord {
            interface_name: "eth1".to_string(),
            ipv4_address: Ipv4Addr::LOCALHOST,
        }];

        // Act
        let addresses = configured_ipv4_addresses("eth0", primary, &records);

        // Assert
        assert_eq!(
            addresses,
            vec![primary],
            "the ioctl primary address remains even when getifaddrs omits the name"
        );
    }

    #[test]
    fn discover_monitor_interface_identity_rejects_loopback_before_address_merge() {
        // Act
        let outcome = discover_monitor_interface_identity("lo");

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback must be rejected for monitoring, got: {outcome:?}"
        );
    }

    #[test]
    fn discover_monitor_interface_identity_rejects_unknown_interface() {
        // Act
        let outcome = discover_monitor_interface_identity("narp_none____");

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceLookupFailed { .. })),
            "an unknown interface must fail before getifaddrs merge, got: {outcome:?}"
        );
    }

    #[test]
    fn discover_monitor_interface_identity_includes_primary_when_usable() {
        // Arrange
        let candidates = enumerate_usable_arp_scan_interface_candidates()
            .expect("enumeration should succeed on Linux test hosts");
        let Some(candidate) = candidates.first() else {
            return;
        };

        // Act
        let identity = discover_monitor_interface_identity(&candidate.interface_name)
            .expect("a usable scan interface should have a monitor identity");

        // Assert
        assert!(
            identity
                .ipv4_addresses
                .contains(&candidate.source_ipv4_address),
            "the scan primary address must be part of the monitor set, got: {identity:?}"
        );
        assert_eq!(identity.source_mac_address, candidate.source_mac_address);
        let mut sorted = identity.ipv4_addresses.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(identity.ipv4_addresses, sorted);
    }
}
