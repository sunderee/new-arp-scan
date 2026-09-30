//! Linux raw `AF_PACKET` socket initialization for ARP scanning.

use std::ffi::CString;
use std::mem::zeroed;
use std::os::fd::OwnedFd;

use crate::address_resolution_protocol::ARP_HARDWARE_TYPE_ETHERNET;
use crate::application_command::ScanWireOptions;
use crate::error::AppError;
use crate::interface_validation;
use crate::link_layer_backend::LinkLayerEndpoint;
use crate::linux_packet::{
    ETHERNET_PROTOCOL_ALL, ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IEEE_802_2,
    INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP,
    SOCKET_ADDRESS_FAMILY_PACKET, SockAddressLinkLayer, ethernet_protocol_host_to_network_order,
};
use crate::linux_system_call;

/// Validates that `interface_name` is usable for ARP scanning and returns its Linux interface
/// index.
///
/// # Errors
///
/// Returns [`AppError`] when the interface name is invalid, cannot be resolved, its flags cannot
/// be read, or its flags indicate that it is loopback, down, or `NOARP`.
///
/// # Panics
///
/// This function does not panic.
pub fn validated_interface_index_for_arp_scanning(
    interface_name: &str,
) -> Result<libc::c_uint, AppError> {
    interface_validation::validate_interface_name_for_linux_packet_socket(interface_name)?;
    let interface_index = interface_index_from_name(interface_name)?;
    let flags = read_interface_flags(interface_name)?;
    validate_interface_flags_for_arp_scanning(interface_name, flags)?;
    Ok(interface_index)
}

fn interface_index_from_name(interface_name: &str) -> Result<libc::c_uint, AppError> {
    let terminated = CString::new(interface_name).map_err(|_| AppError::InvalidInterfaceName {
        message: "interface name contains an interior NUL byte".to_string(),
    })?;

    linux_system_call::interface_index_from_name(&terminated).map_err(|source| {
        AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source,
        }
    })
}

fn read_interface_flags(interface_name: &str) -> Result<i32, AppError> {
    let control_socket = linux_system_call::open_inet_datagram_socket().map_err(AppError::Io)?;
    let mut request: libc::ifreq = unsafe { zeroed() };
    interface_validation::copy_interface_name_to_ifreq(interface_name, &mut request)?;

    linux_system_call::ioctl_ifreq(
        &control_socket,
        linux_system_call::SIOCGIFFLAGS_REQUEST,
        &mut request,
    )
    .map_err(|source| AppError::InterfaceFlagsQueryFailed {
        interface_name: interface_name.to_string(),
        source,
    })?;

    let flags = i32::from(unsafe { request.ifr_ifru.ifru_flags });
    Ok(flags)
}

pub(crate) fn validate_interface_flags_for_arp_scanning(
    interface_name: &str,
    flags: i32,
) -> Result<(), AppError> {
    if (flags & INTERFACE_FLAG_LOOPBACK) != 0 {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "loopback interface".to_string(),
        });
    }

    if (flags & INTERFACE_FLAG_NO_ARP) != 0 {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "interface has NOARP set".to_string(),
        });
    }

    if (flags & INTERFACE_FLAG_UP) == 0 {
        return Err(AppError::InterfaceRejectedForScanning {
            interface_name: interface_name.to_string(),
            reason: "interface is not UP".to_string(),
        });
    }

    Ok(())
}

/// Chooses the `AF_PACKET` capture protocol.
///
/// `ETH_P_ARP` only delivers frames whose length/type field is `0x0806`, so any framing that shifts
/// or replaces that field — an IEEE 802.1Q customer tag, an IEEE 802.1ad service tag, or an IEEE
/// 802.3 length with RFC 1042 SNAP — must fall back to `ETH_P_ALL` and filter in userspace.
///
/// Note that on ingress the kernel always moves the outermost VLAN tag (`0x8100` or `0x88A8`) into
/// skb metadata before packet sockets see the frame (`skb_vlan_untag()`, Linux 3.16, commit
/// `0d5501c1c828`), and the delivery protocol becomes whatever follows that tag — the inner
/// `0x8100` for an IEEE 802.1ad reply. `ETH_P_ALL` is what matches those untagged-by-the-kernel
/// shapes; the stripped outer TCI itself would only be recoverable via `PACKET_AUXDATA`, which
/// this endpoint does not request.
fn packet_socket_protocol_for_wire_options(wire: &ScanWireOptions) -> u16 {
    if wire.vlan_identifier.is_some() || wire.service_vlan_identifier.is_some() || wire.llc_snap {
        ETHERNET_PROTOCOL_ALL
    } else {
        ETHERNET_PROTOCOL_ARP
    }
}

/// Chooses the `sockaddr_ll` send protocol, which is the outermost length/type value on the wire.
///
/// For a stacked frame that is the outer service TPID `0x88A8`, exactly as a single customer tag
/// sends `0x8100`.
fn link_layer_send_protocol_for_wire_options(wire: &ScanWireOptions) -> u16 {
    if let Some(vlan_tag) = wire.ieee_8021q_tag_stack() {
        vlan_tag.outer_tag_protocol_identifier()
    } else if wire.llc_snap {
        ETHERNET_PROTOCOL_IEEE_802_2
    } else {
        ETHERNET_PROTOCOL_ARP
    }
}

fn open_raw_packet_socket(ethernet_protocol_host_order: u16) -> Result<OwnedFd, AppError> {
    match linux_system_call::open_packet_raw_socket(ethernet_protocol_host_order) {
        Ok(socket) => Ok(socket),
        Err(source) => {
            if source.kind() == std::io::ErrorKind::PermissionDenied {
                Err(AppError::RawSocketCapabilityRequired { source })
            } else {
                Err(AppError::RawSocketOpenFailed { source })
            }
        }
    }
}

fn bind_packet_socket_to_interface(
    packet_socket: &OwnedFd,
    interface_name: &str,
    interface_index: libc::c_uint,
    ethernet_protocol_host_order: u16,
) -> Result<(), AppError> {
    let mut address: SockAddressLinkLayer = unsafe { zeroed() };
    address.socket_address_family = SOCKET_ADDRESS_FAMILY_PACKET;
    address.link_layer_protocol =
        ethernet_protocol_host_to_network_order(ethernet_protocol_host_order);
    address.interface_index =
        libc::c_int::try_from(interface_index).map_err(|_| AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("interface index {interface_index} does not fit sockaddr_ll"),
            ),
        })?;
    address.hardware_type = ARP_HARDWARE_TYPE_ETHERNET;

    linux_system_call::bind_sockaddr_link_layer(
        packet_socket,
        address.as_libc_sockaddr_link_layer(),
    )
    .map_err(|source| AppError::SocketBindFailed { source })
}

/// Builds the broadcast `sockaddr_ll` destination used to send ARP requests on `interface_index`.
fn link_layer_broadcast_destination_for_scan(
    interface_name: &str,
    interface_index: libc::c_uint,
    ethernet_protocol_host_order: u16,
) -> Result<SockAddressLinkLayer, AppError> {
    let mut link_layer_destination: SockAddressLinkLayer = unsafe { zeroed() };
    link_layer_destination.socket_address_family = SOCKET_ADDRESS_FAMILY_PACKET;
    link_layer_destination.link_layer_protocol =
        ethernet_protocol_host_to_network_order(ethernet_protocol_host_order);
    link_layer_destination.interface_index =
        libc::c_int::try_from(interface_index).map_err(|_| AppError::InterfaceLookupFailed {
            interface_name: interface_name.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("interface index {interface_index} does not fit sockaddr_ll"),
            ),
        })?;
    link_layer_destination.hardware_type = ARP_HARDWARE_TYPE_ETHERNET;
    link_layer_destination.hardware_address_length = 6;
    link_layer_destination.hardware_address[0..6].fill(0xFF);
    Ok(link_layer_destination)
}

/// A Linux `AF_PACKET` raw socket bound to one interface, used to send and receive ARP frames.
///
/// Owns the bound socket (closed on drop) and the precomputed broadcast `sockaddr_ll` destination.
pub struct LinuxLinkLayerEndpoint {
    packet_socket: OwnedFd,
    link_layer_destination: SockAddressLinkLayer,
}

/// Opens a raw `AF_PACKET` socket bound to `interface_name` and returns a link-layer endpoint for
/// ARP scanning.
///
/// When `wire` is untagged Ethernet II, the socket is bound to `ETH_P_ARP`. When it requests IEEE
/// 802.1Q tagging (customer or service) or RFC 1042 LLC/SNAP, the socket is bound to `ETH_P_ALL`
/// so tagged and SNAP replies are delivered. The send destination protocol is `ETH_P_8021AD`
/// (`0x88A8`) for service-tagged frames, `ETH_P_8021Q` (`0x8100`) for customer-tagged frames,
/// `ETH_P_802_2` for untagged SNAP, and `ETH_P_ARP` otherwise.
///
/// # Errors
///
/// Returns [`AppError`] when the interface name is invalid or unusable, when the raw socket cannot
/// be opened or bound (for example missing `CAP_NET_RAW`), or when the interface index does not fit
/// the link-layer address.
///
/// # Panics
///
/// This function does not panic.
pub fn open_linux_link_layer_endpoint(
    interface_name: &str,
    wire: &ScanWireOptions,
) -> Result<LinuxLinkLayerEndpoint, AppError> {
    let interface_index = validated_interface_index_for_arp_scanning(interface_name)?;
    let capture_protocol = packet_socket_protocol_for_wire_options(wire);
    let send_protocol = link_layer_send_protocol_for_wire_options(wire);
    let packet_socket = open_raw_packet_socket(capture_protocol)?;
    bind_packet_socket_to_interface(
        &packet_socket,
        interface_name,
        interface_index,
        capture_protocol,
    )?;
    let link_layer_destination =
        link_layer_broadcast_destination_for_scan(interface_name, interface_index, send_protocol)?;
    Ok(LinuxLinkLayerEndpoint {
        packet_socket,
        link_layer_destination,
    })
}

/// Capture protocol for passive monitoring.
///
/// `ETH_P_ALL` delivers the Ethernet II, single-tag IEEE 802.1Q, service-plus-customer tag, and
/// RFC 1042 SNAP shapes the existing parser already accepts. `ETH_P_ARP` would hide every frame
/// whose outermost type is not `0x0806`. The kernel still strips the outermost VLAN tag before
/// `AF_PACKET` delivery; this socket does not request `PACKET_AUXDATA`, so that stripped tag is
/// not recovered.
#[allow(dead_code)] // Called by `open_linux_monitor_link_layer_endpoint`.
fn monitor_packet_capture_protocol() -> u16 {
    ETHERNET_PROTOCOL_ALL
}

/// Opens a raw `AF_PACKET` socket bound to `ETH_P_ALL` for receive-only ARP monitoring.
///
/// The endpoint can transmit, but passive monitoring must not call
/// [`LinkLayerEndpoint::send_ethernet_frame`]. The unused send destination stays `ETH_P_ARP` so
/// this opener does not advertise a new transmit framing.
///
/// # Errors
///
/// Returns [`AppError`] when the interface name is invalid or unusable, when the raw socket cannot
/// be opened or bound (for example missing `CAP_NET_RAW`), or when the interface index does not fit
/// the link-layer address.
///
/// # Panics
///
/// This function does not panic.
#[allow(dead_code)] // Called by the Linux monitor wrapper in the following change.
pub fn open_linux_monitor_link_layer_endpoint(
    interface_name: &str,
) -> Result<LinuxLinkLayerEndpoint, AppError> {
    let interface_index = validated_interface_index_for_arp_scanning(interface_name)?;
    let capture_protocol = monitor_packet_capture_protocol();
    let packet_socket = open_raw_packet_socket(capture_protocol)?;
    bind_packet_socket_to_interface(
        &packet_socket,
        interface_name,
        interface_index,
        capture_protocol,
    )?;
    let link_layer_destination = link_layer_broadcast_destination_for_scan(
        interface_name,
        interface_index,
        ETHERNET_PROTOCOL_ARP,
    )?;
    Ok(LinuxLinkLayerEndpoint {
        packet_socket,
        link_layer_destination,
    })
}

impl LinkLayerEndpoint for LinuxLinkLayerEndpoint {
    fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
        linux_system_call::send_to_link_layer(
            &self.packet_socket,
            frame,
            self.link_layer_destination.as_libc_sockaddr_link_layer(),
        )
        .map(|_sent| ())
    }

    fn wait_until_readable(&self, timeout_milliseconds: libc::c_int) -> Result<bool, AppError> {
        match linux_system_call::poll_socket_readiness(
            &self.packet_socket,
            libc::POLLIN,
            timeout_milliseconds,
        ) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => Ok(false),
            Err(source) => Err(AppError::PollWaitFailed { source }),
        }
    }

    fn try_receive_ethernet_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, AppError> {
        loop {
            match linux_system_call::receive_from_link_layer(
                &self.packet_socket,
                buffer,
                libc::MSG_DONTWAIT,
                None,
            ) {
                Ok(0) => return Ok(None),
                Ok(bytes_received) => return Ok(Some(bytes_received)),
                Err(source)
                    if source.raw_os_error() == Some(libc::EAGAIN)
                        || source.raw_os_error() == Some(libc::EWOULDBLOCK) =>
                {
                    return Ok(None);
                }
                Err(source) if source.kind() == std::io::ErrorKind::Interrupted => {}
                Err(source) => return Err(AppError::RawPacketReceiveFailed { source }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::link_layer_send_protocol_for_wire_options;
    use super::monitor_packet_capture_protocol;
    use super::open_linux_monitor_link_layer_endpoint;
    use super::packet_socket_protocol_for_wire_options;
    use super::validate_interface_flags_for_arp_scanning;
    use crate::application_command::ScanWireOptions;
    use crate::error::AppError;
    use crate::ethernet_frame::{
        ETHERNET_PROTOCOL_VLAN_TAG, ETHERNET_PROTOCOL_VLAN_TAG_SERVICE, Ieee8021qVlanIdentifier,
    };
    use crate::linux_packet::{
        ETHERNET_PROTOCOL_ALL, ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IEEE_802_2,
        INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP,
    };

    #[test]
    fn returns_error_when_interface_flags_indicate_loopback() {
        // Arrange
        let interface_name = "lo";
        let flags = INTERFACE_FLAG_UP | INTERFACE_FLAG_LOOPBACK;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_flags_indicate_no_arp() {
        // Arrange
        let interface_name = "eth0";
        let flags = INTERFACE_FLAG_UP | INTERFACE_FLAG_NO_ARP;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "NOARP should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_flags_indicate_administratively_down() {
        // Arrange
        let interface_name = "eth0";
        let flags = 0;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "not UP should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn accepts_interface_flags_when_interface_is_up_and_not_loopback_and_arp_enabled() {
        // Arrange
        let interface_name = "eth0";
        let flags = INTERFACE_FLAG_UP;

        // Act
        let outcome = validate_interface_flags_for_arp_scanning(interface_name, flags);

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "UP non-loopback without NOARP should be accepted, got: {outcome:?}"
        );
    }

    #[test]
    fn packet_socket_uses_eth_p_all_when_vlan_or_llc_snap_is_set() {
        // Arrange
        let vlan_identifier = Ieee8021qVlanIdentifier::new(7).expect("VID 7 fits in 12 bits");
        let tagged = ScanWireOptions {
            vlan_identifier: Some(vlan_identifier),
            ..ScanWireOptions::default()
        };
        let llc_snap = ScanWireOptions {
            llc_snap: true,
            ..ScanWireOptions::default()
        };
        let untagged = ScanWireOptions::default();
        let vlan_and_llc = ScanWireOptions {
            vlan_identifier: Some(vlan_identifier),
            llc_snap: true,
            ..ScanWireOptions::default()
        };

        // Act
        let tagged_capture = packet_socket_protocol_for_wire_options(&tagged);
        let tagged_send = link_layer_send_protocol_for_wire_options(&tagged);
        let llc_capture = packet_socket_protocol_for_wire_options(&llc_snap);
        let llc_send = link_layer_send_protocol_for_wire_options(&llc_snap);
        let untagged_capture = packet_socket_protocol_for_wire_options(&untagged);
        let untagged_send = link_layer_send_protocol_for_wire_options(&untagged);
        let vlan_and_llc_capture = packet_socket_protocol_for_wire_options(&vlan_and_llc);
        let vlan_and_llc_send = link_layer_send_protocol_for_wire_options(&vlan_and_llc);

        // Assert
        assert_eq!(
            tagged_capture, ETHERNET_PROTOCOL_ALL,
            "tagged scans must receive both 0x8100 and stripped ARP"
        );
        assert_eq!(
            tagged_send, ETHERNET_PROTOCOL_VLAN_TAG,
            "tagged send sockaddr_ll protocol should match the outer TPID"
        );
        assert_eq!(
            llc_capture, ETHERNET_PROTOCOL_ALL,
            "LLC/SNAP scans must receive IEEE 802.3 length-field frames"
        );
        assert_eq!(
            llc_send, ETHERNET_PROTOCOL_IEEE_802_2,
            "untagged SNAP send sockaddr_ll protocol should be ETH_P_802_2"
        );
        assert_eq!(
            untagged_capture, ETHERNET_PROTOCOL_ARP,
            "untagged Ethernet II scans should keep ETH_P_ARP capture"
        );
        assert_eq!(
            untagged_send, ETHERNET_PROTOCOL_ARP,
            "untagged Ethernet II send sockaddr_ll protocol should stay ARP"
        );
        assert_eq!(
            vlan_and_llc_capture, ETHERNET_PROTOCOL_ALL,
            "tagged SNAP still needs ETH_P_ALL capture"
        );
        assert_eq!(
            vlan_and_llc_send, ETHERNET_PROTOCOL_VLAN_TAG,
            "outer 802.1Q TPID is the send protocol when both VLAN and SNAP are set"
        );
    }

    #[test]
    fn service_tagged_scan_captures_eth_p_all_and_sends_with_the_outer_service_tpid() {
        // Arrange
        let customer = Ieee8021qVlanIdentifier::new(10).expect("C-VID 10 fits in 12 bits");
        let service = Ieee8021qVlanIdentifier::new(100).expect("S-VID 100 fits in 12 bits");
        let stacked = ScanWireOptions {
            vlan_identifier: Some(customer),
            service_vlan_identifier: Some(service),
            ..ScanWireOptions::default()
        };
        let stacked_with_llc = ScanWireOptions {
            llc_snap: true,
            ..stacked.clone()
        };

        // Act
        let stacked_capture = packet_socket_protocol_for_wire_options(&stacked);
        let stacked_send = link_layer_send_protocol_for_wire_options(&stacked);
        let stacked_with_llc_capture = packet_socket_protocol_for_wire_options(&stacked_with_llc);
        let stacked_with_llc_send = link_layer_send_protocol_for_wire_options(&stacked_with_llc);

        // Assert
        assert_eq!(
            stacked_capture, ETHERNET_PROTOCOL_ALL,
            "a QinQ scan must bind ETH_P_ALL: after the kernel untags the S-TAG the delivery \
             protocol is the inner 0x8100, which ETH_P_ARP would never match"
        );
        assert_eq!(
            stacked_send, ETHERNET_PROTOCOL_VLAN_TAG_SERVICE,
            "a service-tagged send must use the outer TPID 0x88A8, not the inner 0x8100"
        );
        assert_eq!(
            stacked_with_llc_capture, ETHERNET_PROTOCOL_ALL,
            "adding --llc must not narrow the capture protocol"
        );
        assert_eq!(
            stacked_with_llc_send, ETHERNET_PROTOCOL_VLAN_TAG_SERVICE,
            "the outer TPID still leads the frame when RFC 1042 SNAP is used inside the tags"
        );
    }

    #[test]
    fn capture_protocol_falls_back_to_eth_p_all_for_a_service_tag_even_without_a_customer_tag() {
        // Arrange: this combination is rejected before transmit by
        // `ScanWireOptions::validate_ieee_8021q_tag_stack`, but the capture choice must still be
        // the permissive one rather than silently binding ETH_P_ARP.
        let service_only = ScanWireOptions {
            vlan_identifier: None,
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
            ..ScanWireOptions::default()
        };

        // Act
        let capture = packet_socket_protocol_for_wire_options(&service_only);
        let send = link_layer_send_protocol_for_wire_options(&service_only);

        // Assert
        assert_eq!(capture, ETHERNET_PROTOCOL_ALL);
        assert_eq!(
            send, ETHERNET_PROTOCOL_ARP,
            "with no encodable tag stack the send protocol stays plain ARP"
        );
    }

    #[test]
    fn monitor_capture_protocol_is_eth_p_all() {
        // Act
        let protocol = monitor_packet_capture_protocol();

        // Assert
        assert_eq!(
            protocol, ETHERNET_PROTOCOL_ALL,
            "passive monitoring must not bind the narrower ETH_P_ARP capture"
        );
    }

    #[test]
    fn open_linux_monitor_link_layer_endpoint_rejects_loopback() {
        // Act
        let outcome = open_linux_monitor_link_layer_endpoint("lo");

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InterfaceRejectedForScanning { .. })),
            "loopback must be rejected before a monitor socket is opened"
        );
    }

    #[test]
    fn open_linux_monitor_link_layer_endpoint_rejects_unknown_interface() {
        // Act
        let outcome = open_linux_monitor_link_layer_endpoint("narp_none____");

        // Assert
        let Err(error) = outcome else {
            panic!("an unknown interface must fail before socket allocation");
        };
        assert!(
            matches!(error, AppError::InterfaceLookupFailed { .. }),
            "an unknown interface must fail lookup, got: {error}"
        );
    }
}
