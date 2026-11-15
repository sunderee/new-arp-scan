//! Linux packet socket constants and the `sockaddr_ll` layout used with `bind(2)`.

#![allow(
    unsafe_code,
    reason = "libc FFI for the Linux packet backend; see DECISIONS.md 2026-11-15"
)]

/// Linux packet socket address family (`AF_PACKET`).
pub const SOCKET_ADDRESS_FAMILY_PACKET: libc::c_ushort = 17;

/// Ethernet protocol identifier for ARP (`ETH_P_ARP` in `linux/if_ether.h`).
pub const ETHERNET_PROTOCOL_ARP: u16 = 0x0806;

/// Packet-socket protocol that delivers every Ethernet type (`ETH_P_ALL` in `linux/if_ether.h`).
///
/// Used when transmitting IEEE 802.1Q-tagged ARP so replies can arrive tagged (`0x8100`) or with
/// the tag stripped by the NIC or bridge, and when transmitting RFC 1042 LLC/SNAP so the length
/// field is not mistaken for `ETH_P_ARP`.
pub const ETHERNET_PROTOCOL_ALL: u16 = 0x0003;

/// IEEE 802.2 frames (`ETH_P_802_2` in `linux/if_ether.h`), used as the send protocol for untagged
/// RFC 1042 LLC/SNAP ARP.
pub const ETHERNET_PROTOCOL_IEEE_802_2: u16 = 0x0004;

/// `IFF_UP` from `linux/if.h` (interface is administratively up).
pub const INTERFACE_FLAG_UP: i32 = 0x0001;

/// `IFF_LOOPBACK` from `linux/if.h`.
pub const INTERFACE_FLAG_LOOPBACK: i32 = 0x0008;

/// `IFF_NOARP` from `linux/if.h`.
pub const INTERFACE_FLAG_NO_ARP: i32 = 0x0080;

/// Device-independent link-layer socket address (`struct sockaddr_ll` in `linux/if_packet.h`).
///
/// Field order and primitive widths match Linux `sockaddr_ll` as exposed by `libc`.
#[repr(C)]
pub struct SockAddressLinkLayer {
    /// Address family; always `AF_PACKET` when used with packet sockets.
    pub socket_address_family: libc::c_ushort,
    /// Physical-layer protocol in network byte order (for example [`ETHERNET_PROTOCOL_ARP`]).
    pub link_layer_protocol: libc::c_ushort,
    /// Interface index (`ifindex`).
    pub interface_index: libc::c_int,
    /// ARP hardware type (`ARPHRD_*`).
    pub hardware_type: libc::c_ushort,
    /// Packet type (`PACKET_*`, primarily for received packets).
    pub packet_type: libc::c_uchar,
    /// Length of [`Self::hardware_address`] bytes that are valid.
    pub hardware_address_length: libc::c_uchar,
    /// Physical-layer address bytes (for Ethernet, typically 6 octets used).
    pub hardware_address: [libc::c_uchar; 8],
}

impl SockAddressLinkLayer {
    /// Borrows this structure as a [`libc::sockaddr_ll`].
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn as_libc_sockaddr_link_layer(&self) -> &libc::sockaddr_ll {
        // SAFETY: `SockAddressLinkLayer` is `repr(C)` and matches `libc::sockaddr_ll` layout on
        // Linux targets where unit tests assert size, alignment, and field offsets.
        unsafe { &*std::ptr::from_ref(self).cast::<libc::sockaddr_ll>() }
    }
}

/// Converts an Ethernet protocol identifier from host byte order to network byte order for
/// `packet(7)` APIs.
///
/// # Panics
///
/// This function does not panic.
pub fn ethernet_protocol_host_to_network_order(
    ethernet_protocol_host_order: u16,
) -> libc::c_ushort {
    ethernet_protocol_host_order.to_be()
}

#[cfg(test)]
mod tests {
    use super::SockAddressLinkLayer;
    use super::{
        ETHERNET_PROTOCOL_ALL, ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IEEE_802_2,
        INTERFACE_FLAG_LOOPBACK, INTERFACE_FLAG_NO_ARP, INTERFACE_FLAG_UP,
        SOCKET_ADDRESS_FAMILY_PACKET, ethernet_protocol_host_to_network_order,
    };
    use crate::address_resolution_protocol::{
        ARP_HARDWARE_TYPE_ETHERNET, ARP_OPERATION_REPLY, ARP_OPERATION_REQUEST,
    };
    use std::mem::offset_of;

    #[test]
    fn sockaddr_ll_mirror_matches_libc_size_and_alignment() {
        // Arrange
        // Act
        let expected_size = std::mem::size_of::<libc::sockaddr_ll>();
        let expected_alignment = std::mem::align_of::<libc::sockaddr_ll>();
        let actual_size = std::mem::size_of::<SockAddressLinkLayer>();
        let actual_alignment = std::mem::align_of::<SockAddressLinkLayer>();

        // Assert
        assert_eq!(
            actual_size, expected_size,
            "SockAddressLinkLayer size should match libc::sockaddr_ll"
        );
        assert_eq!(
            actual_alignment, expected_alignment,
            "SockAddressLinkLayer alignment should match libc::sockaddr_ll"
        );
    }

    #[test]
    fn sockaddr_ll_mirror_matches_libc_field_offsets() {
        // Arrange
        // Act
        let pairs = [
            (
                offset_of!(SockAddressLinkLayer, socket_address_family),
                offset_of!(libc::sockaddr_ll, sll_family),
                "socket_address_family",
            ),
            (
                offset_of!(SockAddressLinkLayer, link_layer_protocol),
                offset_of!(libc::sockaddr_ll, sll_protocol),
                "link_layer_protocol",
            ),
            (
                offset_of!(SockAddressLinkLayer, interface_index),
                offset_of!(libc::sockaddr_ll, sll_ifindex),
                "interface_index",
            ),
            (
                offset_of!(SockAddressLinkLayer, hardware_type),
                offset_of!(libc::sockaddr_ll, sll_hatype),
                "hardware_type",
            ),
            (
                offset_of!(SockAddressLinkLayer, packet_type),
                offset_of!(libc::sockaddr_ll, sll_pkttype),
                "packet_type",
            ),
            (
                offset_of!(SockAddressLinkLayer, hardware_address_length),
                offset_of!(libc::sockaddr_ll, sll_halen),
                "hardware_address_length",
            ),
            (
                offset_of!(SockAddressLinkLayer, hardware_address),
                offset_of!(libc::sockaddr_ll, sll_addr),
                "hardware_address",
            ),
        ];

        // Assert
        for (ours, libc_offset, label) in pairs {
            assert_eq!(
                ours, libc_offset,
                "field offset mismatch for {label}: ours={ours} libc={libc_offset}"
            );
        }
    }

    #[test]
    fn ethernet_protocol_arp_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            libc::c_int::from(ETHERNET_PROTOCOL_ARP),
            libc::ETH_P_ARP,
            "ETHERNET_PROTOCOL_ARP should match libc::ETH_P_ARP"
        );
    }

    #[test]
    fn ethernet_protocol_all_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            libc::c_int::from(ETHERNET_PROTOCOL_ALL),
            libc::ETH_P_ALL,
            "ETHERNET_PROTOCOL_ALL should match libc::ETH_P_ALL"
        );
    }

    #[test]
    fn ethernet_protocol_ieee_802_2_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            libc::c_int::from(ETHERNET_PROTOCOL_IEEE_802_2),
            libc::ETH_P_802_2,
            "ETHERNET_PROTOCOL_IEEE_802_2 should match libc::ETH_P_802_2"
        );
    }

    #[test]
    fn socket_address_family_packet_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            libc::c_int::from(SOCKET_ADDRESS_FAMILY_PACKET),
            libc::AF_PACKET,
            "SOCKET_ADDRESS_FAMILY_PACKET should match libc::AF_PACKET"
        );
    }

    #[test]
    fn ethernet_protocol_network_order_matches_native_to_be() {
        // Arrange
        // Act
        let protocol = ethernet_protocol_host_to_network_order(ETHERNET_PROTOCOL_ARP);

        // Assert
        assert_eq!(
            protocol,
            ETHERNET_PROTOCOL_ARP.to_be(),
            "packet socket protocol should be stored as network byte order u16"
        );
    }

    #[test]
    fn arp_hardware_type_ethernet_matches_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            ARP_HARDWARE_TYPE_ETHERNET,
            libc::ARPHRD_ETHER,
            "ARP_HARDWARE_TYPE_ETHERNET should match libc::ARPHRD_ETHER"
        );
    }

    #[test]
    fn arp_operation_constants_match_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            ARP_OPERATION_REQUEST,
            libc::ARPOP_REQUEST,
            "ARP_OPERATION_REQUEST should match libc::ARPOP_REQUEST"
        );
        assert_eq!(
            ARP_OPERATION_REPLY,
            libc::ARPOP_REPLY,
            "ARP_OPERATION_REPLY should match libc::ARPOP_REPLY"
        );
    }

    #[test]
    fn interface_name_buffer_size_matches_libc() {
        // Arrange
        use crate::interface_validation;

        // Act
        let libc_value = libc::IFNAMSIZ;

        // Assert
        assert_eq!(
            interface_validation::INTERFACE_NAME_BUFFER_SIZE,
            libc_value,
            "INTERFACE_NAME_BUFFER_SIZE should match libc::IFNAMSIZ"
        );
    }

    #[test]
    fn interface_flag_constants_match_libc() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            INTERFACE_FLAG_UP,
            libc::IFF_UP,
            "INTERFACE_FLAG_UP should match libc::IFF_UP"
        );
        assert_eq!(
            INTERFACE_FLAG_LOOPBACK,
            libc::IFF_LOOPBACK,
            "INTERFACE_FLAG_LOOPBACK should match libc::IFF_LOOPBACK"
        );
        assert_eq!(
            INTERFACE_FLAG_NO_ARP,
            libc::IFF_NOARP,
            "INTERFACE_FLAG_NO_ARP should match libc::IFF_NOARP"
        );
    }

    #[test]
    fn sockaddr_link_layer_as_libc_view_reflects_assigned_scan_fields() {
        // Arrange
        let mut address = SockAddressLinkLayer {
            socket_address_family: SOCKET_ADDRESS_FAMILY_PACKET,
            link_layer_protocol: ethernet_protocol_host_to_network_order(ETHERNET_PROTOCOL_ARP),
            interface_index: 42,
            hardware_type: ARP_HARDWARE_TYPE_ETHERNET,
            packet_type: 0,
            hardware_address_length: 6,
            hardware_address: [0; 8],
        };
        address.hardware_address[0..6].copy_from_slice(&[0xFF; 6]);

        // Act
        let ll = address.as_libc_sockaddr_link_layer();

        // Assert
        assert_eq!(ll.sll_family, address.socket_address_family);
        assert_eq!(ll.sll_protocol, address.link_layer_protocol);
        assert_eq!(ll.sll_ifindex, address.interface_index);
        assert_eq!(ll.sll_hatype, address.hardware_type);
        assert_eq!(ll.sll_pkttype, address.packet_type);
        assert_eq!(ll.sll_halen, address.hardware_address_length);
        assert_eq!(&ll.sll_addr[..6], &[0xFFu8; 6]);
    }
}
