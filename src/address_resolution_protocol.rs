//! IPv4 address resolution protocol (ARP) over Ethernet serialization and reply parsing.
//!
//! Request frames are built with an explicit Ethernet II header, a 28-byte ARP payload matching
//! RFC 826, then zero-filled padding to the IEEE 802.3 minimum frame length without the frame
//! check sequence. Parsers accept Ethernet II, one IEEE 802.1Q customer tag, one IEEE 802.1Q
//! service tag wrapping one customer tag (IEEE 802.1ad), and RFC 1042 LLC/SNAP,
//! and they reject RFC 5494 reserved hardware-type and opcode values. The public reply parser
//! still requires opcode 2; a crate-internal parser accepts any non-reserved opcode so the scanner
//! can ignore well-formed requests without treating them as malformed frames.

use std::net::Ipv4Addr;

use crate::ethernet_frame::{
    ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IPV4, IEEE_8023_LLC_SNAP_HEADER_LENGTH,
    IEEE_8023_MAXIMUM_LENGTH, Ieee8021qTagControlInformation, Ieee8021qTagStack,
    Ieee8021qVlanIdentifier, encode_ethernet_ii_frame_with_optional_ieee_8021q_tag,
    encode_ieee_8023_rfc_1042_llc_snap_frame, try_parse_ethernet_frame,
};
use crate::mac_address::MacAddress;

/// ARP hardware type for Ethernet (`ARPHRD_ETHER` in `linux/if_arp.h`, RFC 826 `ar$hrd`).
pub(crate) const ARP_HARDWARE_TYPE_ETHERNET: u16 = 1;

/// ARP opcode for a request (`ARPOP_REQUEST`, RFC 826 `ares_op$REQUEST`).
pub(crate) const ARP_OPERATION_REQUEST: u16 = 1;

/// ARP opcode for a reply (`ARPOP_REPLY`, RFC 826 `ares_op$REPLY`).
pub(crate) const ARP_OPERATION_REPLY: u16 = 2;

/// RFC 5494 reserved `ar$hrd` / `ar$op` value 0.
const ARP_RESERVED_FIELD_ZERO: u16 = 0;

/// RFC 5494 reserved `ar$hrd` / `ar$op` value 65535.
const ARP_RESERVED_FIELD_ALL_ONES: u16 = 65535;

/// RFC 826 `ar$hrd` offset in an IPv4-over-Ethernet ARP payload.
const ARP_HARDWARE_TYPE_OFFSET: usize = 0;

/// RFC 826 `ar$pro` offset.
const ARP_PROTOCOL_TYPE_OFFSET: usize = 2;

/// RFC 826 `ar$hln` offset.
const ARP_HARDWARE_LENGTH_OFFSET: usize = 4;

/// RFC 826 `ar$pln` offset.
const ARP_PROTOCOL_LENGTH_OFFSET: usize = 5;

/// RFC 826 `ar$op` offset.
const ARP_OPCODE_OFFSET: usize = 6;

/// RFC 826 `ar$sha` offset for Ethernet (`ar$hln` = 6).
const ARP_SENDER_HARDWARE_OFFSET: usize = 8;

/// RFC 826 `ar$spa` offset for Ethernet plus IPv4.
const ARP_SENDER_PROTOCOL_OFFSET: usize = 14;

/// RFC 826 `ar$tha` offset for Ethernet plus IPv4.
const ARP_TARGET_HARDWARE_OFFSET: usize = 18;

/// RFC 826 `ar$tpa` offset for Ethernet plus IPv4.
const ARP_TARGET_PROTOCOL_OFFSET: usize = 24;

const _: () = {
    assert!(ARP_OPERATION_REQUEST == 1);
    assert!(ARP_OPERATION_REPLY == 2);
    assert!(ARP_HARDWARE_TYPE_ETHERNET == 1);
};

/// Length of a minimal ARP packet for IPv4 over Ethernet (fixed field layout).
pub const ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH: usize = 28;

/// Ethernet hardware address length (`ar$hln`) for IEEE 802 48-bit addresses.
pub const ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH: u8 = 6;

/// IPv4 protocol address length (`ar$pln`).
pub const ARP_IPV4_PROTOCOL_ADDRESS_LENGTH: u8 = 4;

/// Minimum Ethernet frame length excluding the frame check sequence (IEEE 802.3).
pub const MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE: usize = 60;

/// IEEE 802.3 MAC client data minimum (46 octets) that ARP's 28-byte payload must be padded to.
pub const MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH: usize = 46;

/// Empty custom payload padding used by RFC 826 default request builders.
const EMPTY_ETHERNET_PADDING: &[u8] = &[];

/// Fully resolved Ethernet and RFC 826 fields for one transmitted ARP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AddressResolutionRequestLayout<'a> {
    /// Ethernet destination (broadcast unless `--destaddr` overrides it).
    pub ethernet_destination: MacAddress,
    /// Ethernet source (`--srcaddr`, defaulting to the interface MAC).
    pub ethernet_source: MacAddress,
    /// Optional IEEE 802.1Q tag stack: one customer tag, or a service tag wrapping a customer tag.
    pub vlan_tag: Option<Ieee8021qTagStack>,
    /// RFC 1042 LLC/SNAP instead of Ethernet II.
    pub llc_snap: bool,
    /// RFC 826 `ar$hrd`.
    pub hardware_type: u16,
    /// RFC 826 `ar$pro`.
    pub protocol_type: u16,
    /// RFC 826 `ar$hln` (does not change the encoded SHA/THA widths).
    pub hardware_length: u8,
    /// RFC 826 `ar$pln` (does not change the encoded SPA/TPA widths).
    pub protocol_length: u8,
    /// RFC 826 `ar$op`.
    pub opcode: u16,
    /// RFC 826 `ar$sha`.
    pub sender_hardware: MacAddress,
    /// RFC 826 `ar$spa`.
    pub sender_protocol: Ipv4Addr,
    /// RFC 826 `ar$tha`.
    pub target_hardware: MacAddress,
    /// RFC 826 `ar$tpa`.
    pub target_protocol: Ipv4Addr,
    /// Octets appended after the 28-octet ARP PDU (`--padding`). Not the IEEE 802.3 minimum-frame
    /// zero pad.
    pub padding: &'a [u8],
}

impl AddressResolutionRequestLayout<'static> {
    /// RFC 826 Ethernet II request: broadcast destination, interface MAC as Ethernet source and
    /// `ar$sha`, zero `ar$tha`, request opcode, Ethernet/IPv4 type lengths.
    #[must_use]
    pub(crate) fn rfc_826_ethernet_ii(
        interface_mac_address: MacAddress,
        source_ipv4_address: Ipv4Addr,
        target_ipv4_address: Ipv4Addr,
    ) -> Self {
        Self {
            ethernet_destination: MacAddress::BROADCAST,
            ethernet_source: interface_mac_address,
            vlan_tag: None,
            llc_snap: false,
            hardware_type: ARP_HARDWARE_TYPE_ETHERNET,
            protocol_type: ETHERNET_PROTOCOL_IPV4,
            hardware_length: ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH,
            protocol_length: ARP_IPV4_PROTOCOL_ADDRESS_LENGTH,
            opcode: ARP_OPERATION_REQUEST,
            sender_hardware: interface_mac_address,
            sender_protocol: source_ipv4_address,
            target_hardware: MacAddress::ZERO,
            target_protocol: target_ipv4_address,
            padding: EMPTY_ETHERNET_PADDING,
        }
    }
}

const _: () = {
    assert!(
        14 + MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
            == MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
    );
    assert!(
        ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH
            + (MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
                - ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH)
            == MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
    );
};

/// Builds a minimum-length on-wire Ethernet frame carrying an IPv4 ARP request.
///
/// The Ethernet II header and 28-byte ARP payload are built first, then the buffer is zero-padded
/// to [`MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE`] octets for link-layer minimum
/// size. Sender protocol address is `source_ipv4_address` (RFC 826 request, not an RFC 5227 Probe).
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use new_arp_scan::{MacAddress, build_address_resolution_request_ethernet_frame};
///
/// let frame = build_address_resolution_request_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     Ipv4Addr::new(192, 168, 1, 1),
///     Ipv4Addr::new(192, 168, 1, 50),
/// );
/// assert_eq!(&frame[12..14], &[0x08, 0x06]);
/// assert_eq!(frame.len(), 60);
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_request_ethernet_frame(
    source_mac_address: MacAddress,
    source_ipv4_address: Ipv4Addr,
    target_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag(
        source_mac_address,
        source_ipv4_address,
        target_ipv4_address,
        None,
    )
}

/// Builds a minimum-length Ethernet frame carrying an IPv4 ARP request, with an optional IEEE
/// 802.1Q tag.
///
/// When `vlan_identifier` is [`None`], this matches
/// [`build_address_resolution_request_ethernet_frame`]. When it is [`Some`], the Ethernet header
/// is destination, source, TPID `0x8100`, TCI (VID only), inner `EtherType` `0x0806`, then the
/// RFC 826 ARP payload. The buffer is still zero-padded to
/// [`MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE`] (IEEE 802.3 / 802.3ac minimum
/// without the frame check sequence, matching original `arp-scan` `ETH_ZLEN` padding).
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag(
    source_mac_address: MacAddress,
    source_ipv4_address: Ipv4Addr,
    target_ipv4_address: Ipv4Addr,
    vlan_identifier: Option<Ieee8021qVlanIdentifier>,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    build_address_resolution_request_ethernet_frame_with_wire_options(
        source_mac_address,
        source_ipv4_address,
        target_ipv4_address,
        vlan_identifier,
        false,
    )
}

/// Builds a minimum-length Ethernet frame carrying an IPv4 ARP request, with optional IEEE 802.1Q
/// tagging and optional RFC 1042 LLC/SNAP encapsulation.
///
/// When `llc_snap` is false, this matches
/// [`build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag`]. When it is
/// true, the frame uses an IEEE 802.3 length field and RFC 1042 LLC/SNAP (`AA AA 03` plus OUI
/// `00:00:00` plus `EtherType` `0x0806`) before the ARP payload. The buffer is still zero-padded to
/// [`MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE`].
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_request_ethernet_frame_with_wire_options(
    source_mac_address: MacAddress,
    source_ipv4_address: Ipv4Addr,
    target_ipv4_address: Ipv4Addr,
    vlan_identifier: Option<Ieee8021qVlanIdentifier>,
    llc_snap: bool,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    let mut layout = AddressResolutionRequestLayout::rfc_826_ethernet_ii(
        source_mac_address,
        source_ipv4_address,
        target_ipv4_address,
    );
    layout.vlan_tag = vlan_identifier
        .map(Ieee8021qTagControlInformation::from)
        .map(Ieee8021qTagStack::Customer);
    layout.llc_snap = llc_snap;
    copy_into_minimum_ethernet_frame(&encode_address_resolution_request_from_layout(layout))
}

/// Builds an RFC 5227 ARP Probe: an ARP request with an all-zero sender IPv4 address.
///
/// Sender hardware address is the scanning interface MAC. Target hardware address is all zeroes.
/// Target protocol address is the address being probed.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use new_arp_scan::{MacAddress, build_address_resolution_probe_ethernet_frame};
///
/// let frame = build_address_resolution_probe_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     Ipv4Addr::new(192, 168, 1, 50),
/// );
/// assert_eq!(&frame[28..32], &[0, 0, 0, 0]);
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_probe_ethernet_frame(
    source_mac_address: MacAddress,
    target_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    copy_into_minimum_ethernet_frame(&encode_address_resolution_request_from_layout(
        AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            source_mac_address,
            Ipv4Addr::UNSPECIFIED,
            target_ipv4_address,
        ),
    ))
}

/// Builds an RFC 5227 ARP Announcement: an ARP request whose sender and target IPv4 addresses are
/// both the claimed address.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
/// use new_arp_scan::{MacAddress, build_address_resolution_announcement_ethernet_frame};
///
/// let claimed = Ipv4Addr::new(192, 168, 1, 50);
/// let frame = build_address_resolution_announcement_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     claimed,
/// );
/// assert_eq!(&frame[28..32], &claimed.octets());
/// assert_eq!(&frame[38..42], &claimed.octets());
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn build_address_resolution_announcement_ethernet_frame(
    source_mac_address: MacAddress,
    claimed_ipv4_address: Ipv4Addr,
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    copy_into_minimum_ethernet_frame(&encode_address_resolution_request_from_layout(
        AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            source_mac_address,
            claimed_ipv4_address,
            claimed_ipv4_address,
        ),
    ))
}

/// Encodes one ARP request from already-resolved Ethernet and RFC 826 fields.
///
/// Custom [`AddressResolutionRequestLayout::padding`] is appended after the 28-octet ARP PDU. The
/// frame is then zero-padded to
/// [`MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE`] when shorter. IEEE 802.3 SNAP
/// length fields include LLC, SNAP, ARP, and custom padding, but not the minimum-frame zero pad.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub(crate) fn encode_address_resolution_request_from_layout(
    layout: AddressResolutionRequestLayout<'_>,
) -> Vec<u8> {
    let mut address_resolution_header = [0u8; ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
    address_resolution_header[ARP_HARDWARE_TYPE_OFFSET..ARP_HARDWARE_TYPE_OFFSET + 2]
        .copy_from_slice(&layout.hardware_type.to_be_bytes());
    address_resolution_header[ARP_PROTOCOL_TYPE_OFFSET..ARP_PROTOCOL_TYPE_OFFSET + 2]
        .copy_from_slice(&layout.protocol_type.to_be_bytes());
    address_resolution_header[ARP_HARDWARE_LENGTH_OFFSET] = layout.hardware_length;
    address_resolution_header[ARP_PROTOCOL_LENGTH_OFFSET] = layout.protocol_length;
    address_resolution_header[ARP_OPCODE_OFFSET..ARP_OPCODE_OFFSET + 2]
        .copy_from_slice(&layout.opcode.to_be_bytes());
    address_resolution_header[ARP_SENDER_HARDWARE_OFFSET..ARP_SENDER_HARDWARE_OFFSET + 6]
        .copy_from_slice(&layout.sender_hardware.octets());
    address_resolution_header[ARP_SENDER_PROTOCOL_OFFSET..ARP_SENDER_PROTOCOL_OFFSET + 4]
        .copy_from_slice(&layout.sender_protocol.octets());
    address_resolution_header[ARP_TARGET_HARDWARE_OFFSET..ARP_TARGET_HARDWARE_OFFSET + 6]
        .copy_from_slice(&layout.target_hardware.octets());
    address_resolution_header[ARP_TARGET_PROTOCOL_OFFSET..ARP_TARGET_PROTOCOL_OFFSET + 4]
        .copy_from_slice(&layout.target_protocol.octets());
    let mut address_resolution_payload = Vec::with_capacity(
        ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH.saturating_add(layout.padding.len()),
    );
    address_resolution_payload.extend_from_slice(&address_resolution_header);
    address_resolution_payload.extend_from_slice(layout.padding);

    let mut ethernet_body = if layout.llc_snap {
        encode_ieee_8023_rfc_1042_llc_snap_frame(
            layout.ethernet_destination,
            layout.ethernet_source,
            layout.vlan_tag,
            ETHERNET_PROTOCOL_ARP,
            &address_resolution_payload,
        )
    } else {
        encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
            layout.ethernet_destination,
            layout.ethernet_source,
            layout.vlan_tag,
            ETHERNET_PROTOCOL_ARP,
            &address_resolution_payload,
        )
    };

    if ethernet_body.len() < MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE {
        ethernet_body.resize(
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            0,
        );
    }
    ethernet_body
}

fn copy_into_minimum_ethernet_frame(
    frame: &[u8],
) -> [u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE] {
    let mut minimum = [0u8; MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE];
    let copy_length = frame
        .len()
        .min(MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE);
    minimum[..copy_length].copy_from_slice(&frame[..copy_length]);
    minimum
}

/// Maximum `--padding` octets that still fit in IEEE 802.3 MAC client data with a 28-octet ARP PDU.
#[must_use]
pub(crate) fn maximum_arp_request_padding_octet_count(llc_snap: bool) -> usize {
    let reserved = if llc_snap {
        IEEE_8023_LLC_SNAP_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH
    } else {
        ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH
    };
    usize::from(IEEE_8023_MAXIMUM_LENGTH).saturating_sub(reserved)
}

/// Parsed IPv4-over-Ethernet ARP packet after Ethernet, optional 802.1Q, and SNAP decoding.
///
/// Opcode 2 is an RFC 826 reply. Other non-reserved opcodes (request, RARP, and so on) are still
/// well-formed ARP; RFC 5494 reserved values 0 and 65535 never appear here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParsedIpv4EthernetArp {
    /// RFC 826 `ar$op`.
    pub opcode: u16,
    /// RFC 826 `ar$spa`.
    pub sender_protocol: Ipv4Addr,
    /// RFC 826 `ar$sha`.
    pub sender_hardware: MacAddress,
    /// RFC 826 `ar$tha`.
    pub target_hardware: MacAddress,
    /// RFC 826 `ar$tpa`.
    pub target_protocol: Ipv4Addr,
}

/// Parses an IPv4 ARP packet from a raw Ethernet frame buffer.
///
/// Trailing padding beyond the ARP payload is ignored once the fixed ARP fields are validated.
/// One IEEE 802.1Q customer tag, an IEEE 802.1Q service tag wrapping one customer tag, and RFC
/// 1042 LLC/SNAP encapsulation are accepted. Sender and target hardware and protocol addresses
/// (`ar$sha`, `ar$spa`, `ar$tha`, `ar$tpa`) are the values returned, matching RFC 826. Any
/// non-reserved opcode is accepted, including requests.
///
/// # Errors
///
/// Returns a static message when the Ethernet header, `EtherType`, or ARP fields are invalid, when
/// `ar$hrd` or `ar$op` is reserved by RFC 5494, or when the buffer is too short.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn try_parse_address_resolution_ipv4_over_ethernet(
    frame: &[u8],
) -> Result<ParsedIpv4EthernetArp, &'static str> {
    let parsed = try_parse_ethernet_frame(frame)?;
    if parsed.ether_type != ETHERNET_PROTOCOL_ARP {
        return Err("EtherType is not address resolution protocol");
    }

    if parsed.payload.len() < ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH {
        return Err("address resolution payload is shorter than IPv4 over Ethernet");
    }

    let arp = parsed.payload;
    let hardware_type = u16::from_be_bytes([
        arp[ARP_HARDWARE_TYPE_OFFSET],
        arp[ARP_HARDWARE_TYPE_OFFSET + 1],
    ]);
    if hardware_type == ARP_RESERVED_FIELD_ZERO || hardware_type == ARP_RESERVED_FIELD_ALL_ONES {
        return Err("address resolution hardware type is reserved by RFC 5494");
    }
    if hardware_type != ARP_HARDWARE_TYPE_ETHERNET {
        return Err("address resolution hardware type is not Ethernet");
    }

    let protocol_type = u16::from_be_bytes([
        arp[ARP_PROTOCOL_TYPE_OFFSET],
        arp[ARP_PROTOCOL_TYPE_OFFSET + 1],
    ]);
    if protocol_type != ETHERNET_PROTOCOL_IPV4 {
        return Err("address resolution protocol type is not IPv4");
    }

    if arp[ARP_HARDWARE_LENGTH_OFFSET] != ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH
        || arp[ARP_PROTOCOL_LENGTH_OFFSET] != ARP_IPV4_PROTOCOL_ADDRESS_LENGTH
    {
        return Err("address resolution address lengths are not Ethernet plus IPv4");
    }

    let opcode = u16::from_be_bytes([arp[ARP_OPCODE_OFFSET], arp[ARP_OPCODE_OFFSET + 1]]);
    if opcode == ARP_RESERVED_FIELD_ZERO || opcode == ARP_RESERVED_FIELD_ALL_ONES {
        return Err("address resolution opcode is reserved by RFC 5494");
    }

    let mut sender_mac_octets = [0u8; 6];
    sender_mac_octets
        .copy_from_slice(&arp[ARP_SENDER_HARDWARE_OFFSET..ARP_SENDER_HARDWARE_OFFSET + 6]);
    let sender_ipv4 = Ipv4Addr::new(
        arp[ARP_SENDER_PROTOCOL_OFFSET],
        arp[ARP_SENDER_PROTOCOL_OFFSET + 1],
        arp[ARP_SENDER_PROTOCOL_OFFSET + 2],
        arp[ARP_SENDER_PROTOCOL_OFFSET + 3],
    );
    let mut target_mac_octets = [0u8; 6];
    target_mac_octets
        .copy_from_slice(&arp[ARP_TARGET_HARDWARE_OFFSET..ARP_TARGET_HARDWARE_OFFSET + 6]);
    let target_ipv4 = Ipv4Addr::new(
        arp[ARP_TARGET_PROTOCOL_OFFSET],
        arp[ARP_TARGET_PROTOCOL_OFFSET + 1],
        arp[ARP_TARGET_PROTOCOL_OFFSET + 2],
        arp[ARP_TARGET_PROTOCOL_OFFSET + 3],
    );

    Ok(ParsedIpv4EthernetArp {
        opcode,
        sender_protocol: sender_ipv4,
        sender_hardware: MacAddress::from_octets(sender_mac_octets),
        target_hardware: MacAddress::from_octets(target_mac_octets),
        target_protocol: target_ipv4,
    })
}

/// Parses an IPv4 ARP reply from a raw Ethernet frame buffer.
///
/// Trailing padding beyond the ARP payload is ignored once the fixed ARP fields are validated.
/// One IEEE 802.1Q customer tag, an IEEE 802.1Q service tag wrapping one customer tag, and RFC
/// 1042 LLC/SNAP encapsulation are accepted. Sender hardware and protocol addresses (`ar$sha`,
/// `ar$spa`) are the values returned, matching RFC 826.
///
/// Well-formed ARP that is not a reply (for example an RFC 826 request) is rejected here. The
/// scanner records opcode 2 only, so those frames are not treated as malformed capture noise.
///
/// ```
/// use new_arp_scan::{
///     MacAddress, build_address_resolution_request_ethernet_frame,
///     try_parse_address_resolution_reply_ipv4_over_ethernet,
/// };
/// use std::net::Ipv4Addr;
///
/// let frame = build_address_resolution_request_ethernet_frame(
///     MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
///     Ipv4Addr::new(192, 168, 1, 1),
///     Ipv4Addr::new(192, 168, 1, 2),
/// );
/// assert_eq!(
///     try_parse_address_resolution_reply_ipv4_over_ethernet(&frame),
///     Err("address resolution opcode is a request, not a reply")
/// );
/// ```
///
/// # Errors
///
/// Returns a static message when the Ethernet header, `EtherType`, or ARP fields are invalid, when
/// the opcode is not a reply, or when the buffer is too short.
///
/// # Panics
///
/// This function does not panic.
pub fn try_parse_address_resolution_reply_ipv4_over_ethernet(
    frame: &[u8],
) -> Result<(Ipv4Addr, MacAddress), &'static str> {
    let parsed = try_parse_address_resolution_ipv4_over_ethernet(frame)?;
    match parsed.opcode {
        ARP_OPERATION_REPLY => Ok((parsed.sender_protocol, parsed.sender_hardware)),
        ARP_OPERATION_REQUEST => Err("address resolution opcode is a request, not a reply"),
        _ => Err("address resolution opcode is not a recognized reply"),
    }
}

#[cfg(test)]
mod tests {
    use super::ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
    use super::ARP_OPERATION_REPLY;
    use super::ARP_OPERATION_REQUEST;
    use super::MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE;
    use super::MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH;
    use super::build_address_resolution_announcement_ethernet_frame;
    use super::build_address_resolution_probe_ethernet_frame;
    use super::build_address_resolution_request_ethernet_frame;
    use super::build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag;
    use super::build_address_resolution_request_ethernet_frame_with_wire_options;
    use super::try_parse_address_resolution_ipv4_over_ethernet;
    use super::try_parse_address_resolution_reply_ipv4_over_ethernet;
    use crate::ethernet_frame::ETHERNET_II_HEADER_LENGTH;
    use crate::ethernet_frame::ETHERNET_PROTOCOL_VLAN_TAG;
    use crate::ethernet_frame::IEEE_8021Q_TAG_LENGTH;
    use crate::ethernet_frame::IEEE_8023_LLC_SNAP_HEADER_LENGTH;
    use crate::ethernet_frame::Ieee8021qPriorityCodePoint;
    use crate::ethernet_frame::Ieee8021qTagControlInformation;
    use crate::ethernet_frame::Ieee8021qTagStack;
    use crate::ethernet_frame::Ieee8021qVlanIdentifier;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;

    #[test]
    fn built_request_has_expected_ethernet_and_address_resolution_fields() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        assert_eq!(&frame[0..6], &MacAddress::BROADCAST.octets());
        assert_eq!(
            &frame[6..12],
            &source_mac.octets(),
            "source MAC should match"
        );
        assert_eq!(&frame[12..14], &[0x08, 0x06], "EtherType should be ARP");
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(
            u16::from_be_bytes([arp[0], arp[1]]),
            1,
            "hardware type should be Ethernet"
        );
        assert_eq!(
            u16::from_be_bytes([arp[6], arp[7]]),
            1,
            "opcode should be request"
        );
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            "frame should meet minimum Ethernet size"
        );
    }

    #[test]
    fn built_request_with_ieee_8021q_tag_places_arp_after_tpid_and_tci() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let vlan_identifier = Ieee8021qVlanIdentifier::new(42).expect("VID 42 fits in 12 bits");

        // Act
        let frame = build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag(
            source_mac,
            source_ip,
            target_ip,
            Some(vlan_identifier),
        );

        // Assert
        assert_eq!(&frame[12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(&frame[14..16], &42u16.to_be_bytes());
        assert_eq!(
            &frame[16..18],
            &[0x08, 0x06],
            "inner EtherType should be ARP"
        );
        let arp_start = ETHERNET_II_HEADER_LENGTH + IEEE_8021Q_TAG_LENGTH;
        assert_eq!(
            u16::from_be_bytes([frame[arp_start], frame[arp_start + 1]]),
            1,
            "hardware type should be Ethernet"
        );
        assert_eq!(
            &frame[arp_start + 24..arp_start + 28],
            &target_ip.octets(),
            "target protocol address should follow the tagged header"
        );
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            "tagged request should still pad to the 60-octet minimum without FCS"
        );
        assert!(
            frame[arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH..]
                .iter()
                .all(|octet| *octet == 0),
            "octets after the ARP payload should be zero padding"
        );
    }

    #[test]
    fn built_request_with_llc_snap_uses_ieee_8023_length_and_rfc_1042_header() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let expected_length = u16::try_from(
            IEEE_8023_LLC_SNAP_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH,
        )
        .expect("SNAP plus ARP fits in an IEEE 802.3 length");

        // Act
        let frame = build_address_resolution_request_ethernet_frame_with_wire_options(
            source_mac, source_ip, target_ip, None, true,
        );

        // Assert
        assert_eq!(&frame[12..14], &expected_length.to_be_bytes());
        assert_eq!(&frame[14..17], &[0xAA, 0xAA, 0x03]);
        assert_eq!(&frame[17..20], &[0, 0, 0]);
        assert_eq!(&frame[20..22], &[0x08, 0x06]);
        let arp_start = ETHERNET_II_HEADER_LENGTH + IEEE_8023_LLC_SNAP_HEADER_LENGTH;
        assert_eq!(
            &frame[arp_start + 14..arp_start + 18],
            &source_ip.octets(),
            "ar$spa should follow the SNAP header"
        );
        assert_eq!(
            &frame[arp_start + 24..arp_start + 28],
            &target_ip.octets(),
            "ar$tpa should follow the SNAP header"
        );
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
        );
    }

    #[test]
    fn layout_encode_uses_ethernet_destination_source_and_arp_field_overrides() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let ethernet_destination = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ethernet_source = MacAddress::from_octets([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        let sender_hardware = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let target_hardware = MacAddress::from_octets([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let mut layout = super::AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            interface_mac,
            source_ip,
            target_ip,
        );
        layout.ethernet_destination = ethernet_destination;
        layout.ethernet_source = ethernet_source;
        layout.hardware_type = 6;
        layout.sender_hardware = sender_hardware;
        layout.target_hardware = target_hardware;

        // Act
        let frame = super::encode_address_resolution_request_from_layout(layout);

        // Assert
        assert_eq!(&frame[0..6], &ethernet_destination.octets());
        assert_eq!(&frame[6..12], &ethernet_source.octets());
        assert_ne!(
            &frame[6..12],
            &sender_hardware.octets(),
            "Ethernet source and ar$sha are independent RFC 826 fields"
        );
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(u16::from_be_bytes([arp[0], arp[1]]), 6);
        assert_eq!(&arp[8..14], &sender_hardware.octets());
        assert_eq!(&arp[18..24], &target_hardware.octets());
    }

    #[test]
    fn layout_encode_appends_custom_padding_then_zero_pads_to_minimum_frame() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let mut layout = super::AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            interface_mac,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 50),
        );
        let custom_padding = [0xDEu8, 0xAD, 0xBE, 0xEF];
        layout.padding = &custom_padding;

        // Act
        let frame = super::encode_address_resolution_request_from_layout(layout);

        // Assert
        let payload_start =
            ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        assert_eq!(&frame[payload_start..payload_start + 4], &custom_padding);
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            "short custom padding should still zero-pad the frame to 60 octets"
        );
        assert!(
            frame[payload_start + 4..].iter().all(|octet| *octet == 0),
            "octets after custom padding should be IEEE 802.3 minimum-frame zeroes"
        );
    }

    #[test]
    fn layout_encode_keeps_custom_padding_when_frame_exceeds_minimum() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let mut layout = super::AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            interface_mac,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 50),
        );
        let custom_padding = [0xAAu8; 20];
        layout.padding = &custom_padding;

        // Act
        let frame = super::encode_address_resolution_request_from_layout(layout);

        // Assert
        let payload_start =
            ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        assert_eq!(
            frame.len(),
            ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH + 20
        );
        assert_eq!(&frame[payload_start..], custom_padding.as_slice());
    }

    #[test]
    fn layout_encode_includes_custom_padding_in_rfc_1042_snap_length() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let mut layout = super::AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            interface_mac,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 50),
        );
        let custom_padding = [0x11u8, 0x22];
        layout.llc_snap = true;
        layout.padding = &custom_padding;
        let expected_length = u16::try_from(
            IEEE_8023_LLC_SNAP_HEADER_LENGTH
                + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH
                + custom_padding.len(),
        )
        .expect("SNAP plus ARP plus two padding octets fits in an IEEE 802.3 length");

        // Act
        let frame = super::encode_address_resolution_request_from_layout(layout);

        // Assert
        assert_eq!(&frame[12..14], &expected_length.to_be_bytes());
        let padding_start = ETHERNET_II_HEADER_LENGTH
            + IEEE_8023_LLC_SNAP_HEADER_LENGTH
            + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        assert_eq!(&frame[padding_start..padding_start + 2], &custom_padding);
        assert_eq!(
            expected_length, 38,
            "MAC client data is LLC/SNAP (8) plus ARP (28) plus custom padding (2)"
        );
    }

    #[test]
    fn layout_encode_writes_ieee_8021q_pcp_and_dei_in_tci() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let mut layout = super::AddressResolutionRequestLayout::rfc_826_ethernet_ii(
            interface_mac,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 50),
        );
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits");
        let priority = Ieee8021qPriorityCodePoint::new(5).expect("PCP 5 fits");
        layout.vlan_tag = Some(Ieee8021qTagStack::Customer(
            Ieee8021qTagControlInformation::new(priority, true, vlan_identifier),
        ));

        // Act
        let frame = super::encode_address_resolution_request_from_layout(layout);

        // Assert
        assert_eq!(&frame[12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(
            &frame[14..16],
            &0xB00Au16.to_be_bytes(),
            "PCP 5, DEI 1, VID 10 encode as TCI 0xB00A"
        );
        assert_eq!(&frame[16..18], &[0x08, 0x06]);
    }

    #[test]
    fn built_request_zero_pads_to_ieee_8023_minimum_without_frame_check_sequence() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 2);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        let header_and_arp =
            ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        assert_eq!(
            header_and_arp + 18,
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
            "28-byte ARP plus 18 pad octets is the 46-octet IEEE 802.3 minimum client data"
        );
        assert!(
            frame[header_and_arp..].iter().all(|octet| *octet == 0),
            "IEEE 802.3 padding must be zeroes"
        );
        assert_eq!(
            frame.len() - ETHERNET_II_HEADER_LENGTH,
            MINIMUM_ETHERNET_MAC_CLIENT_DATA_LENGTH
        );
    }

    #[test]
    fn parses_valid_reply_with_trailing_padding() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12] = 0x08;
        frame[13] = 0x06;
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        let (ip, mac) = outcome.expect("valid reply should parse");
        assert_eq!(ip, source_ip, "sender IPv4 should match");
        assert_eq!(mac, source_mac, "sender MAC should match");
    }

    #[test]
    fn rejects_frame_that_is_too_short() {
        // Arrange
        let frame = [0u8; 20];

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert!(outcome.is_err(), "short frame should be rejected");
    }

    #[test]
    fn rejects_non_reply_opcode() {
        // Arrange
        let frame = build_address_resolution_request_ethernet_frame(
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 2),
        );

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("request opcode should not parse as reply"),
            "address resolution opcode is a request, not a reply"
        );
    }

    #[test]
    fn parses_rfc_826_request_as_ipv4_over_ethernet_arp() {
        // Arrange
        let source_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let source_ip = Ipv4Addr::new(192, 168, 0, 1);
        let frame = build_address_resolution_request_ethernet_frame(
            source_mac,
            source_ip,
            Ipv4Addr::new(192, 168, 0, 2),
        );

        // Act
        let parsed = try_parse_address_resolution_ipv4_over_ethernet(&frame)
            .expect("RFC 826 request should parse as well-formed ARP");

        // Assert
        assert_eq!(parsed.opcode, ARP_OPERATION_REQUEST);
        assert_eq!(parsed.sender_protocol, source_ip);
        assert_eq!(parsed.sender_hardware, source_mac);
        assert_eq!(parsed.target_hardware, MacAddress::from_octets([0; 6]));
        assert_eq!(parsed.target_protocol, Ipv4Addr::new(192, 168, 0, 2));
    }

    #[test]
    fn parses_non_reserved_non_reply_opcode_as_ipv4_over_ethernet_arp() {
        // Arrange
        let source_mac = MacAddress::from_octets([9; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 2);
        let mut frame = reply_fixture(source_mac, source_ip);
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&3u16.to_be_bytes());

        // Act
        let parsed = try_parse_address_resolution_ipv4_over_ethernet(&frame)
            .expect("RARP request opcode should parse as well-formed ARP");

        // Assert
        assert_eq!(parsed.opcode, 3);
        assert_eq!(parsed.sender_protocol, source_ip);
        assert_eq!(parsed.sender_hardware, source_mac);
        assert_eq!(
            try_parse_address_resolution_reply_ipv4_over_ethernet(&frame)
                .expect_err("RARP must not parse as an ARP reply"),
            "address resolution opcode is not a recognized reply"
        );
    }

    fn reply_fixture(source_mac: MacAddress, source_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12] = 0x08;
        frame[13] = 0x06;
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);
        frame
    }

    #[test]
    fn built_request_places_target_ipv4_and_zero_target_hardware_in_payload() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 2);
        let target_ip = Ipv4Addr::new(10, 0, 0, 99);

        // Act
        let frame =
            build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

        // Assert
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(&arp[14..18], &source_ip.octets());
        assert_eq!(
            &arp[18..24],
            &[0u8; 6],
            "target hardware should be zero in requests"
        );
        assert_eq!(&arp[24..28], &target_ip.octets());
    }

    #[test]
    fn rfc_5227_probe_uses_unspecified_sender_ipv4_and_zero_target_hardware() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame = build_address_resolution_probe_ethernet_frame(source_mac, target_ip);

        // Assert
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), 1, "opcode is request");
        assert_eq!(&arp[8..14], &source_mac.octets());
        assert_eq!(
            &arp[14..18],
            &[0, 0, 0, 0],
            "RFC 5227 Probe SPA is all zeros"
        );
        assert_eq!(&arp[18..24], &[0u8; 6], "RFC 5227 Probe THA SHOULD be zero");
        assert_eq!(&arp[24..28], &target_ip.octets());
        assert_eq!(
            frame.len(),
            MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
        );
    }

    #[test]
    fn rfc_5227_announcement_sets_sender_and_target_ipv4_to_the_claimed_address() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let claimed = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let frame = build_address_resolution_announcement_ethernet_frame(source_mac, claimed);

        // Assert
        let arp = &frame[ETHERNET_II_HEADER_LENGTH..];
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), 1, "opcode is request");
        assert_eq!(&arp[14..18], &claimed.octets());
        assert_eq!(&arp[24..28], &claimed.octets());
        assert_eq!(&arp[18..24], &[0u8; 6]);
    }

    #[test]
    fn rejects_reply_when_ether_type_is_not_arp() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        frame[12] = 0x08;
        frame[13] = 0x00;

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("wrong EtherType should fail"),
            "EtherType is not address resolution protocol"
        );
    }

    #[test]
    fn rejects_reply_when_arp_hardware_type_is_not_ethernet() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start..arp_start + 2].copy_from_slice(&2u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("non-Ethernet hardware type should fail"),
            "address resolution hardware type is not Ethernet"
        );
    }

    #[test]
    fn rejects_rfc_5494_reserved_hardware_type_zero() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start..arp_start + 2].copy_from_slice(&0u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved hardware type 0 should fail"),
            "address resolution hardware type is reserved by RFC 5494"
        );
    }

    #[test]
    fn rejects_rfc_5494_reserved_hardware_type_all_ones() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start..arp_start + 2].copy_from_slice(&65535u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved hardware type 65535 should fail"),
            "address resolution hardware type is reserved by RFC 5494"
        );
    }

    #[test]
    fn rejects_rfc_5494_reserved_opcode_zero() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&0u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved opcode 0 should fail"),
            "address resolution opcode is reserved by RFC 5494"
        );
    }

    #[test]
    fn rejects_reply_when_arp_protocol_type_is_not_ipv4() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 2..arp_start + 4].copy_from_slice(&0x86ddu16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("non-IPv4 protocol type should fail"),
            "address resolution protocol type is not IPv4"
        );
    }

    #[test]
    fn rejects_reply_when_arp_address_lengths_are_not_ethernet_ipv4() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 4] = 5;

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("wrong hardware length should fail"),
            "address resolution address lengths are not Ethernet plus IPv4"
        );
    }

    #[test]
    fn rejects_unknown_arp_opcode() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&99u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("unknown opcode should fail"),
            "address resolution opcode is not a recognized reply"
        );
    }

    #[test]
    fn parses_ieee_8021q_tagged_arp_reply() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        frame[14..16].copy_from_slice(&0x0064u16.to_be_bytes());
        frame[16] = 0x08;
        frame[17] = 0x06;
        let arp_start = 18;
        let arp_end = arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
        let arp = &mut frame[arp_start..arp_end];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        let (ip, mac) = outcome.expect("802.1Q tagged ARP reply should parse");
        assert_eq!(ip, source_ip);
        assert_eq!(mac, source_mac);
    }

    #[test]
    fn uses_arp_sender_hardware_when_ethernet_source_differs() {
        // Arrange
        let ethernet_source = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let arp_sender = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = reply_fixture(arp_sender, source_ip);
        frame[6..12].copy_from_slice(&ethernet_source.octets());

        // Act
        let (ip, mac) = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame)
            .expect("reply should parse using ar$sha");

        // Assert
        assert_eq!(ip, source_ip);
        assert_eq!(
            mac, arp_sender,
            "RFC 826 sender hardware address is ar$sha, not the Ethernet source"
        );
        assert_ne!(mac, ethernet_source);
    }

    #[test]
    fn parses_rfc_1042_llc_snap_arp_reply() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let mut frame = vec![0u8; 128];
        frame[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[6..12].copy_from_slice(&source_mac.octets());
        frame[12..14].copy_from_slice(&46u16.to_be_bytes());
        frame[14] = 0xAA;
        frame[15] = 0xAA;
        frame[16] = 0x03;
        frame[17..20].copy_from_slice(&[0, 0, 0]);
        frame[20] = 0x08;
        frame[21] = 0x06;
        let arp_start = 22;
        let arp =
            &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes());
        arp[8..14].copy_from_slice(&source_mac.octets());
        arp[14..18].copy_from_slice(&source_ip.octets());
        arp[18..24].fill(0);
        arp[24..28].copy_from_slice(&[10, 0, 0, 1]);

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        let (ip, mac) = outcome.expect("RFC 1042 SNAP ARP reply should parse");
        assert_eq!(ip, source_ip);
        assert_eq!(mac, source_mac);
    }

    #[test]
    fn parses_valid_reply_through_general_ipv4_over_ethernet_parser() {
        // Arrange
        let source_mac = MacAddress::from_octets([0xAA; 6]);
        let source_ip = Ipv4Addr::new(10, 0, 0, 5);
        let frame = reply_fixture(source_mac, source_ip);

        // Act
        let parsed = try_parse_address_resolution_ipv4_over_ethernet(&frame)
            .expect("well-formed reply should parse");

        // Assert
        assert_eq!(parsed.opcode, ARP_OPERATION_REPLY);
        assert_eq!(parsed.sender_protocol, source_ip);
        assert_eq!(parsed.sender_hardware, source_mac);
        assert_eq!(parsed.target_hardware, MacAddress::from_octets([0; 6]));
        assert_eq!(parsed.target_protocol, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            try_parse_address_resolution_reply_ipv4_over_ethernet(&frame),
            Ok((source_ip, source_mac)),
            "the public reply parser still returns only the sender tuple"
        );
    }

    #[test]
    fn parses_nonzero_target_hardware_and_broadcast_target_protocol() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02; 6]);
        let target_mac = MacAddress::BROADCAST;
        let source_ip = Ipv4Addr::UNSPECIFIED;
        let target_ip = Ipv4Addr::BROADCAST;
        let mut frame = reply_fixture(source_mac, source_ip);
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 18..arp_start + 24].copy_from_slice(&target_mac.octets());
        frame[arp_start + 24..arp_start + 28].copy_from_slice(&target_ip.octets());

        // Act
        let parsed = try_parse_address_resolution_ipv4_over_ethernet(&frame)
            .expect("boundary target addresses should still parse");

        // Assert
        assert_eq!(parsed.sender_protocol, Ipv4Addr::UNSPECIFIED);
        assert_eq!(parsed.target_hardware, target_mac);
        assert_eq!(parsed.target_protocol, Ipv4Addr::BROADCAST);
        assert_eq!(
            try_parse_address_resolution_reply_ipv4_over_ethernet(&frame),
            Ok((source_ip, source_mac)),
            "reply parsing must ignore target fields"
        );
    }

    #[test]
    fn rejects_truncated_arp_payload_after_ethernet_header() {
        // Arrange
        let frame = crate::ethernet_frame::encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            crate::ethernet_frame::ETHERNET_PROTOCOL_ARP,
            &[0u8; 10],
        );

        // Act
        let outcome = try_parse_address_resolution_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("short ARP payload should fail"),
            "address resolution payload is shorter than IPv4 over Ethernet"
        );
    }

    #[test]
    fn rejects_reply_when_arp_protocol_length_is_not_ipv4() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 5] = 3;

        // Act
        let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("wrong protocol length should fail"),
            "address resolution address lengths are not Ethernet plus IPv4"
        );
    }

    #[test]
    fn general_parser_rejects_rfc_5494_reserved_opcode_all_ones() {
        // Arrange
        let mut frame = reply_fixture(MacAddress::from_octets([9; 6]), Ipv4Addr::new(10, 0, 0, 2));
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&65535u16.to_be_bytes());

        // Act
        let outcome = try_parse_address_resolution_ipv4_over_ethernet(&frame);

        // Assert
        assert_eq!(
            outcome.expect_err("reserved opcode 65535 should fail the general parser"),
            "address resolution opcode is reserved by RFC 5494"
        );
    }

    #[test]
    fn parses_rfc_1042_llc_snap_request_as_ipv4_over_ethernet_arp() {
        // Arrange
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let frame = build_address_resolution_request_ethernet_frame_with_wire_options(
            source_mac,
            source_ip,
            Ipv4Addr::new(192, 168, 1, 2),
            None,
            true,
        );

        // Act
        let parsed = try_parse_address_resolution_ipv4_over_ethernet(&frame)
            .expect("SNAP request should parse as well-formed ARP");

        // Assert
        assert_eq!(parsed.opcode, ARP_OPERATION_REQUEST);
        assert_eq!(parsed.sender_protocol, source_ip);
        assert_eq!(parsed.sender_hardware, source_mac);
        assert_eq!(
            try_parse_address_resolution_reply_ipv4_over_ethernet(&frame)
                .expect_err("SNAP request must not parse as a reply"),
            "address resolution opcode is a request, not a reply"
        );
    }
}
