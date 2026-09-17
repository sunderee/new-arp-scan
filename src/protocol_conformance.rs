//! Spec-facing tests that lock RFC 826, RFC 5227, RFC 5494, IEEE 802.3, IEEE 802.1Q, and
//! IEEE MA-L / MA-M / MA-S behaviour to named requirements.

use crate::address_resolution_protocol::{
    ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH, ARP_OPERATION_REQUEST,
    MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE,
    build_address_resolution_announcement_ethernet_frame,
    build_address_resolution_probe_ethernet_frame, build_address_resolution_request_ethernet_frame,
    build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag,
    build_address_resolution_request_ethernet_frame_with_wire_options,
    encode_address_resolution_request_from_layout, try_parse_address_resolution_ipv4_over_ethernet,
    try_parse_address_resolution_reply_ipv4_over_ethernet,
};
use crate::application_command::{ArpSenderProtocolAddress, ScanWireOptions};
use crate::ethernet_frame::{
    ETHERNET_II_HEADER_LENGTH, ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_VLAN_TAG,
    ETHERNET_PROTOCOL_VLAN_TAG_SERVICE, EthernetFraming, IEEE_8023_LLC_SNAP_HEADER_LENGTH,
    IEEE_8023_MAXIMUM_LENGTH, Ieee8021qPriorityCodePoint, Ieee8021qTagControlInformation,
    Ieee8021qTagStack, Ieee8021qVlanIdentifier, MINIMUM_ETHERNET_II_ETHERTYPE,
    encode_ethernet_ii_frame, encode_ethernet_ii_frame_with_optional_ieee_8021q_tag,
    try_parse_ethernet_frame,
};
use crate::mac_address::MacAddress;
use crate::mac_vendor_registry::MacVendorRegistry;
use std::net::Ipv4Addr;

fn rfc_826_arp_field(frame: &[u8], offset: usize, length: usize) -> &[u8] {
    let start = ETHERNET_II_HEADER_LENGTH + offset;
    &frame[start..start + length]
}

#[test]
fn rfc_826_request_uses_ethernet_hardware_ipv4_protocol_request_opcode_and_zero_target_hardware() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let source_ip = Ipv4Addr::new(192, 168, 1, 1);
    let target_ip = Ipv4Addr::new(192, 168, 1, 2);

    // Act
    let frame = build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

    // Assert
    assert_eq!(rfc_826_arp_field(&frame, 0, 2), 1u16.to_be_bytes());
    assert_eq!(rfc_826_arp_field(&frame, 2, 2), 0x0800u16.to_be_bytes());
    assert_eq!(rfc_826_arp_field(&frame, 4, 1), [6]);
    assert_eq!(rfc_826_arp_field(&frame, 5, 1), [4]);
    assert_eq!(rfc_826_arp_field(&frame, 6, 2), 1u16.to_be_bytes());
    assert_eq!(rfc_826_arp_field(&frame, 8, 6), source_mac.octets());
    assert_eq!(rfc_826_arp_field(&frame, 14, 4), source_ip.octets());
    assert_eq!(rfc_826_arp_field(&frame, 18, 6), [0u8; 6]);
    assert_eq!(rfc_826_arp_field(&frame, 24, 4), target_ip.octets());
}

#[test]
fn rfc_826_request_is_well_formed_arp_and_is_not_a_packet_parse_failure() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let source_ip = Ipv4Addr::new(192, 168, 1, 1);
    let target_ip = Ipv4Addr::new(192, 168, 1, 2);
    let frame = build_address_resolution_request_ethernet_frame(source_mac, source_ip, target_ip);

    // Act
    let parsed = try_parse_address_resolution_ipv4_over_ethernet(&frame)
        .expect("RFC 826 request should parse as well-formed ARP");
    let reply_outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

    // Assert
    assert_eq!(parsed.opcode, ARP_OPERATION_REQUEST);
    assert_eq!(parsed.sender_protocol, source_ip);
    assert_eq!(parsed.sender_hardware, source_mac);
    assert_eq!(
        reply_outcome.expect_err("request must not parse as a reply"),
        "address resolution opcode is a request, not a reply"
    );
}

#[test]
fn rfc_5227_probe_sender_protocol_address_is_all_zeros() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let target_ip = Ipv4Addr::new(10, 0, 0, 5);

    // Act
    let frame = build_address_resolution_probe_ethernet_frame(source_mac, target_ip);

    // Assert
    assert_eq!(rfc_826_arp_field(&frame, 14, 4), [0, 0, 0, 0]);
    assert_eq!(rfc_826_arp_field(&frame, 24, 4), target_ip.octets());
    assert_eq!(rfc_826_arp_field(&frame, 6, 2), 1u16.to_be_bytes());
}

#[test]
fn rfc_5227_announcement_sender_and_target_protocol_addresses_are_equal() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let claimed = Ipv4Addr::new(10, 0, 0, 5);

    // Act
    let frame = build_address_resolution_announcement_ethernet_frame(source_mac, claimed);

    // Assert
    assert_eq!(rfc_826_arp_field(&frame, 14, 4), claimed.octets());
    assert_eq!(rfc_826_arp_field(&frame, 24, 4), claimed.octets());
    assert_eq!(rfc_826_arp_field(&frame, 6, 2), 1u16.to_be_bytes());
}

#[test]
fn rfc_5494_reserved_opcode_65535_is_rejected() {
    // Arrange
    let mut frame = build_address_resolution_request_ethernet_frame(
        MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
    );
    let opcode_offset = ETHERNET_II_HEADER_LENGTH + 6;
    frame[opcode_offset..opcode_offset + 2].copy_from_slice(&65535u16.to_be_bytes());

    // Act
    let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

    // Assert
    assert_eq!(
        outcome.expect_err("reserved opcode 65535 should fail"),
        "address resolution opcode is reserved by RFC 5494"
    );
}

#[test]
fn ieee_8023_minimum_frame_without_fcs_is_sixty_octets_with_eighteen_zero_pad() {
    // Arrange
    let frame = build_address_resolution_request_ethernet_frame(
        MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 1, 2),
    );

    // Act
    let pad_start = ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;

    // Assert
    assert_eq!(
        frame.len(),
        MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
    );
    assert_eq!(frame.len() - pad_start, 18);
    assert!(frame[pad_start..].iter().all(|octet| *octet == 0));
}

#[test]
fn ieee_8023_length_versus_ethertype_boundary_is_1536() {
    // Arrange
    assert_eq!(MINIMUM_ETHERNET_II_ETHERTYPE, 1536);
    assert_eq!(IEEE_8023_MAXIMUM_LENGTH, 1500);
    let destination = MacAddress::BROADCAST;
    let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
    let arp_type = encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_ARP, &[]);
    let min_ethertype =
        encode_ethernet_ii_frame(destination, source, MINIMUM_ETHERNET_II_ETHERTYPE, &[]);

    // Act
    let arp_parsed = try_parse_ethernet_frame(&arp_type).expect("ARP EtherType should parse");
    let min_parsed = try_parse_ethernet_frame(&min_ethertype)
        .expect("EtherType 1536 should parse as Ethernet II");

    // Assert
    assert_eq!(arp_parsed.framing, EthernetFraming::EthernetIi);
    assert_eq!(min_parsed.framing, EthernetFraming::EthernetIi);
    assert_eq!(min_parsed.ether_type, 1536);
}

#[test]
fn ieee_8021q_vid_is_the_low_twelve_tci_bits() {
    // Arrange
    let destination = MacAddress::BROADCAST;
    let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
    let tci: u16 = 0xE044;
    let mut payload = Vec::from(tci.to_be_bytes());
    payload.extend_from_slice(&ETHERNET_PROTOCOL_ARP.to_be_bytes());
    payload.push(0x99);
    let frame = encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_VLAN_TAG, &payload);

    // Act
    let parsed = try_parse_ethernet_frame(&frame).expect("802.1Q frame should parse");

    // Assert
    assert_eq!(parsed.vlan_identifier, Some(0x044));
    assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
    assert_eq!(parsed.payload, &[0x99]);
    let vlan_tag = parsed
        .vlan_tag
        .expect("802.1Q frame should expose Tag Control Information");
    assert_eq!(vlan_tag.priority_code_point.as_u8(), 7);
    assert!(!vlan_tag.drop_eligible_indicator);
    assert_eq!(vlan_tag.as_u16(), 0xE044);
}

#[test]
fn ieee_8021q_receive_decodes_pcp_dei_and_vid_from_tci() {
    // Arrange
    let destination = MacAddress::BROADCAST;
    let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
    let tci: u16 = 0xF044;
    let mut payload = Vec::from(tci.to_be_bytes());
    payload.extend_from_slice(&ETHERNET_PROTOCOL_ARP.to_be_bytes());
    let frame = encode_ethernet_ii_frame(destination, source, ETHERNET_PROTOCOL_VLAN_TAG, &payload);

    // Act
    let parsed = try_parse_ethernet_frame(&frame).expect("802.1Q frame should parse");

    // Assert
    let vlan_tag = parsed
        .vlan_tag
        .expect("802.1Q frame should expose Tag Control Information");
    assert_eq!(vlan_tag.priority_code_point.as_u8(), 7);
    assert!(vlan_tag.drop_eligible_indicator);
    assert_eq!(vlan_tag.vlan_identifier.as_u16(), 0x044);
    assert_eq!(parsed.vlan_identifier, Some(0x044));
    assert_eq!(vlan_tag.as_u16(), 0xF044);
}

#[test]
fn ieee_8021q_tagged_request_round_trips_through_parser() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let source_ip = Ipv4Addr::new(192, 168, 1, 1);
    let target_ip = Ipv4Addr::new(192, 168, 1, 2);
    let vlan_identifier = Ieee8021qVlanIdentifier::new(100).expect("VID 100 fits in 12 bits");

    // Act
    let frame = build_address_resolution_request_ethernet_frame_with_optional_ieee_8021q_tag(
        source_mac,
        source_ip,
        target_ip,
        Some(vlan_identifier),
    );
    let parsed = try_parse_ethernet_frame(&frame).expect("tagged request should parse");

    // Assert
    assert_eq!(parsed.vlan_identifier, Some(100));
    assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
    assert_eq!(parsed.framing, EthernetFraming::EthernetIi);
    assert_eq!(
        &parsed.payload[24..28],
        &target_ip.octets(),
        "RFC 826 target protocol address should follow the 802.1Q header"
    );
    assert_eq!(
        frame.len(),
        MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
    );
}

#[test]
fn ieee_ma_l_ma_m_ma_s_longest_prefix_match_follows_registry_bit_lengths() {
    // Arrange
    let text = include_str!("../tests/fixtures/ieee-mac-registry.txt");
    let registry = MacVendorRegistry::parse_ieee_oui_text(text).expect("fixture file should parse");
    let twenty_four_bit = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0xAA, 0x11, 0x22]);
    let twenty_eight_bit = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x0A, 0x11, 0x22]);
    let thirty_six_bit = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x00, 0x01, 0x22]);
    let other_assignment = MacAddress::from_octets([0x00, 0x1A, 0x2B, 0x00, 0x00, 0x01]);
    let iab_assignment = MacAddress::from_octets([0x40, 0xD8, 0x55, 0x0D, 0x70, 0x01]);

    // Act
    // Assert
    assert_eq!(
        registry.vendor_name_for(thirty_six_bit),
        Some("Fixture MA-S")
    );
    assert_eq!(
        registry.vendor_name_for(twenty_eight_bit),
        Some("Fixture MA-M")
    );
    assert_eq!(
        registry.vendor_name_for(twenty_four_bit),
        Some("Fixture MA-L")
    );
    assert_eq!(
        registry.vendor_name_for(other_assignment),
        Some("Fixture other MA-L")
    );
    assert_eq!(
        registry.vendor_name_for(iab_assignment),
        Some("Fixture IAB")
    );
}

#[test]
fn rfc_1042_llc_snap_request_uses_ieee_8023_length_of_llc_snap_plus_arp() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let source_ip = Ipv4Addr::new(192, 168, 1, 1);
    let target_ip = Ipv4Addr::new(192, 168, 1, 2);
    let expected_length = u16::try_from(
        IEEE_8023_LLC_SNAP_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH,
    )
    .expect("SNAP plus 28-octet ARP fits in an IEEE 802.3 length field");

    // Act
    let frame = build_address_resolution_request_ethernet_frame_with_wire_options(
        source_mac, source_ip, target_ip, None, true,
    );
    let parsed = try_parse_ethernet_frame(&frame).expect("SNAP request should parse");

    // Assert
    assert_eq!(&frame[12..14], &expected_length.to_be_bytes());
    assert_eq!(
        expected_length, 36,
        "MAC client data is LLC/SNAP (8) plus ARP (28), not an Ethernet-header-inclusive formula"
    );
    assert_eq!(&frame[14..17], &[0xAA, 0xAA, 0x03]);
    assert_eq!(&frame[17..20], &[0, 0, 0]);
    assert_eq!(&frame[20..22], &ETHERNET_PROTOCOL_ARP.to_be_bytes());
    assert_eq!(parsed.framing, EthernetFraming::Ieee8023LlcSnap);
    assert_eq!(parsed.ether_type, ETHERNET_PROTOCOL_ARP);
    assert_eq!(
        frame.len(),
        MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
    );
}

#[test]
fn rfc_5227_probe_via_unspecified_sender_protocol_address_matches_probe_builder() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let interface_ip = Ipv4Addr::new(192, 168, 1, 1);
    let target_ip = Ipv4Addr::new(192, 168, 1, 50);
    let spa = ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED)
        .ipv4_address_for_target(interface_ip, target_ip);

    // Act
    let from_wire = build_address_resolution_request_ethernet_frame_with_wire_options(
        source_mac, spa, target_ip, None, false,
    );
    let from_builder = build_address_resolution_probe_ethernet_frame(source_mac, target_ip);

    // Assert
    assert_eq!(spa, Ipv4Addr::UNSPECIFIED);
    assert_eq!(from_wire, from_builder);
    assert_eq!(&from_wire[28..32], &[0, 0, 0, 0]);
}

#[test]
fn rfc_5227_announcement_via_destination_sender_protocol_address_matches_announcement_builder() {
    // Arrange
    let source_mac = MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let interface_ip = Ipv4Addr::new(192, 168, 1, 1);
    let claimed = Ipv4Addr::new(192, 168, 1, 50);
    let spa =
        ArpSenderProtocolAddress::DestinationTarget.ipv4_address_for_target(interface_ip, claimed);

    // Act
    let from_wire = build_address_resolution_request_ethernet_frame_with_wire_options(
        source_mac, spa, claimed, None, false,
    );
    let from_builder = build_address_resolution_announcement_ethernet_frame(source_mac, claimed);

    // Assert
    assert_eq!(spa, claimed);
    assert_eq!(from_wire, from_builder);
    assert_eq!(&from_wire[28..32], &claimed.octets());
    assert_eq!(&from_wire[38..42], &claimed.octets());
}

#[test]
fn rfc_826_ethernet_source_and_sender_hardware_are_independent_and_destaddr_can_be_unicast() {
    // Arrange
    let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
    let destination = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ethernet_source = MacAddress::from_octets([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    let sender_hardware = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let spa = Ipv4Addr::new(192, 168, 1, 1);
    let tpa = Ipv4Addr::new(192, 168, 1, 50);
    let wire = ScanWireOptions {
        ethernet_destination: Some(destination),
        ethernet_source: Some(ethernet_source),
        arp_sender_hardware: Some(sender_hardware),
        arp_hardware_type: 6,
        ..ScanWireOptions::default()
    };

    // Act
    let frame = encode_address_resolution_request_from_layout(
        wire.address_resolution_request_layout(interface_mac, spa, tpa),
    );

    // Assert
    assert_eq!(&frame[0..6], &destination.octets());
    assert_eq!(&frame[6..12], &ethernet_source.octets());
    assert_eq!(&frame[22..28], &sender_hardware.octets());
    assert_eq!(rfc_826_arp_field(&frame, 0, 2), 6u16.to_be_bytes());
    assert_ne!(ethernet_source, sender_hardware);
}

#[test]
fn ieee_8021q_transmit_encodes_pcp_and_dei_in_tci() {
    // Arrange
    let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
    let spa = Ipv4Addr::new(192, 168, 1, 1);
    let tpa = Ipv4Addr::new(192, 168, 1, 50);
    let wire = ScanWireOptions {
        vlan_identifier: Ieee8021qVlanIdentifier::new(0x044),
        vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(7).expect("PCP 7 fits"),
        vlan_drop_eligible_indicator: true,
        ..ScanWireOptions::default()
    };

    // Act
    let frame = encode_address_resolution_request_from_layout(
        wire.address_resolution_request_layout(interface_mac, spa, tpa),
    );
    let parsed = try_parse_ethernet_frame(&frame).expect("tagged request should parse");

    // Assert
    assert_eq!(&frame[14..16], &0xF044u16.to_be_bytes());
    assert_eq!(parsed.vlan_identifier, Some(0x044));
    let vlan_tag = parsed
        .vlan_tag
        .expect("tagged request should expose Tag Control Information");
    assert_eq!(
        vlan_tag,
        Ieee8021qTagControlInformation::new(
            Ieee8021qPriorityCodePoint::new(7).expect("PCP 7 fits"),
            true,
            Ieee8021qVlanIdentifier::new(0x044).expect("VID fits in 12 bits"),
        )
    );
    assert_eq!(vlan_tag.as_u16(), 0xF044);
}

#[test]
fn ieee_8023_custom_padding_is_included_in_snap_length_and_still_meets_minimum_frame() {
    // Arrange
    let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
    let spa = Ipv4Addr::new(192, 168, 1, 1);
    let tpa = Ipv4Addr::new(192, 168, 1, 50);
    let padding = vec![0xAAu8, 0xBB];
    let wire = ScanWireOptions {
        llc_snap: true,
        padding: padding.clone(),
        ..ScanWireOptions::default()
    };
    let expected_length = u16::try_from(
        IEEE_8023_LLC_SNAP_HEADER_LENGTH
            + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH
            + padding.len(),
    )
    .expect("SNAP plus ARP plus two padding octets fits");

    // Act
    let frame = encode_address_resolution_request_from_layout(
        wire.address_resolution_request_layout(interface_mac, spa, tpa),
    );

    // Assert
    assert_eq!(&frame[12..14], &expected_length.to_be_bytes());
    assert_eq!(expected_length, 38);
    assert_eq!(
        frame.len(),
        MINIMUM_ETHERNET_FRAME_LENGTH_WITHOUT_FRAME_CHECK_SEQUENCE
    );
    let padding_start = ETHERNET_II_HEADER_LENGTH
        + IEEE_8023_LLC_SNAP_HEADER_LENGTH
        + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH;
    assert_eq!(&frame[padding_start..padding_start + 2], padding.as_slice());
}

#[test]
fn ieee_8021ad_service_tag_wrapping_a_customer_tag_is_accepted_and_lone_or_unofficial_tags_are_not()
{
    // Arrange: the legal S-TAG/C-TAG pair (IANA EtherType 34984 outside 33024), a lone S-TAG, and
    // the unofficial vendor TPID 0x9100 that `linux/if_ether.h` marks "NOT AN OFFICIALLY
    // REGISTERED ID".
    let destination = MacAddress::BROADCAST;
    let source = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
    let inner = [0x00, 0x01, 0x08, 0x06];
    let service_and_customer = encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
        destination,
        source,
        Some(Ieee8021qTagStack::ServiceAndCustomer {
            service: Ieee8021qTagControlInformation::from_vlan_identifier(
                Ieee8021qVlanIdentifier::new(100).expect("S-VID 100 fits in 12 bits"),
            ),
            customer: Ieee8021qTagControlInformation::from_vlan_identifier(
                Ieee8021qVlanIdentifier::new(10).expect("C-VID 10 fits in 12 bits"),
            ),
        }),
        ETHERNET_PROTOCOL_ARP,
        &[0x99],
    );
    let lone_service = encode_ethernet_ii_frame(
        destination,
        source,
        ETHERNET_PROTOCOL_VLAN_TAG_SERVICE,
        &inner,
    );
    let unofficial = encode_ethernet_ii_frame(destination, source, 0x9100, &inner);

    // Act
    let accepted = try_parse_ethernet_frame(&service_and_customer);
    let lone_service_outcome = try_parse_ethernet_frame(&lone_service);
    let unofficial_outcome = try_parse_ethernet_frame(&unofficial);

    // Assert
    let accepted = accepted.expect("an S-TAG wrapping one C-TAG is IEEE 802.1ad and must parse");
    assert_eq!(
        accepted
            .service_vlan_tag
            .expect("service tag should be decoded")
            .vlan_identifier
            .as_u16(),
        100
    );
    assert_eq!(accepted.vlan_identifier, Some(10));
    assert_eq!(accepted.ether_type, ETHERNET_PROTOCOL_ARP);
    assert_eq!(
        lone_service_outcome.expect_err("a lone S-TAG must be rejected"),
        "IEEE 802.1Q service tag is not followed by an IEEE 802.1Q customer tag"
    );
    assert_eq!(
        unofficial_outcome.expect_err("unofficial QinQ TPID 0x9100 must be rejected"),
        "Ethernet frame uses an unofficial QinQ TPID; only IEEE 802.1Q 0x8100 and 0x88A8 tagging is supported here"
    );
}

#[test]
fn rfc_5494_reserved_hardware_type_zero_is_rejected() {
    // Arrange
    let mut frame = build_address_resolution_request_ethernet_frame(
        MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
    );
    frame[ETHERNET_II_HEADER_LENGTH..ETHERNET_II_HEADER_LENGTH + 2]
        .copy_from_slice(&0u16.to_be_bytes());

    // Act
    let outcome = try_parse_address_resolution_ipv4_over_ethernet(&frame);

    // Assert
    assert_eq!(
        outcome.expect_err("reserved hardware type 0 should fail"),
        "address resolution hardware type is reserved by RFC 5494"
    );
}

#[test]
fn rfc_5494_reserved_opcode_zero_is_rejected() {
    // Arrange
    let mut frame = build_address_resolution_request_ethernet_frame(
        MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
    );
    let opcode_offset = ETHERNET_II_HEADER_LENGTH + 6;
    frame[opcode_offset..opcode_offset + 2].copy_from_slice(&0u16.to_be_bytes());

    // Act
    let outcome = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame);

    // Assert
    assert_eq!(
        outcome.expect_err("reserved opcode 0 should fail"),
        "address resolution opcode is reserved by RFC 5494"
    );
}

#[test]
fn rfc_826_reply_uses_sender_hardware_not_ethernet_source() {
    // Arrange
    let ethernet_source = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let arp_sender = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let sender_ip = Ipv4Addr::new(10, 0, 0, 5);
    let mut frame = build_address_resolution_request_ethernet_frame(
        arp_sender,
        sender_ip,
        Ipv4Addr::new(10, 0, 0, 1),
    );
    frame[6..12].copy_from_slice(&ethernet_source.octets());
    let opcode_offset = ETHERNET_II_HEADER_LENGTH + 6;
    frame[opcode_offset..opcode_offset + 2].copy_from_slice(&2u16.to_be_bytes());

    // Act
    let (ip, mac) = try_parse_address_resolution_reply_ipv4_over_ethernet(&frame)
        .expect("reply should parse using ar$sha");

    // Assert
    assert_eq!(ip, sender_ip);
    assert_eq!(mac, arp_sender);
    assert_ne!(mac, ethernet_source);
}

#[test]
fn rfc_1042_llc_snap_reply_is_accepted() {
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
    let arp = &mut frame[arp_start..arp_start + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH];
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
