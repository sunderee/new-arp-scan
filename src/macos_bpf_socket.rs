//! macOS Berkeley Packet Filter link-layer endpoint for ARP send and receive.
//!
//! A single BPF `read(2)` can return several records, each prefixed by a `bpf_hdr` header and
//! padded to a 4-byte (`BPF_ALIGNMENT`) boundary. [`MacosBpfEndpoint`] hides that aggregation
//! behind the portable [`LinkLayerEndpoint`] surface so the shared scanner observes one Ethernet
//! frame at a time, exactly as it does on Linux. The capture filter admits only the framings the
//! shared parser accepts, including the IEEE 802.1ad service-tag-plus-customer-tag pair. All raw
//! system calls live in
//! [`crate::macos_system_call`]; the record-walking here is pure byte-slice arithmetic.

#![allow(
    unsafe_code,
    reason = "libc FFI for the macOS packet backend; see DECISIONS.md 2026-11-15"
)]

use std::mem::offset_of;
use std::os::fd::OwnedFd;

use crate::error::AppError;
use crate::interface_validation;
use crate::link_layer_backend::LinkLayerEndpoint;
use crate::macos_system_call::{self, BpfProgramInstruction};

/// `BPF_ALIGNMENT` from `net/bpf.h`: each record is padded to this boundary.
const BPF_RECORD_ALIGNMENT: usize = 4;

/// `BPF_LD | BPF_H | BPF_ABS`: load the 16-bit halfword at a fixed frame offset into the accumulator.
const BPF_LOAD_HALFWORD_ABSOLUTE: u16 = 0x28;
/// `BPF_LD | BPF_W | BPF_ABS`: load the 32-bit word at a fixed frame offset into the accumulator.
const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`: branch on accumulator equal to a constant.
const BPF_JUMP_IF_EQUAL_CONSTANT: u16 = 0x15;
/// `BPF_JMP | BPF_JGT | BPF_K`: branch on accumulator greater than a constant.
const BPF_JUMP_IF_GREATER_THAN_CONSTANT: u16 = 0x25;
/// `BPF_RET | BPF_K`: return a constant capture length (0 drops the frame).
const BPF_RETURN_CONSTANT: u16 = 0x06;
/// Offset of the `EtherType` / IEEE 802.3 length field in an untagged Ethernet header.
const ETHERNET_TYPE_FIELD_OFFSET: u32 = 12;
/// Octets one IEEE 802.1Q tag (TPID + TCI) inserts before the inner length/type field.
const IEEE_8021Q_TAG_OCTETS: u32 = 4;
/// Offset of the IEEE 802.2 LLC header, which starts right after the 2-octet length field.
const LLC_SNAP_PREFIX_OFFSET_AFTER_LENGTH: u32 = 2;
/// Offset of the last 4 SNAP octets (OUI tail plus encapsulated `EtherType`) after the length.
const SNAP_ETHERTYPE_OFFSET_AFTER_LENGTH: u32 = 6;

/// Frame offset of the length/type field that sits behind `tag_count` IEEE 802.1Q tags.
const fn length_type_field_offset(tag_count: u32) -> u32 {
    ETHERNET_TYPE_FIELD_OFFSET + tag_count * IEEE_8021Q_TAG_OCTETS
}
/// `EtherType` for ARP (`ETH_P_ARP`).
const ETHERNET_TYPE_ARP: u32 = 0x0806;
/// `EtherType` for IEEE 802.1Q VLAN tagging (`ETH_P_8021Q`).
const ETHERNET_TYPE_VLAN_TAG: u32 = 0x8100;
/// `EtherType` for IEEE 802.1Q service VLAN tagging / IEEE 802.1ad S-TAG (`ETH_P_8021AD`).
const ETHERNET_TYPE_VLAN_TAG_SERVICE: u32 = 0x88A8;
/// IEEE 802.3 maximum MAC client data length; values above this are not length fields.
const IEEE_8023_MAXIMUM_LENGTH: u32 = 1500;
/// First four octets of RFC 1042 LLC/SNAP (`AA AA 03 00`).
const RFC_1042_LLC_SNAP_PREFIX: u32 = 0xAAAA_0300;
/// Last four octets of RFC 1042 SNAP ARP (`00 00 08 06`).
const RFC_1042_SNAP_ARP_ETHERTYPE: u32 = 0x0000_0806;
/// Capture length that accepts the whole frame.
const BPF_ACCEPT_WHOLE_FRAME: u32 = u32::MAX;

/// Classic Berkeley Packet Filter program accepting ARP in Ethernet II, behind a single IEEE
/// 802.1Q customer tag, behind an IEEE 802.1Q service tag wrapping one customer tag (IEEE
/// 802.1ad), and in RFC 1042 LLC/SNAP under any of those three framings.
///
/// Unlike a Linux `AF_PACKET` socket bound to `ETH_P_ARP`, a BPF device delivers every frame on the
/// interface by default, so this filter is what scopes reads to ARP and avoids flooding the scanner
/// with unrelated traffic. VLAN-tagged and IEEE 802.3 SNAP ARP are included so those replies are
/// not dropped before the shared parser.
///
/// The filter admits only the tag arrangements the userspace parser accepts. A service tag is
/// followed to its customer tag and no further, so a lone `0x88A8` tag, stacked customer tags, a
/// third tag after a legal pair, and the unofficial TPIDs `0x9100` / `0x9200` / `0x9300` never
/// reach userspace. Relative jump targets are dense and hand-maintained; the accept/drop matrix in
/// this module's tests interprets the program to keep them honest.
const ARP_CAPTURE_FILTER: [BpfProgramInstruction; 27] = [
    // 0: outermost length/type field
    BpfProgramInstruction {
        code: BPF_LOAD_HALFWORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(0),
    },
    // 1: untagged Ethernet II ARP -> accept
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 24,
        jump_if_false: 0,
        operand: ETHERNET_TYPE_ARP,
    },
    // 2: one IEEE 802.1Q customer tag -> customer branch
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 6,
        jump_if_false: 0,
        operand: ETHERNET_TYPE_VLAN_TAG,
    },
    // 3: IEEE 802.1Q service tag (IEEE 802.1ad) -> service branch
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 12,
        jump_if_false: 0,
        operand: ETHERNET_TYPE_VLAN_TAG_SERVICE,
    },
    // 4: neither ARP, a tag, nor a length -> drop
    BpfProgramInstruction {
        code: BPF_JUMP_IF_GREATER_THAN_CONSTANT,
        jump_if_true: 20,
        jump_if_false: 0,
        operand: IEEE_8023_MAXIMUM_LENGTH,
    },
    // 5: untagged IEEE 802.3: LLC and the head of SNAP
    BpfProgramInstruction {
        code: BPF_LOAD_WORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(0) + LLC_SNAP_PREFIX_OFFSET_AFTER_LENGTH,
    },
    // 6: must be RFC 1042 AA AA 03 00
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 0,
        jump_if_false: 18,
        operand: RFC_1042_LLC_SNAP_PREFIX,
    },
    // 7: SNAP OUI tail and encapsulated EtherType
    BpfProgramInstruction {
        code: BPF_LOAD_WORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(0) + SNAP_ETHERTYPE_OFFSET_AFTER_LENGTH,
    },
    // 8: untagged RFC 1042 SNAP ARP -> accept
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 17,
        jump_if_false: 16,
        operand: RFC_1042_SNAP_ARP_ETHERTYPE,
    },
    // 9: customer branch: inner length/type after one tag
    BpfProgramInstruction {
        code: BPF_LOAD_HALFWORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(1),
    },
    // 10: 0x8100 then ARP -> accept
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 15,
        jump_if_false: 0,
        operand: ETHERNET_TYPE_ARP,
    },
    // 11: not a length either -> drop
    BpfProgramInstruction {
        code: BPF_JUMP_IF_GREATER_THAN_CONSTANT,
        jump_if_true: 13,
        jump_if_false: 0,
        operand: IEEE_8023_MAXIMUM_LENGTH,
    },
    // 12: tagged IEEE 802.3: LLC and the head of SNAP
    BpfProgramInstruction {
        code: BPF_LOAD_WORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(1) + LLC_SNAP_PREFIX_OFFSET_AFTER_LENGTH,
    },
    // 13: must be RFC 1042 AA AA 03 00
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 0,
        jump_if_false: 11,
        operand: RFC_1042_LLC_SNAP_PREFIX,
    },
    // 14: SNAP OUI tail and encapsulated EtherType
    BpfProgramInstruction {
        code: BPF_LOAD_WORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(1) + SNAP_ETHERTYPE_OFFSET_AFTER_LENGTH,
    },
    // 15: 0x8100 then RFC 1042 SNAP ARP -> accept
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 10,
        jump_if_false: 9,
        operand: RFC_1042_SNAP_ARP_ETHERTYPE,
    },
    // 16: service branch: the TPID that must follow the S-TAG
    BpfProgramInstruction {
        code: BPF_LOAD_HALFWORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(1),
    },
    // 17: an S-TAG must be followed by a 0x8100 C-TAG, else drop
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 0,
        jump_if_false: 7,
        operand: ETHERNET_TYPE_VLAN_TAG,
    },
    // 18: inner length/type after S-TAG + C-TAG
    BpfProgramInstruction {
        code: BPF_LOAD_HALFWORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(2),
    },
    // 19: 0x88A8 + 0x8100 then ARP -> accept
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 6,
        jump_if_false: 0,
        operand: ETHERNET_TYPE_ARP,
    },
    // 20: not a length either -> drop
    BpfProgramInstruction {
        code: BPF_JUMP_IF_GREATER_THAN_CONSTANT,
        jump_if_true: 4,
        jump_if_false: 0,
        operand: IEEE_8023_MAXIMUM_LENGTH,
    },
    // 21: stacked IEEE 802.3: LLC and the head of SNAP
    BpfProgramInstruction {
        code: BPF_LOAD_WORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(2) + LLC_SNAP_PREFIX_OFFSET_AFTER_LENGTH,
    },
    // 22: must be RFC 1042 AA AA 03 00
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 0,
        jump_if_false: 2,
        operand: RFC_1042_LLC_SNAP_PREFIX,
    },
    // 23: SNAP OUI tail and encapsulated EtherType
    BpfProgramInstruction {
        code: BPF_LOAD_WORD_ABSOLUTE,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: length_type_field_offset(2) + SNAP_ETHERTYPE_OFFSET_AFTER_LENGTH,
    },
    // 24: 0x88A8 + 0x8100 then RFC 1042 SNAP ARP -> accept
    BpfProgramInstruction {
        code: BPF_JUMP_IF_EQUAL_CONSTANT,
        jump_if_true: 1,
        jump_if_false: 0,
        operand: RFC_1042_SNAP_ARP_ETHERTYPE,
    },
    // 25: drop: zero capture length
    BpfProgramInstruction {
        code: BPF_RETURN_CONSTANT,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: 0,
    },
    // 26: accept: the whole frame
    BpfProgramInstruction {
        code: BPF_RETURN_CONSTANT,
        jump_if_true: 0,
        jump_if_false: 0,
        operand: BPF_ACCEPT_WHOLE_FRAME,
    },
];

/// Mirror of the macOS userspace `struct bpf_hdr` used only for its field offsets.
///
/// macOS keeps an 8-byte 32-bit timestamp in the BPF header even on 64-bit userland, so the
/// capture-length and header-length fields sit at fixed offsets that [`offset_of`] resolves. The
/// data offset of each record is taken from its own `bh_hdrlen`, never assumed.
#[repr(C)]
struct BpfPacketHeaderLayout {
    bpf_timestamp_seconds: i32,
    bpf_timestamp_microseconds: i32,
    capture_length: u32,
    data_length: u32,
    header_length: u16,
}

/// Rounds `value` up to the next [`BPF_RECORD_ALIGNMENT`] boundary (`BPF_WORDALIGN`).
fn bpf_word_align(value: usize) -> usize {
    value.wrapping_add(BPF_RECORD_ALIGNMENT - 1) & !(BPF_RECORD_ALIGNMENT - 1)
}

/// Locates the next captured frame in a BPF read buffer starting at `cursor`.
///
/// Returns `(frame_start, frame_end, next_cursor)` on success, or [`None`] when the remaining bytes
/// cannot hold a complete record (a partial trailing record, or a malformed zero-length one).
fn next_bpf_record(buffer: &[u8], cursor: usize) -> Option<(usize, usize, usize)> {
    let capture_length_offset =
        cursor.checked_add(offset_of!(BpfPacketHeaderLayout, capture_length))?;
    let header_length_offset =
        cursor.checked_add(offset_of!(BpfPacketHeaderLayout, header_length))?;
    let capture_length_bytes = buffer.get(capture_length_offset..capture_length_offset + 4)?;
    let header_length_bytes = buffer.get(header_length_offset..header_length_offset + 2)?;

    let capture_length = u32::from_ne_bytes(capture_length_bytes.try_into().ok()?) as usize;
    let header_length = u16::from_ne_bytes(header_length_bytes.try_into().ok()?) as usize;

    let frame_start = cursor.checked_add(header_length)?;
    let frame_end = frame_start.checked_add(capture_length)?;
    if frame_end > buffer.len() {
        return None;
    }

    let record_length = bpf_word_align(header_length.checked_add(capture_length)?);
    if record_length == 0 {
        return None;
    }
    let next_cursor = cursor.checked_add(record_length)?;

    Some((frame_start, frame_end, next_cursor))
}

/// A macOS Berkeley Packet Filter device attached to one interface for ARP frames.
///
/// Owns the BPF descriptor (closed on drop) and a kernel-sized read buffer with a parse cursor so
/// the aggregated records from one `read(2)` are surfaced one frame at a time.
pub struct MacosBpfEndpoint {
    bpf_device: OwnedFd,
    read_buffer: Vec<u8>,
    filled_length: usize,
    parse_cursor: usize,
}

/// Opens a Berkeley Packet Filter device, attaches it to `interface_name`, and configures it for
/// immediate, complete-header ARP frame input/output.
///
/// # Errors
///
/// Returns [`AppError::RawSocketOpenFailed`] when the device cannot be opened or configured,
/// [`AppError::SocketBindFailed`] when it cannot be attached to the interface, or
/// [`AppError::InvalidInterfaceName`] when the name does not fit the kernel request structure.
///
/// # Panics
///
/// This function does not panic.
pub fn open_macos_link_layer_endpoint(interface_name: &str) -> Result<MacosBpfEndpoint, AppError> {
    let bpf_device = macos_system_call::open_bpf_device().map_err(|source| {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            AppError::BpfDeviceAccessRequired { source }
        } else {
            AppError::RawSocketOpenFailed { source }
        }
    })?;

    let mut interface_request: libc::ifreq = unsafe { std::mem::zeroed() };
    interface_validation::copy_interface_name_to_ifreq(interface_name, &mut interface_request)?;
    macos_system_call::set_bpf_interface(&bpf_device, &interface_request)
        .map_err(|source| AppError::SocketBindFailed { source })?;

    // Scope reads to ARP (Ethernet II, one 802.1Q customer tag, an 802.1ad service tag wrapping
    // one customer tag, or RFC 1042 SNAP under any of those) and stop the device from echoing back
    // the requests we broadcast, matching the effect of a Linux packet socket plus the extra
    // framings the shared parser accepts.
    macos_system_call::set_bpf_filter(&bpf_device, &ARP_CAPTURE_FILTER)
        .map_err(|source| AppError::RawSocketOpenFailed { source })?;
    macos_system_call::set_bpf_see_sent(&bpf_device, false)
        .map_err(|source| AppError::RawSocketOpenFailed { source })?;

    macos_system_call::set_bpf_immediate(&bpf_device, true)
        .map_err(|source| AppError::RawSocketOpenFailed { source })?;
    macos_system_call::set_bpf_header_complete(&bpf_device, true)
        .map_err(|source| AppError::RawSocketOpenFailed { source })?;
    let buffer_length = macos_system_call::get_bpf_buffer_length(&bpf_device)
        .map_err(|source| AppError::RawSocketOpenFailed { source })?;
    macos_system_call::set_file_descriptor_nonblocking(&bpf_device)
        .map_err(|source| AppError::RawSocketOpenFailed { source })?;

    Ok(MacosBpfEndpoint {
        bpf_device,
        read_buffer: vec![0u8; buffer_length as usize],
        filled_length: 0,
        parse_cursor: 0,
    })
}

impl LinkLayerEndpoint for MacosBpfEndpoint {
    fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
        macos_system_call::write_link_layer_frame(&self.bpf_device, frame).map(|_sent| ())
    }

    fn wait_until_readable(&self, timeout_milliseconds: libc::c_int) -> Result<bool, AppError> {
        match macos_system_call::poll_readiness(
            &self.bpf_device,
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
            if self.parse_cursor < self.filled_length {
                match next_bpf_record(&self.read_buffer[..self.filled_length], self.parse_cursor) {
                    Some((frame_start, frame_end, next_cursor)) => {
                        let copy_length = (frame_end - frame_start).min(buffer.len());
                        buffer[..copy_length].copy_from_slice(
                            &self.read_buffer[frame_start..frame_start + copy_length],
                        );
                        self.parse_cursor = next_cursor.min(self.filled_length);
                        return Ok(Some(copy_length));
                    }
                    None => {
                        self.parse_cursor = self.filled_length;
                    }
                }
            }

            match macos_system_call::read_link_layer_frames(&self.bpf_device, &mut self.read_buffer)
            {
                Ok(0) => return Ok(None),
                Ok(received) => {
                    self.filled_length = received;
                    self.parse_cursor = 0;
                }
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
    use super::{
        ARP_CAPTURE_FILTER, BPF_JUMP_IF_EQUAL_CONSTANT, BPF_JUMP_IF_GREATER_THAN_CONSTANT,
        BPF_LOAD_HALFWORD_ABSOLUTE, BPF_LOAD_WORD_ABSOLUTE, BPF_RECORD_ALIGNMENT,
        BPF_RETURN_CONSTANT, BpfPacketHeaderLayout, bpf_word_align, length_type_field_offset,
        next_bpf_record, open_macos_link_layer_endpoint,
    };
    use crate::error::AppError;
    use crate::macos_system_call::BpfProgramInstruction;
    use std::mem::offset_of;

    #[test]
    fn open_macos_link_layer_endpoint_opens_a_device_or_reports_a_recognized_failure() {
        // Act
        let outcome = open_macos_link_layer_endpoint("en0");

        // Assert
        match outcome {
            Ok(_endpoint) => {
                // Running with BPF access (root): a device opened and attached successfully. The
                // test suite does not drive live ARP traffic, so there is nothing further to assert.
            }
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        AppError::BpfDeviceAccessRequired { .. }
                            | AppError::RawSocketOpenFailed { .. }
                            | AppError::SocketBindFailed { .. }
                            | AppError::InvalidInterfaceName { .. }
                    ),
                    "opening a BPF endpoint without privileges should report a BPF access or \
                     socket/open failure, got: {error:?}"
                );
            }
        }
    }

    /// Builds one BPF record: a word-aligned header carrying `frame`, followed by the frame bytes,
    /// followed by trailing padding to the next record boundary.
    fn build_bpf_record(frame: &[u8]) -> Vec<u8> {
        let header_length = bpf_word_align(offset_of!(BpfPacketHeaderLayout, header_length) + 2);
        let mut record = vec![0u8; header_length];
        let capture_length = u32::try_from(frame.len()).expect("fixture frame fits u32");
        record[offset_of!(BpfPacketHeaderLayout, capture_length)
            ..offset_of!(BpfPacketHeaderLayout, capture_length) + 4]
            .copy_from_slice(&capture_length.to_ne_bytes());
        record[offset_of!(BpfPacketHeaderLayout, data_length)
            ..offset_of!(BpfPacketHeaderLayout, data_length) + 4]
            .copy_from_slice(&capture_length.to_ne_bytes());
        let header_length_value = u16::try_from(header_length).expect("header length fits u16");
        record[offset_of!(BpfPacketHeaderLayout, header_length)
            ..offset_of!(BpfPacketHeaderLayout, header_length) + 2]
            .copy_from_slice(&header_length_value.to_ne_bytes());
        record.extend_from_slice(frame);
        while !record.len().is_multiple_of(BPF_RECORD_ALIGNMENT) {
            record.push(0);
        }
        record
    }

    #[test]
    fn capture_and_header_length_offsets_match_macos_bpf_header() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            offset_of!(BpfPacketHeaderLayout, capture_length),
            8,
            "bh_caplen should sit after the 8-byte 32-bit BPF timestamp"
        );
        assert_eq!(
            offset_of!(BpfPacketHeaderLayout, header_length),
            16,
            "bh_hdrlen should sit after the two 32-bit length fields"
        );
    }

    #[test]
    fn word_align_rounds_up_to_four_byte_boundary() {
        // Arrange
        // Act
        // Assert
        assert_eq!(bpf_word_align(0), 0, "zero stays aligned");
        assert_eq!(bpf_word_align(1), 4, "one rounds up to four");
        assert_eq!(bpf_word_align(18), 20, "the 18-byte header rounds to 20");
        assert_eq!(
            bpf_word_align(20),
            20,
            "already-aligned values are unchanged"
        );
    }

    #[test]
    fn next_bpf_record_extracts_single_frame() {
        // Arrange
        let frame = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04];
        let buffer = build_bpf_record(&frame);

        // Act
        let outcome = next_bpf_record(&buffer, 0);

        // Assert
        let (start, end, next) = outcome.expect("a complete record should be located");
        assert_eq!(
            &buffer[start..end],
            &frame,
            "extracted bytes should equal the frame"
        );
        assert_eq!(
            next,
            buffer.len(),
            "the next cursor should advance past the only record"
        );
    }

    #[test]
    fn next_bpf_record_walks_two_aggregated_frames() {
        // Arrange
        let first_frame = [0xAAu8; 12];
        let second_frame = [0xBBu8; 20];
        let mut buffer = build_bpf_record(&first_frame);
        buffer.extend_from_slice(&build_bpf_record(&second_frame));

        // Act
        let (first_start, first_end, first_next) =
            next_bpf_record(&buffer, 0).expect("first record should be located");
        let (second_start, second_end, second_next) =
            next_bpf_record(&buffer, first_next).expect("second record should be located");

        // Assert
        assert_eq!(
            &buffer[first_start..first_end],
            &first_frame,
            "first frame should de-aggregate correctly"
        );
        assert_eq!(
            &buffer[second_start..second_end],
            &second_frame,
            "second frame should de-aggregate correctly after word-aligned advance"
        );
        assert_eq!(
            second_next,
            buffer.len(),
            "walking should end exactly at the buffer length"
        );
    }

    #[test]
    fn next_bpf_record_returns_none_for_partial_trailing_header() {
        // Arrange
        let buffer = [0u8; 4];

        // Act
        let outcome = next_bpf_record(&buffer, 0);

        // Assert
        assert!(
            outcome.is_none(),
            "a buffer too small for a header should yield no record, got: {outcome:?}"
        );
    }

    #[test]
    fn next_bpf_record_returns_none_when_capture_length_exceeds_buffer() {
        // Arrange
        let frame = [0x10u8; 8];
        let mut buffer = build_bpf_record(&frame);
        // Truncate so the advertised capture length runs past the available bytes.
        buffer.truncate(buffer.len() - 4);

        // Act
        let outcome = next_bpf_record(&buffer, 0);

        // Assert
        assert!(
            outcome.is_none(),
            "a capture length past the buffer end should be rejected, got: {outcome:?}"
        );
    }

    fn classic_bpf_accepts_frame(filter: &[BpfProgramInstruction], frame: &[u8]) -> bool {
        let mut program_counter = 0usize;
        let mut accumulator = 0u32;
        for _ in 0..=filter.len() {
            let instruction = filter
                .get(program_counter)
                .expect("BPF program counter should stay inside the filter");
            match instruction.code {
                BPF_LOAD_HALFWORD_ABSOLUTE => {
                    let offset = usize::try_from(instruction.operand).expect("offset fits usize");
                    let Some(octets) = frame.get(offset..offset + 2) else {
                        return false;
                    };
                    accumulator = u32::from(u16::from_be_bytes([octets[0], octets[1]]));
                    program_counter += 1;
                }
                BPF_LOAD_WORD_ABSOLUTE => {
                    let offset = usize::try_from(instruction.operand).expect("offset fits usize");
                    let Some(octets) = frame.get(offset..offset + 4) else {
                        return false;
                    };
                    accumulator = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
                    program_counter += 1;
                }
                BPF_JUMP_IF_EQUAL_CONSTANT => {
                    let skip = if accumulator == instruction.operand {
                        usize::from(instruction.jump_if_true)
                    } else {
                        usize::from(instruction.jump_if_false)
                    };
                    program_counter = program_counter
                        .checked_add(1)
                        .and_then(|next| next.checked_add(skip))
                        .expect("BPF jump should stay in range");
                }
                BPF_JUMP_IF_GREATER_THAN_CONSTANT => {
                    let skip = if accumulator > instruction.operand {
                        usize::from(instruction.jump_if_true)
                    } else {
                        usize::from(instruction.jump_if_false)
                    };
                    program_counter = program_counter
                        .checked_add(1)
                        .and_then(|next| next.checked_add(skip))
                        .expect("BPF jump should stay in range");
                }
                BPF_RETURN_CONSTANT => {
                    return instruction.operand != 0;
                }
                other => panic!("unexpected BPF opcode {other:#x} in ARP capture filter"),
            }
        }
        panic!("ARP capture filter did not return");
    }

    /// Builds a 60-octet fixture: broadcast destination, a fixed source, then `fragments`.
    fn ethernet_fixture(fragments: &[&[u8]]) -> [u8; 60] {
        let mut frame = [0u8; 60];
        let header: [u8; 12] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1];
        frame[..header.len()].copy_from_slice(&header);
        let mut cursor = header.len();
        for fragment in fragments {
            frame[cursor..cursor + fragment.len()].copy_from_slice(fragment);
            cursor += fragment.len();
        }
        frame
    }

    /// IEEE 802.1Q customer tag protocol identifier (C-TAG).
    const C_TAG: &[u8] = &[0x81, 0x00];
    /// IEEE 802.1Q service tag protocol identifier (S-TAG, IANA `EtherType` 34984).
    const S_TAG: &[u8] = &[0x88, 0xa8];
    /// Unofficial vendor `QinQ` TPID `0x9100`.
    const QINQ_9100: &[u8] = &[0x91, 0x00];
    /// `EtherType` for ARP.
    const ARP: &[u8] = &[0x08, 0x06];
    /// `EtherType` for IPv4.
    const IPV4: &[u8] = &[0x08, 0x00];
    /// RFC 1042 LLC/SNAP prefix `AA AA 03 00 00 00`, without the encapsulated `EtherType`.
    const SNAP: &[u8] = &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];
    /// An IEEE 802.3 length field of 36: LLC + SNAP + a 28-octet ARP PDU.
    const SNAP_LENGTH: &[u8] = &[0x00, 0x24];
    /// Eight octets that are not RFC 1042 LLC/SNAP.
    const NOT_SNAP: &[u8] = &[0u8; 8];
    /// TCI for service PCP 5, DEI 1, S-VID 100.
    const SERVICE_TCI: &[u8] = &[0xb0, 0x64];
    /// TCI for customer PCP 0, DEI 0, C-VID 10.
    const CUSTOMER_TCI: &[u8] = &[0x00, 0x0a];

    /// Runs each `(name, fragments, expected)` case through the filter and asserts the verdict.
    fn assert_filter_verdicts(cases: &[(&str, &[&[u8]], bool)]) {
        let outcomes: Vec<(&str, bool, bool)> = cases
            .iter()
            .map(|(name, fragments, expected)| {
                let frame = ethernet_fixture(fragments);
                (
                    *name,
                    classic_bpf_accepts_frame(&ARP_CAPTURE_FILTER, &frame),
                    *expected,
                )
            })
            .collect();
        for (name, accepted, expected) in outcomes {
            assert_eq!(
                accepted, expected,
                "BPF filter verdict for `{name}` should be accept={expected}"
            );
        }
    }

    #[test]
    fn arp_capture_filter_accepts_every_arp_framing_the_parser_accepts() {
        // Arrange: one fixture per accepting path through the filter.
        let cases: [(&str, &[&[u8]], bool); 7] = [
            ("untagged Ethernet II ARP", &[ARP], true),
            ("customer tag then ARP", &[C_TAG, CUSTOMER_TCI, ARP], true),
            (
                "untagged RFC 1042 SNAP ARP",
                &[SNAP_LENGTH, SNAP, ARP],
                true,
            ),
            (
                "customer tag then RFC 1042 SNAP ARP",
                &[C_TAG, CUSTOMER_TCI, SNAP_LENGTH, SNAP, ARP],
                true,
            ),
            (
                "service tag wrapping a customer tag then ARP",
                &[S_TAG, SERVICE_TCI, C_TAG, CUSTOMER_TCI, ARP],
                true,
            ),
            (
                "service tag wrapping a customer tag then RFC 1042 SNAP ARP",
                &[
                    S_TAG,
                    SERVICE_TCI,
                    C_TAG,
                    CUSTOMER_TCI,
                    SNAP_LENGTH,
                    SNAP,
                    ARP,
                ],
                true,
            ),
            (
                "service tag with the maximum TCI wrapping a customer tag then ARP",
                &[S_TAG, &[0xff, 0xff], C_TAG, &[0xff, 0xff], ARP],
                true,
            ),
        ];

        // Act
        // Assert
        assert_filter_verdicts(&cases);
    }

    #[test]
    fn arp_capture_filter_drops_non_arp_and_every_unsupported_tag_arrangement() {
        // Arrange: non-ARP traffic under each accepted framing, then the tag arrangements the
        // userspace parser rejects, so the kernel never hands them to the scanner at all.
        let cases: [(&str, &[&[u8]], bool); 12] = [
            ("untagged Ethernet II IPv4", &[IPV4], false),
            (
                "customer tag then IPv4",
                &[C_TAG, CUSTOMER_TCI, IPV4],
                false,
            ),
            (
                "untagged RFC 1042 SNAP IPv4",
                &[SNAP_LENGTH, SNAP, IPV4],
                false,
            ),
            (
                "IEEE 802.3 length without RFC 1042 SNAP",
                &[SNAP_LENGTH, NOT_SNAP],
                false,
            ),
            (
                "service tag wrapping a customer tag then IPv4",
                &[S_TAG, SERVICE_TCI, C_TAG, CUSTOMER_TCI, IPV4],
                false,
            ),
            (
                "service tag wrapping a customer tag then RFC 1042 SNAP IPv4",
                &[
                    S_TAG,
                    SERVICE_TCI,
                    C_TAG,
                    CUSTOMER_TCI,
                    SNAP_LENGTH,
                    SNAP,
                    IPV4,
                ],
                false,
            ),
            (
                "service tag then ARP with no customer tag",
                &[S_TAG, SERVICE_TCI, ARP],
                false,
            ),
            (
                "two stacked service tags",
                &[S_TAG, SERVICE_TCI, S_TAG, CUSTOMER_TCI, ARP],
                false,
            ),
            (
                "two stacked customer tags",
                &[C_TAG, CUSTOMER_TCI, C_TAG, &[0x00, 0x02], ARP],
                false,
            ),
            (
                "three stacked tags",
                &[
                    S_TAG,
                    SERVICE_TCI,
                    C_TAG,
                    CUSTOMER_TCI,
                    C_TAG,
                    &[0x00, 0x03],
                    ARP,
                ],
                false,
            ),
            (
                "unofficial QinQ TPID 0x9100",
                &[QINQ_9100, CUSTOMER_TCI, ARP],
                false,
            ),
            (
                "stacked tags then a length without RFC 1042 SNAP",
                &[
                    S_TAG,
                    SERVICE_TCI,
                    C_TAG,
                    CUSTOMER_TCI,
                    SNAP_LENGTH,
                    NOT_SNAP,
                ],
                false,
            ),
        ];

        // Act
        // Assert
        assert_filter_verdicts(&cases);
    }

    #[test]
    fn arp_capture_filter_structure_matches_the_documented_branch_layout() {
        // Arrange
        let filter = ARP_CAPTURE_FILTER;

        // Act
        // Assert
        assert_eq!(
            filter.len(),
            27,
            "filter should cover Ethernet II, one customer tag, a service tag pair, and SNAP \
             under each"
        );
        assert_eq!(
            filter[0].operand, 12,
            "first load is the Ethernet length/type field"
        );
        assert_eq!(filter[1].operand, 0x0806, "first compare is EtherType ARP");
        assert_eq!(
            filter[2].operand, 0x8100,
            "second compare is the IEEE 802.1Q customer TPID"
        );
        assert_eq!(
            filter[3].operand, 0x88A8,
            "third compare is the IEEE 802.1Q service TPID (IANA EtherType 34984)"
        );
        assert_eq!(
            filter[17].operand, 0x8100,
            "the service branch requires a customer TPID at offset 16"
        );
        assert_eq!(filter[25].operand, 0, "drop returns zero capture length");
        assert_eq!(
            filter[26].operand,
            u32::MAX,
            "accept returns the whole frame"
        );
    }

    #[test]
    fn length_type_field_offset_tracks_one_tag_per_four_octets() {
        // Arrange
        // Act
        // Assert
        assert_eq!(
            length_type_field_offset(0),
            12,
            "untagged length/type field"
        );
        assert_eq!(
            length_type_field_offset(1),
            16,
            "one IEEE 802.1Q tag shifts the inner field by 4 octets"
        );
        assert_eq!(
            length_type_field_offset(2),
            20,
            "an S-TAG plus a C-TAG shifts the inner field by 8 octets"
        );
    }
}
