//! Passive IPv4 ARP listen loop shared by Linux and macOS.
//!
//! The loop is receive-only: it never calls [`LinkLayerEndpoint::send_ethernet_frame`]. A checked
//! monotonic deadline is re-evaluated before every read so a busy capture cannot run past the
//! timeout. Distinct packet records are capped, repeated records increment a saturating count, and
//! unrelated Ethernet frames stay silent.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::address_resolution_protocol::{
    ARP_OPERATION_REPLY, ARP_OPERATION_REQUEST, ParsedIpv4EthernetArp,
    try_parse_address_resolution_ipv4_over_ethernet,
};
use crate::error::{AppError, ScanTimingLimit};
use crate::ethernet_frame::{ETHERNET_PROTOCOL_ARP, try_parse_ethernet_frame};
use crate::link_layer_backend::LinkLayerEndpoint;
use crate::mac_address::MacAddress;
use crate::scan_timing::ScanClock;

/// Maximum number of distinct ARP packet identities retained for one listen.
pub(crate) const MONITOR_DISTINCT_RECORD_LIMIT: usize = 4_096;

/// Receive buffer shared with the scanner's fixed capture buffer.
const RECEIVE_BUFFER_LENGTH: usize = 4_096;

const PASSIVE_MONITOR_TRUNCATION_WARNING: &str = "passive monitor record limit reached; additional distinct ARP packets were not recorded, and duplicate-ip claims were not updated for those packets";

/// Local addresses and hardware address used to classify inbound ARP.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MonitorListenRequest<'a> {
    /// IPv4 addresses configured on the monitored interface.
    pub local_ipv4_addresses: &'a [Ipv4Addr],
    /// Ethernet address of that interface.
    pub local_mac_address: MacAddress,
    /// Positive listen window. Zero is rejected before the endpoint is used.
    pub timeout: Duration,
}

/// Whether a retained ARP packet conflicts with a local address or is only observed.
///
/// New classes may be added. Match with a wildcard outside this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PassiveArpClass {
    /// RFC 5227-style conflict: request or reply, local `ar$spa`, foreign `ar$sha`.
    Conflict,
    /// Any other well-formed ARP packet that was not sent by this interface.
    Observed,
}

/// One aggregated ARP packet identity.
///
/// New fields may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PassiveArpRecord {
    /// Conflict or ordinary observation. A packet is never both.
    pub classification: PassiveArpClass,
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
    /// How many identical packets were retained. Saturates at [`u64::MAX`].
    pub count: u64,
}

/// Nonlocal, non-zero IPv4 address claimed by more than one hardware address.
///
/// New fields may be added. A packet dropped by the distinct-record limit does not create or
/// extend one of these claims.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DuplicateIpClaim {
    /// Shared `ar$spa`.
    pub protocol_address: Ipv4Addr,
    /// Distinct `ar$sha` values, in ascending hardware-address order.
    pub hardware_addresses: Vec<MacAddress>,
}

/// Buffered result of one passive listen.
///
/// New fields may be added. Duplicate claims cover only packet identities that were retained.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MonitorListenOutcome {
    /// Conflict and observation records in first-seen order.
    pub records: Vec<PassiveArpRecord>,
    /// Third-party duplicate claims in the order their IPv4 address was first seen.
    pub duplicate_ip_claims: Vec<DuplicateIpClaim>,
    /// Malformed-frame warnings, then at most one truncation warning.
    pub warnings: Vec<String>,
}

/// Rejects a zero timeout and a timeout that cannot be added to `clock`.
///
/// # Errors
///
/// Returns [`AppError::MonitorTimeoutRejected`] when `timeout` is zero, or
/// [`AppError::ScanTimingExceedsLimit`] with [`ScanTimingLimit::MonotonicDeadline`] when the
/// deadline is not representable.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn monitor_deadline<C: ScanClock>(
    clock: &C,
    timeout: Duration,
) -> Result<C::Timestamp, AppError> {
    if timeout.is_zero() {
        return Err(AppError::MonitorTimeoutRejected);
    }
    clock
        .checked_add(clock.now(), timeout)
        .ok_or(AppError::ScanTimingExceedsLimit {
            limit: ScanTimingLimit::MonotonicDeadline,
        })
}

/// Listens until `request.timeout` elapses, without transmitting.
///
/// # Errors
///
/// Returns [`AppError::MonitorTimeoutRejected`] for a zero timeout,
/// [`AppError::ScanTimingExceedsLimit`] when the deadline does not fit the clock, or the endpoint's
/// poll and receive errors.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn listen_for_passive_arp<E, C>(
    endpoint: &mut E,
    clock: &C,
    request: &MonitorListenRequest<'_>,
) -> Result<MonitorListenOutcome, AppError>
where
    E: LinkLayerEndpoint,
    C: ScanClock,
{
    let deadline = monitor_deadline(clock, request.timeout)?;
    let mut aggregator = PassiveArpAggregator::new(
        request.local_mac_address,
        request.local_ipv4_addresses,
        MONITOR_DISTINCT_RECORD_LIMIT,
    );
    let mut receive_buffer = [0u8; RECEIVE_BUFFER_LENGTH];
    while clock.now() < deadline {
        let remaining = clock.saturating_duration_since(deadline, clock.now());
        if remaining.is_zero() {
            break;
        }
        let timeout_milliseconds = poll_timeout_milliseconds_for_receive_wait(remaining);
        if endpoint.wait_until_readable(timeout_milliseconds)? {
            drain_until_deadline(
                endpoint,
                clock,
                deadline,
                &mut receive_buffer,
                &mut aggregator,
            )?;
        } else {
            clock.advance_after_unreadable_wait(remaining);
        }
    }
    Ok(aggregator.finish())
}

/// Writes labeled conflict, observation, and duplicate lines, then `no conflicts observed` when
/// no conflict record was retained.
///
/// # Errors
///
/// Returns the writer error unchanged.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn write_monitor_stdout(
    outcome: &MonitorListenOutcome,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    for record in &outcome.records {
        if record.classification == PassiveArpClass::Conflict {
            write_packet_line(writer, "conflict", record)?;
        }
    }
    for record in &outcome.records {
        if record.classification == PassiveArpClass::Observed {
            write_packet_line(writer, "observed", record)?;
        }
    }
    for claim in &outcome.duplicate_ip_claims {
        write!(
            writer,
            "duplicate-ip: {} claimed by ",
            claim.protocol_address
        )?;
        write_claimed_hardware_addresses(writer, &claim.hardware_addresses)?;
        writeln!(writer, " count {}", claim.hardware_addresses.len())?;
    }
    if !outcome
        .records
        .iter()
        .any(|record| record.classification == PassiveArpClass::Conflict)
    {
        writeln!(writer, "no conflicts observed")?;
    }
    Ok(())
}

/// Writes `warning:` lines and the monitor completion summary.
///
/// Counts are distinct retained records, not the sum of repeat counts.
///
/// # Errors
///
/// Returns the writer error unchanged.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn write_monitor_stderr(
    outcome: &MonitorListenOutcome,
    interface_name: &str,
    elapsed: Duration,
    writer: &mut impl Write,
) -> std::io::Result<()> {
    for warning in &outcome.warnings {
        writeln!(writer, "warning: {warning}")?;
    }
    writeln!(
        writer,
        "{}",
        monitor_completion_summary(interface_name, outcome, elapsed)
    )
}

/// Stable stderr summary for one completed listen.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub(crate) fn monitor_completion_summary(
    interface_name: &str,
    outcome: &MonitorListenOutcome,
    elapsed: Duration,
) -> String {
    let conflict_count = outcome
        .records
        .iter()
        .filter(|record| record.classification == PassiveArpClass::Conflict)
        .count();
    let observation_count = outcome
        .records
        .iter()
        .filter(|record| record.classification == PassiveArpClass::Observed)
        .count();
    let duplicate_count = outcome.duplicate_ip_claims.len();
    format!(
        "monitor complete: interface {interface_name}, {conflict_count} {}, {observation_count} {}, {duplicate_count} {}, {} ms",
        counted_noun(conflict_count, "conflict", "conflicts"),
        counted_noun(observation_count, "observation", "observations"),
        counted_noun(duplicate_count, "duplicate-ip claim", "duplicate-ip claims"),
        elapsed_milliseconds_saturating(elapsed),
    )
}

fn counted_noun<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn elapsed_milliseconds_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
}

fn poll_timeout_milliseconds_for_receive_wait(remaining: Duration) -> libc::c_int {
    let milliseconds = remaining.as_millis();
    libc::c_int::try_from(milliseconds).unwrap_or(libc::c_int::MAX)
}

fn drain_until_deadline<E, C>(
    endpoint: &mut E,
    clock: &C,
    deadline: C::Timestamp,
    receive_buffer: &mut [u8],
    aggregator: &mut PassiveArpAggregator,
) -> Result<(), AppError>
where
    E: LinkLayerEndpoint,
    C: ScanClock,
{
    loop {
        if clock.now() >= deadline {
            break;
        }
        match endpoint.try_receive_ethernet_frame(receive_buffer)? {
            Some(length) => {
                let Some(frame) = receive_buffer.get(..length) else {
                    return Err(AppError::RawPacketReceiveFailed {
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "receive length exceeds the monitor buffer",
                        ),
                    });
                };
                aggregator.observe(frame);
            }
            None => break,
        }
    }
    Ok(())
}

fn frame_is_unrelated_to_address_resolution(frame: &[u8]) -> bool {
    match try_parse_ethernet_frame(frame) {
        Ok(parsed) => parsed.ether_type != ETHERNET_PROTOCOL_ARP,
        Err(_) => true,
    }
}

fn classify_passive_arp(
    opcode: u16,
    sender_hardware: MacAddress,
    sender_protocol: Ipv4Addr,
    local_mac_address: MacAddress,
    local_ipv4_addresses: &BTreeSet<Ipv4Addr>,
) -> Option<PassiveArpClass> {
    let sender_protocol_is_local = local_ipv4_addresses.contains(&sender_protocol);
    if sender_hardware == local_mac_address && sender_protocol_is_local {
        return None;
    }
    if sender_protocol_is_local && matches!(opcode, ARP_OPERATION_REQUEST | ARP_OPERATION_REPLY) {
        Some(PassiveArpClass::Conflict)
    } else {
        Some(PassiveArpClass::Observed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PacketIdentity {
    opcode: u16,
    sender_hardware: MacAddress,
    sender_protocol: Ipv4Addr,
    target_hardware: MacAddress,
    target_protocol: Ipv4Addr,
}

struct MalformedWarning {
    reason: &'static str,
    count: u64,
}

struct PassiveArpAggregator {
    local_mac_address: MacAddress,
    local_ipv4_addresses: BTreeSet<Ipv4Addr>,
    record_limit: usize,
    records: Vec<PassiveArpRecord>,
    indexes: BTreeMap<PacketIdentity, usize>,
    claimants: BTreeMap<Ipv4Addr, BTreeSet<MacAddress>>,
    claim_order: Vec<Ipv4Addr>,
    malformed: Vec<MalformedWarning>,
    truncated: bool,
}

impl PassiveArpAggregator {
    fn new(
        local_mac_address: MacAddress,
        local_ipv4_addresses: &[Ipv4Addr],
        record_limit: usize,
    ) -> Self {
        Self {
            local_mac_address,
            local_ipv4_addresses: local_ipv4_addresses.iter().copied().collect(),
            record_limit,
            records: Vec::new(),
            indexes: BTreeMap::new(),
            claimants: BTreeMap::new(),
            claim_order: Vec::new(),
            malformed: Vec::new(),
            truncated: false,
        }
    }

    fn observe(&mut self, frame: &[u8]) {
        if frame_is_unrelated_to_address_resolution(frame) {
            return;
        }
        match try_parse_address_resolution_ipv4_over_ethernet(frame) {
            Ok(parsed) => self.observe_parsed(parsed),
            Err(reason) => self.record_malformed(reason),
        }
    }

    fn observe_parsed(&mut self, parsed: ParsedIpv4EthernetArp) {
        let Some(classification) = classify_passive_arp(
            parsed.opcode,
            parsed.sender_hardware,
            parsed.sender_protocol,
            self.local_mac_address,
            &self.local_ipv4_addresses,
        ) else {
            return;
        };
        let identity = PacketIdentity {
            opcode: parsed.opcode,
            sender_hardware: parsed.sender_hardware,
            sender_protocol: parsed.sender_protocol,
            target_hardware: parsed.target_hardware,
            target_protocol: parsed.target_protocol,
        };
        if !self.remember_packet(classification, identity) {
            return;
        }
        if classification == PassiveArpClass::Observed {
            self.note_third_party_sender(parsed.sender_protocol, parsed.sender_hardware);
        }
    }

    fn remember_packet(
        &mut self,
        classification: PassiveArpClass,
        identity: PacketIdentity,
    ) -> bool {
        if let Some(index) = self.indexes.get(&identity).copied() {
            if let Some(record) = self.records.get_mut(index) {
                record.count = record.count.saturating_add(1);
            }
            return true;
        }
        if self.records.len() >= self.record_limit {
            self.truncated = true;
            return false;
        }
        let index = self.records.len();
        self.indexes.insert(identity, index);
        self.records.push(PassiveArpRecord {
            classification,
            opcode: identity.opcode,
            sender_hardware: identity.sender_hardware,
            sender_protocol: identity.sender_protocol,
            target_hardware: identity.target_hardware,
            target_protocol: identity.target_protocol,
            count: 1,
        });
        true
    }

    fn note_third_party_sender(&mut self, sender_protocol: Ipv4Addr, sender_hardware: MacAddress) {
        if sender_protocol.is_unspecified() || self.local_ipv4_addresses.contains(&sender_protocol)
        {
            return;
        }
        let claimants = self.claimants.entry(sender_protocol).or_default();
        if claimants.is_empty() {
            self.claim_order.push(sender_protocol);
        }
        claimants.insert(sender_hardware);
    }

    fn record_malformed(&mut self, reason: &'static str) {
        if let Some(existing) = self
            .malformed
            .iter_mut()
            .find(|warning| warning.reason == reason)
        {
            existing.count = existing.count.saturating_add(1);
            return;
        }
        self.malformed.push(MalformedWarning { reason, count: 1 });
    }

    fn finish(self) -> MonitorListenOutcome {
        let mut duplicate_ip_claims = Vec::new();
        for protocol_address in self.claim_order {
            let Some(hardware_addresses) = self.claimants.get(&protocol_address) else {
                continue;
            };
            if hardware_addresses.len() < 2 {
                continue;
            }
            duplicate_ip_claims.push(DuplicateIpClaim {
                protocol_address,
                hardware_addresses: hardware_addresses.iter().copied().collect(),
            });
        }
        let mut warnings = Vec::new();
        for malformed in self.malformed {
            warnings.push(malformed_warning_line(malformed.reason, malformed.count));
        }
        if self.truncated {
            warnings.push(PASSIVE_MONITOR_TRUNCATION_WARNING.to_string());
        }
        MonitorListenOutcome {
            records: self.records,
            duplicate_ip_claims,
            warnings,
        }
    }
}

fn malformed_warning_line(reason: &str, count: u64) -> String {
    if count == 1 {
        format!("received malformed Ethernet/ARP frame: {reason}")
    } else {
        format!("received malformed Ethernet/ARP frame: {reason} ({count} occurrences)")
    }
}

fn write_packet_line(
    writer: &mut impl Write,
    label: &str,
    record: &PassiveArpRecord,
) -> std::io::Result<()> {
    write!(writer, "{label}: ")?;
    write_opcode(writer, record.opcode)?;
    writeln!(
        writer,
        " {} is-at {} target {} {} count {}",
        record.sender_protocol,
        record.sender_hardware,
        record.target_hardware,
        record.target_protocol,
        record.count,
    )
}

fn write_opcode(writer: &mut impl Write, opcode: u16) -> std::io::Result<()> {
    match opcode {
        ARP_OPERATION_REQUEST => write!(writer, "request"),
        ARP_OPERATION_REPLY => write!(writer, "reply"),
        other => write!(writer, "opcode {other}"),
    }
}

fn write_claimed_hardware_addresses(
    writer: &mut impl Write,
    hardware_addresses: &[MacAddress],
) -> std::io::Result<()> {
    match hardware_addresses {
        [first, second] => write!(writer, "{first} and {second}"),
        [first, rest @ .., last] => {
            write!(writer, "{first}")?;
            for address in rest {
                write!(writer, ", {address}")?;
            }
            write!(writer, ", and {last}")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::MONITOR_DISTINCT_RECORD_LIMIT;
    use super::MonitorListenRequest;
    use super::PassiveArpAggregator;
    use super::PassiveArpClass;
    use super::classify_passive_arp;
    use super::listen_for_passive_arp;
    use super::monitor_completion_summary;
    use super::monitor_deadline;
    use super::poll_timeout_milliseconds_for_receive_wait;
    use super::write_monitor_stderr;
    use super::write_monitor_stdout;
    use crate::address_resolution_protocol::{
        ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH, ARP_OPERATION_REPLY,
        ARP_OPERATION_REQUEST, build_address_resolution_request_ethernet_frame,
    };
    use crate::error::{AppError, ScanTimingLimit};
    use crate::ethernet_frame::{
        ETHERNET_II_HEADER_LENGTH, ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IPV4,
        Ieee8021qTagControlInformation, Ieee8021qTagStack, Ieee8021qVlanIdentifier,
        encode_ethernet_ii_frame, encode_ethernet_ii_frame_with_optional_ieee_8021q_tag,
        encode_ieee_8023_rfc_1042_llc_snap_frame,
    };
    use crate::link_layer_backend::LinkLayerEndpoint;
    use crate::mac_address::MacAddress;
    use crate::scan_timing::{FakeScanClock, SystemScanClock};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    struct QueueEndpoint {
        sent: RefCell<Vec<Vec<u8>>>,
        inbound: Vec<Vec<u8>>,
    }

    impl LinkLayerEndpoint for QueueEndpoint {
        fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
            self.sent.borrow_mut().push(frame.to_vec());
            Ok(())
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Ok(!self.inbound.is_empty())
        }

        fn try_receive_ethernet_frame(
            &mut self,
            buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            if self.inbound.is_empty() {
                return Ok(None);
            }
            let frame = self.inbound.remove(0);
            let length = frame.len().min(buffer.len());
            buffer[..length].copy_from_slice(&frame[..length]);
            Ok(Some(length))
        }
    }

    struct UnusedEndpoint;

    impl LinkLayerEndpoint for UnusedEndpoint {
        fn send_ethernet_frame(&self, _frame: &[u8]) -> std::io::Result<()> {
            panic!("passive monitor must not send");
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            panic!("passive monitor must not wait after rejecting the timeout");
        }

        fn try_receive_ethernet_frame(
            &mut self,
            _buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            panic!("passive monitor must not receive after rejecting the timeout");
        }
    }

    struct ContinuousEndpoint<'a> {
        clock: &'a FakeScanClock,
        sent: RefCell<Vec<Vec<u8>>>,
        returned: Cell<u32>,
        frame: Vec<u8>,
    }

    impl LinkLayerEndpoint for ContinuousEndpoint<'_> {
        fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
            self.sent.borrow_mut().push(frame.to_vec());
            Ok(())
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Ok(true)
        }

        fn try_receive_ethernet_frame(
            &mut self,
            buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            if self.returned.get() >= 32 {
                return Ok(None);
            }
            self.clock.advance(Duration::from_millis(1));
            self.returned.set(self.returned.get().saturating_add(1));
            let length = self.frame.len().min(buffer.len());
            buffer[..length].copy_from_slice(&self.frame[..length]);
            Ok(Some(length))
        }
    }

    struct FailingWaitEndpoint {
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl LinkLayerEndpoint for FailingWaitEndpoint {
        fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
            self.sent.borrow_mut().push(frame.to_vec());
            Ok(())
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Err(AppError::PollWaitFailed {
                source: std::io::Error::other("poll failed"),
            })
        }

        fn try_receive_ethernet_frame(
            &mut self,
            _buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            panic!("a failed wait must not receive");
        }
    }

    struct FailingReceiveEndpoint;

    impl LinkLayerEndpoint for FailingReceiveEndpoint {
        fn send_ethernet_frame(&self, _frame: &[u8]) -> std::io::Result<()> {
            panic!("passive monitor must not send");
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Ok(true)
        }

        fn try_receive_ethernet_frame(
            &mut self,
            _buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            Err(AppError::RawPacketReceiveFailed {
                source: std::io::Error::other("receive failed"),
            })
        }
    }

    struct OversizedReceiveEndpoint;

    impl LinkLayerEndpoint for OversizedReceiveEndpoint {
        fn send_ethernet_frame(&self, _frame: &[u8]) -> std::io::Result<()> {
            panic!("passive monitor must not send");
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Ok(true)
        }

        fn try_receive_ethernet_frame(
            &mut self,
            _buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            Ok(Some(usize::MAX))
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn local_mac() -> MacAddress {
        MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    }

    fn other_mac(last: u8) -> MacAddress {
        MacAddress::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, last])
    }

    fn local_ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 10)
    }

    fn second_local_ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 11)
    }

    fn arp_ethernet_frame(
        opcode: u16,
        sender_hardware: MacAddress,
        sender_protocol: Ipv4Addr,
        target_hardware: MacAddress,
        target_protocol: Ipv4Addr,
    ) -> Vec<u8> {
        let mut frame = build_address_resolution_request_ethernet_frame(
            sender_hardware,
            sender_protocol,
            target_protocol,
        )
        .to_vec();
        let arp_start = ETHERNET_II_HEADER_LENGTH;
        frame[arp_start + 6..arp_start + 8].copy_from_slice(&opcode.to_be_bytes());
        frame[arp_start + 18..arp_start + 24].copy_from_slice(&target_hardware.octets());
        frame
    }

    fn run(frames: Vec<Vec<u8>>, locals: &[Ipv4Addr]) -> super::MonitorListenOutcome {
        let clock = FakeScanClock::new();
        let mut endpoint = QueueEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: frames,
        };
        let listen_request = MonitorListenRequest {
            local_ipv4_addresses: locals,
            local_mac_address: local_mac(),
            timeout: Duration::from_secs(30),
        };
        let outcome = listen_for_passive_arp(&mut endpoint, &clock, &listen_request)
            .expect("scripted passive listen should succeed");
        assert!(
            endpoint.sent.borrow().is_empty(),
            "passive monitor must not send, got: {:?}",
            endpoint.sent.borrow()
        );
        outcome
    }

    fn stdout_text(outcome: &super::MonitorListenOutcome) -> String {
        let mut buffer = Vec::new();
        write_monitor_stdout(outcome, &mut buffer).expect("vector writer should succeed");
        String::from_utf8(buffer).expect("monitor stdout is UTF-8")
    }

    fn stderr_text(outcome: &super::MonitorListenOutcome, elapsed: Duration) -> String {
        let mut buffer = Vec::new();
        write_monitor_stderr(outcome, "eth0", elapsed, &mut buffer)
            .expect("vector writer should succeed");
        String::from_utf8(buffer).expect("monitor stderr is UTF-8")
    }

    #[test]
    fn request_for_local_address_from_foreign_hardware_is_a_conflict() {
        // Arrange
        let frame = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(2),
            local_ip(),
            MacAddress::from_octets([0; 6]),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        // Act
        let outcome = run(vec![frame], &[local_ip()]);

        // Assert
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].classification, PassiveArpClass::Conflict);
        assert_eq!(outcome.records[0].opcode, ARP_OPERATION_REQUEST);
        assert_eq!(outcome.records[0].sender_hardware, other_mac(2));
        assert_eq!(outcome.records[0].sender_protocol, local_ip());
        assert_eq!(
            outcome.records[0].target_protocol,
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(outcome.records[0].count, 1);
        assert!(outcome.duplicate_ip_claims.is_empty());
        assert!(outcome.warnings.is_empty());
        assert_eq!(
            stdout_text(&outcome),
            "conflict: request 192.168.1.10 is-at 02:00:00:00:00:02 target 00:00:00:00:00:00 192.168.1.1 count 1\n"
        );
        assert_eq!(
            stderr_text(&outcome, Duration::from_millis(30)),
            "monitor complete: interface eth0, 1 conflict, 0 observations, 0 duplicate-ip claims, 30 ms\n"
        );
    }

    #[test]
    fn reply_for_local_address_from_foreign_hardware_is_a_conflict() {
        // Arrange
        let frame = arp_ethernet_frame(
            ARP_OPERATION_REPLY,
            other_mac(2),
            local_ip(),
            local_mac(),
            local_ip(),
        );

        // Act
        let outcome = run(vec![frame], &[local_ip()]);

        // Assert
        assert_eq!(outcome.records[0].classification, PassiveArpClass::Conflict);
        assert_eq!(outcome.records[0].opcode, ARP_OPERATION_REPLY);
        assert_eq!(outcome.records[0].target_hardware, local_mac());
        assert_eq!(
            stdout_text(&outcome),
            "conflict: reply 192.168.1.10 is-at 02:00:00:00:00:02 target 02:00:00:00:00:01 192.168.1.10 count 1\n"
        );
    }

    #[test]
    fn every_configured_local_address_can_conflict() {
        // Arrange
        let second = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(4),
            second_local_ip(),
            MacAddress::from_octets([0; 6]),
            Ipv4Addr::new(10, 0, 0, 1),
        );

        // Act
        let outcome = run(vec![second], &[second_local_ip(), local_ip()]);

        // Assert
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].sender_protocol, second_local_ip());
        assert_eq!(outcome.records[0].classification, PassiveArpClass::Conflict);
    }

    #[test]
    fn own_sender_hardware_and_protocol_are_suppressed() {
        // Arrange
        let frame = arp_ethernet_frame(
            ARP_OPERATION_REPLY,
            local_mac(),
            second_local_ip(),
            other_mac(9),
            Ipv4Addr::new(192, 168, 1, 50),
        );

        // Act
        let outcome = run(vec![frame], &[local_ip(), second_local_ip()]);

        // Assert
        assert!(outcome.records.is_empty());
        assert!(outcome.duplicate_ip_claims.is_empty());
        assert_eq!(stdout_text(&outcome), "no conflicts observed\n");
    }

    #[test]
    fn ordinary_nonlocal_arp_is_observed_and_not_a_conflict() {
        // Arrange
        let frame = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(9),
            Ipv4Addr::new(192, 168, 1, 50),
            MacAddress::from_octets([0; 6]),
            Ipv4Addr::new(192, 168, 1, 1),
        );

        // Act
        let outcome = run(vec![frame], &[local_ip()]);

        // Assert
        assert_eq!(outcome.records[0].classification, PassiveArpClass::Observed);
        assert!(stdout_text(&outcome).contains("no conflicts observed"));
        assert!(!stdout_text(&outcome).contains("conflict:"));
    }

    #[test]
    fn third_party_duplicate_is_labeled_separately_from_a_local_conflict() {
        // Arrange
        let shared = Ipv4Addr::new(10, 1, 2, 3);
        let frames = vec![
            arp_ethernet_frame(
                ARP_OPERATION_REPLY,
                other_mac(9),
                shared,
                local_mac(),
                local_ip(),
            ),
            arp_ethernet_frame(
                ARP_OPERATION_REQUEST,
                other_mac(2),
                shared,
                MacAddress::from_octets([0; 6]),
                local_ip(),
            ),
            arp_ethernet_frame(
                ARP_OPERATION_REPLY,
                other_mac(4),
                shared,
                other_mac(2),
                shared,
            ),
        ];

        // Act
        let outcome = run(frames, &[local_ip()]);

        // Assert
        assert_eq!(outcome.records.len(), 3);
        assert!(
            outcome
                .records
                .iter()
                .all(|record| record.classification == PassiveArpClass::Observed)
        );
        assert_eq!(outcome.duplicate_ip_claims.len(), 1);
        assert_eq!(outcome.duplicate_ip_claims[0].protocol_address, shared);
        assert_eq!(
            outcome.duplicate_ip_claims[0].hardware_addresses,
            vec![other_mac(2), other_mac(4), other_mac(9)]
        );
        let text = stdout_text(&outcome);
        assert!(
            text.contains(
                "duplicate-ip: 10.1.2.3 claimed by 02:00:00:00:00:02, 02:00:00:00:00:04, and 02:00:00:00:00:09 count 3\n"
            ),
            "duplicate claim should list hardware addresses in order, got: {text}"
        );
        assert!(
            text.ends_with("no conflicts observed\n"),
            "ordinary observations are not local conflicts, got: {text}"
        );
        assert_eq!(
            stderr_text(&outcome, Duration::from_millis(1)),
            "monitor complete: interface eth0, 0 conflicts, 3 observations, 1 duplicate-ip claim, 1 ms\n"
        );
    }

    #[test]
    fn duplicate_line_joins_two_hardware_addresses_with_and() {
        // Arrange
        let outcome = super::MonitorListenOutcome {
            records: vec![],
            duplicate_ip_claims: vec![super::DuplicateIpClaim {
                protocol_address: Ipv4Addr::new(10, 1, 2, 3),
                hardware_addresses: vec![other_mac(2), other_mac(9)],
            }],
            warnings: vec![],
        };

        // Act
        let text = stdout_text(&outcome);

        // Assert
        assert_eq!(
            text,
            "duplicate-ip: 10.1.2.3 claimed by 02:00:00:00:00:02 and 02:00:00:00:00:09 count 2\nno conflicts observed\n"
        );
    }

    #[test]
    fn local_conflicts_and_unspecified_senders_are_not_duplicate_claims() {
        // Arrange
        let frames = vec![
            arp_ethernet_frame(
                ARP_OPERATION_REQUEST,
                other_mac(2),
                local_ip(),
                MacAddress::from_octets([0; 6]),
                Ipv4Addr::new(192, 168, 1, 1),
            ),
            arp_ethernet_frame(
                ARP_OPERATION_REPLY,
                other_mac(4),
                local_ip(),
                local_mac(),
                local_ip(),
            ),
            arp_ethernet_frame(
                ARP_OPERATION_REQUEST,
                other_mac(2),
                Ipv4Addr::UNSPECIFIED,
                MacAddress::from_octets([0; 6]),
                local_ip(),
            ),
            arp_ethernet_frame(
                ARP_OPERATION_REQUEST,
                other_mac(4),
                Ipv4Addr::UNSPECIFIED,
                MacAddress::from_octets([0; 6]),
                local_ip(),
            ),
        ];

        // Act
        let outcome = run(frames, &[local_ip()]);

        // Assert
        assert_eq!(
            outcome
                .records
                .iter()
                .filter(|record| record.classification == PassiveArpClass::Conflict)
                .count(),
            2
        );
        assert!(outcome.duplicate_ip_claims.is_empty());
        assert!(!stdout_text(&outcome).contains("duplicate-ip:"));
        assert!(!stdout_text(&outcome).contains("no conflicts observed"));
    }

    #[test]
    fn repeated_packets_saturate_and_rarp_is_not_a_local_conflict() {
        // Arrange
        let repeated = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(2),
            local_ip(),
            MacAddress::from_octets([0; 6]),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        let rarp = arp_ethernet_frame(3, other_mac(8), local_ip(), local_mac(), local_ip());

        // Act
        let outcome = run(vec![repeated.clone(), repeated, rarp], &[local_ip()]);

        // Assert
        assert_eq!(outcome.records[0].count, 2);
        assert_eq!(outcome.records[0].classification, PassiveArpClass::Conflict);
        assert_eq!(outcome.records[1].classification, PassiveArpClass::Observed);
        assert_eq!(outcome.records[1].opcode, 3);
        assert!(stdout_text(&outcome).contains("observed: opcode 3 "));
    }

    #[test]
    fn malformed_arp_is_warned_and_unrelated_frames_are_silent() {
        // Arrange
        let short = encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            other_mac(2),
            ETHERNET_PROTOCOL_ARP,
            &[0u8; 10],
        );
        let reserved = arp_ethernet_frame(
            0,
            other_mac(2),
            local_ip(),
            MacAddress::from_octets([0; 6]),
            local_ip(),
        );
        let reserved_again = arp_ethernet_frame(
            u16::MAX,
            other_mac(2),
            local_ip(),
            MacAddress::from_octets([0; 6]),
            local_ip(),
        );
        let ipv4 = encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            other_mac(2),
            ETHERNET_PROTOCOL_IPV4,
            &[0u8; 20],
        );

        // Act
        let outcome = run(
            vec![short, vec![0u8; 4], ipv4, reserved, reserved_again],
            &[local_ip()],
        );

        // Assert
        assert!(outcome.records.is_empty());
        assert_eq!(
            outcome.warnings,
            vec![
                "received malformed Ethernet/ARP frame: address resolution payload is shorter than IPv4 over Ethernet".to_string(),
                "received malformed Ethernet/ARP frame: address resolution opcode is reserved by RFC 5494 (2 occurrences)".to_string(),
            ]
        );
        assert!(stderr_text(&outcome, Duration::ZERO).starts_with("warning: "));
    }

    #[test]
    fn tagged_and_snap_frames_use_the_existing_parser() {
        // Arrange
        let plain = arp_ethernet_frame(
            ARP_OPERATION_REPLY,
            other_mac(2),
            local_ip(),
            local_mac(),
            second_local_ip(),
        );
        let payload = plain[ETHERNET_II_HEADER_LENGTH
            ..ETHERNET_II_HEADER_LENGTH + ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH]
            .to_vec();
        let customer = Ieee8021qTagControlInformation::from_vlan_identifier(
            Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits"),
        );
        let service = Ieee8021qTagControlInformation::from_vlan_identifier(
            Ieee8021qVlanIdentifier::new(100).expect("VID 100 fits"),
        );
        let tagged = encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
            MacAddress::BROADCAST,
            other_mac(2),
            Some(Ieee8021qTagStack::Customer(customer)),
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );
        let stacked = encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
            MacAddress::BROADCAST,
            other_mac(2),
            Some(Ieee8021qTagStack::ServiceAndCustomer { service, customer }),
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );
        let snap = encode_ieee_8023_rfc_1042_llc_snap_frame(
            MacAddress::BROADCAST,
            other_mac(2),
            None,
            ETHERNET_PROTOCOL_ARP,
            &payload,
        );

        // Act
        let outcome = run(vec![tagged, stacked, snap], &[local_ip()]);

        // Assert
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].count, 3);
        assert_eq!(outcome.records[0].classification, PassiveArpClass::Conflict);
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn continuous_input_stops_at_the_deadline_without_sending() {
        // Arrange
        let clock = FakeScanClock::new();
        let frame = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(2),
            Ipv4Addr::new(10, 0, 0, 8),
            MacAddress::from_octets([0; 6]),
            local_ip(),
        );
        let mut endpoint = ContinuousEndpoint {
            clock: &clock,
            sent: RefCell::new(Vec::new()),
            returned: Cell::new(0),
            frame,
        };
        let listen_request = MonitorListenRequest {
            local_ipv4_addresses: &[local_ip()],
            local_mac_address: local_mac(),
            timeout: Duration::from_millis(5),
        };

        // Act
        let outcome = listen_for_passive_arp(&mut endpoint, &clock, &listen_request)
            .expect("continuous input should still finish");

        // Assert
        assert_eq!(endpoint.returned.get(), 5);
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].count, 5);
        assert!(endpoint.sent.borrow().is_empty());
    }

    #[test]
    fn empty_listen_advances_the_fake_clock_and_reports_no_conflicts() {
        // Arrange
        let clock = FakeScanClock::new();
        let mut endpoint = QueueEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let listen_request = MonitorListenRequest {
            local_ipv4_addresses: &[local_ip()],
            local_mac_address: local_mac(),
            timeout: Duration::from_millis(10),
        };

        // Act
        let outcome = listen_for_passive_arp(&mut endpoint, &clock, &listen_request)
            .expect("an empty listen should succeed");

        // Assert
        assert_eq!(clock.unreadable_waits(), vec![Duration::from_millis(10)]);
        assert_eq!(stdout_text(&outcome), "no conflicts observed\n");
        assert!(endpoint.sent.borrow().is_empty());
    }

    #[test]
    fn zero_timeout_and_unrepresentable_deadline_do_not_touch_the_endpoint() {
        // Arrange
        let clock = FakeScanClock::new();
        let mut endpoint = UnusedEndpoint;
        let locals = [local_ip()];
        let mut listen_request = MonitorListenRequest {
            local_ipv4_addresses: &locals,
            local_mac_address: local_mac(),
            timeout: Duration::ZERO,
        };

        // Act
        let zero = listen_for_passive_arp(&mut endpoint, &clock, &listen_request);
        clock.set_nanos(u128::MAX);
        listen_request.timeout = Duration::from_nanos(1);
        let overflow = listen_for_passive_arp(&mut endpoint, &clock, &listen_request);
        let system_overflow = monitor_deadline(&SystemScanClock, Duration::MAX);

        // Assert
        assert!(matches!(zero, Err(AppError::MonitorTimeoutRejected)));
        assert!(matches!(
            overflow,
            Err(AppError::ScanTimingExceedsLimit {
                limit: ScanTimingLimit::MonotonicDeadline
            })
        ));
        assert!(matches!(
            system_overflow,
            Err(AppError::ScanTimingExceedsLimit {
                limit: ScanTimingLimit::MonotonicDeadline
            })
        ));
    }

    #[test]
    fn poll_receive_and_oversize_failures_propagate() {
        // Arrange
        let clock = FakeScanClock::new();
        let listen_request = MonitorListenRequest {
            local_ipv4_addresses: &[local_ip()],
            local_mac_address: local_mac(),
            timeout: Duration::from_millis(5),
        };
        let mut waiting = FailingWaitEndpoint {
            sent: RefCell::new(Vec::new()),
        };
        let mut receiving = FailingReceiveEndpoint;
        let mut oversized = OversizedReceiveEndpoint;

        // Act
        let poll_error = listen_for_passive_arp(&mut waiting, &clock, &listen_request);
        let receive_error = listen_for_passive_arp(&mut receiving, &clock, &listen_request);
        let oversize_error = listen_for_passive_arp(&mut oversized, &clock, &listen_request);

        // Assert
        assert!(matches!(poll_error, Err(AppError::PollWaitFailed { .. })));
        assert!(waiting.sent.borrow().is_empty());
        assert!(matches!(
            receive_error,
            Err(AppError::RawPacketReceiveFailed { .. })
        ));
        assert!(matches!(
            oversize_error,
            Err(AppError::RawPacketReceiveFailed { .. })
        ));
    }

    #[test]
    fn repeat_count_saturates_and_a_full_table_drops_new_identities() {
        // Arrange
        let frame = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(2),
            Ipv4Addr::new(10, 0, 0, 8),
            MacAddress::from_octets([0; 6]),
            local_ip(),
        );
        let second = arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(4),
            Ipv4Addr::new(10, 0, 0, 8),
            MacAddress::from_octets([0; 6]),
            local_ip(),
        );
        let mut aggregator = PassiveArpAggregator::new(local_mac(), &[local_ip()], 1);

        // Act
        aggregator.observe(&frame);
        aggregator.records[0].count = u64::MAX;
        aggregator.observe(&frame);
        aggregator.observe(&second);
        let outcome = aggregator.finish();

        // Assert
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].count, u64::MAX);
        assert!(outcome.duplicate_ip_claims.is_empty());
        assert_eq!(
            outcome.warnings,
            vec![super::PASSIVE_MONITOR_TRUNCATION_WARNING.to_string()]
        );
    }

    #[test]
    fn listen_caps_distinct_records_at_the_documented_limit() {
        // Arrange
        let limit = u32::try_from(MONITOR_DISTINCT_RECORD_LIMIT).expect("limit fits u32");
        let mut frames = Vec::with_capacity(usize::try_from(limit).expect("limit fits usize") + 2);
        for host in 1..=limit {
            frames.push(arp_ethernet_frame(
                ARP_OPERATION_REQUEST,
                other_mac(2),
                Ipv4Addr::from(host),
                MacAddress::from_octets([0; 6]),
                local_ip(),
            ));
        }
        let overflow_address = Ipv4Addr::from(limit.saturating_add(1));
        frames.push(arp_ethernet_frame(
            ARP_OPERATION_REQUEST,
            other_mac(2),
            overflow_address,
            MacAddress::from_octets([0; 6]),
            local_ip(),
        ));
        frames.push(frames[0].clone());

        // Act
        let outcome = run(frames, &[local_ip()]);

        // Assert
        assert_eq!(outcome.records.len(), MONITOR_DISTINCT_RECORD_LIMIT);
        assert_eq!(outcome.records[0].count, 2);
        assert!(
            !outcome
                .records
                .iter()
                .any(|record| record.sender_protocol == overflow_address)
        );
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(
            outcome.warnings[0],
            super::PASSIVE_MONITOR_TRUNCATION_WARNING
        );
    }

    #[test]
    fn poll_timeout_clamps_to_c_int_max() {
        // Arrange
        let huge = Duration::from_millis(u64::MAX);

        // Act
        let timeout = poll_timeout_milliseconds_for_receive_wait(huge);

        // Assert
        assert_eq!(timeout, libc::c_int::MAX);
    }

    #[test]
    fn summary_uses_singular_plurals_and_saturating_milliseconds() {
        // Arrange
        let outcome = super::MonitorListenOutcome {
            records: vec![],
            duplicate_ip_claims: vec![],
            warnings: vec!["received malformed Ethernet/ARP frame: fixture".to_string()],
        };

        // Act
        let empty = monitor_completion_summary("eth0", &outcome, Duration::from_micros(500));
        let saturated = monitor_completion_summary("narp_long_name", &outcome, Duration::MAX);
        let stderr = stderr_text(&outcome, Duration::from_micros(500));

        // Assert
        assert_eq!(
            empty,
            "monitor complete: interface eth0, 0 conflicts, 0 observations, 0 duplicate-ip claims, 0 ms"
        );
        assert!(saturated.contains(&format!("{} ms", u64::MAX)));
        assert!(saturated.contains("narp_long_name"));
        assert_eq!(
            stderr,
            format!("warning: received malformed Ethernet/ARP frame: fixture\n{empty}\n")
        );
    }

    #[test]
    fn writers_propagate_io_errors() {
        // Arrange
        let outcome = super::MonitorListenOutcome {
            records: vec![],
            duplicate_ip_claims: vec![],
            warnings: vec![],
        };
        let mut writer = FailingWriter;

        // Act
        let stdout_error = write_monitor_stdout(&outcome, &mut writer);
        let stderr_error = write_monitor_stderr(&outcome, "eth0", Duration::ZERO, &mut writer);

        // Assert
        assert!(stdout_error.is_err());
        assert!(stderr_error.is_err());
    }

    proptest::proptest! {
        #[test]
        fn classification_matches_the_local_conflict_predicate(
            opcode in proptest::num::u16::ANY,
            spa in proptest::array::uniform4(proptest::num::u8::ANY),
            sha in proptest::array::uniform6(proptest::num::u8::ANY),
        ) {
            let locals = BTreeSet::from([local_ip(), second_local_ip()]);
            let sender_protocol = Ipv4Addr::from(spa);
            let sender_hardware = MacAddress::from_octets(sha);
            let class = classify_passive_arp(
                opcode,
                sender_hardware,
                sender_protocol,
                local_mac(),
                &locals,
            );
            let sender_protocol_is_local = locals.contains(&sender_protocol);
            let suppressed = sender_hardware == local_mac() && sender_protocol_is_local;
            let expected = if suppressed {
                None
            } else if sender_protocol_is_local
                && (opcode == ARP_OPERATION_REQUEST || opcode == ARP_OPERATION_REPLY)
            {
                Some(PassiveArpClass::Conflict)
            } else {
                Some(PassiveArpClass::Observed)
            };
            proptest::prop_assert_eq!(class, expected);
        }
    }
}
