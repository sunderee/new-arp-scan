//! Portable address resolution scan orchestration.
//!
//! Target expansion, send rounds with inter-round pacing, the bounded receive phase, duplicate
//! reply merging, and warning collection are all platform-neutral. They are parameterized over the
//! [`LinkLayerEndpoint`] backend, so Linux (`AF_PACKET`) and macOS (Berkeley Packet Filter) share
//! one scan engine and only differ in interface discovery and raw frame input/output.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::scan_timing::{
    ScanClock, ScheduledRateLimit, retry_receive_window, validate_scan_timing_before_socket,
};

use crate::address_resolution_protocol::{
    ARP_OPERATION_REPLY, encode_address_resolution_request_from_layout,
    try_parse_address_resolution_ipv4_over_ethernet,
};
use crate::application_command::{RateLimitedScanTiming, ScanWireOptions};
use crate::application_outcome::{DiscoveredHost, ScanOutcome};
use crate::error::AppError;
use crate::ethernet_frame::{ETHERNET_PROTOCOL_ARP, try_parse_ethernet_frame};
use crate::ipv4_cidr::Ipv4HostAddressIterator;
use crate::ipv4_subnet::ipv4_address_is_strictly_inside_subnet;
use crate::link_layer_backend::{InterfaceScanAddresses, LinkLayerEndpoint};
use crate::mac_address::MacAddress;

/// Converts remaining receive time to a `poll(2)` timeout in whole milliseconds, clamped to
/// [`libc::c_int::MAX`] when the span does not fit the system call parameter type.
fn poll_timeout_milliseconds_for_receive_wait(remaining: Duration) -> libc::c_int {
    let milliseconds = remaining.as_millis();
    libc::c_int::try_from(milliseconds).unwrap_or(libc::c_int::MAX)
}

/// Builds the ordered list of IPv4 targets: interior hosts from the iterator, then the interface
/// address when it is not strictly inside the open `(network, broadcast)` interval.
fn ipv4_scan_target_address_sequence(
    interior_host_addresses: impl Iterator<Item = Ipv4Addr>,
    source_ipv4_address: Ipv4Addr,
    network_bits: u32,
    broadcast_bits: u32,
) -> Vec<Ipv4Addr> {
    let mut targets: Vec<Ipv4Addr> = interior_host_addresses.collect();
    if !ipv4_address_is_strictly_inside_subnet(source_ipv4_address, network_bits, broadcast_bits) {
        targets.push(source_ipv4_address);
    }
    targets
}

/// Returns whether inter-round pacing should run after the round at `round_index` (zero-based).
fn should_apply_pacing_after_scan_round(
    round_index: u64,
    total_rounds: u64,
    pacing_between_scan_rounds: Duration,
) -> bool {
    !pacing_between_scan_rounds.is_zero() && round_index.saturating_add(1) < total_rounds
}

/// Returns how many address resolution requests are sent for `target_count` targets over
/// `scan_round_count` full rounds, or [`None`] when the product does not fit [`u64`].
#[cfg(test)]
fn total_address_resolution_request_send_count(
    target_count: usize,
    scan_round_count: NonZeroU64,
) -> Option<u64> {
    let target_count_u64 = u64::try_from(target_count).ok()?;
    target_count_u64.checked_mul(scan_round_count.get())
}

/// Counts inter-round pacing sleeps implied by [`should_apply_pacing_after_scan_round`] for every
/// zero-based round index in a scan.
#[cfg(test)]
fn inter_round_sleep_count_for_scan_schedule(
    total_rounds: u64,
    pacing_between_scan_rounds: Duration,
) -> u64 {
    if pacing_between_scan_rounds.is_zero() || total_rounds <= 1 {
        return 0;
    }
    total_rounds - 1
}

/// Inserts or merges a sender IPv4 and Ethernet address from a parsed address resolution reply.
///
/// The first media access control address wins; later replies with a different address for the
/// same IPv4 produce a warning and are ignored.
fn merge_address_resolution_reply_sender_into_discovered_hosts(
    discovered_hosts: &mut BTreeMap<Ipv4Addr, MacAddress>,
    ipv4_address: Ipv4Addr,
    media_access_control_address: MacAddress,
    warnings: &mut Vec<String>,
) {
    match discovered_hosts.entry(ipv4_address) {
        Entry::Vacant(entry) => {
            entry.insert(media_access_control_address);
        }
        Entry::Occupied(entry) => {
            let stored = *entry.get();
            if stored != media_access_control_address {
                warnings.push(format!(
                    "conflicting address resolution reply for {ipv4_address}: keeping {stored}, ignoring {media_access_control_address}"
                ));
            }
        }
    }
}

fn ipv4_sender_is_probed_target(
    sender_ipv4_address: Ipv4Addr,
    source_ipv4_address: Ipv4Addr,
    network_bits: u32,
    broadcast_bits: u32,
) -> bool {
    sender_ipv4_address == source_ipv4_address
        || ipv4_address_is_strictly_inside_subnet(sender_ipv4_address, network_bits, broadcast_bits)
}

/// Selects which address resolution reply senders are recorded during a receive phase.
#[derive(Debug)]
pub(crate) enum ArpReplyAcceptance {
    /// Accept the interface address and any strictly interior subnet senders (full-subnet scan).
    SubnetScope {
        source_ipv4_address: Ipv4Addr,
        network_bits: u32,
        broadcast_bits: u32,
    },
    /// Accept only replies whose sender IPv4 equals the probed target.
    ExactTarget { target_ipv4_address: Ipv4Addr },
}

impl ArpReplyAcceptance {
    fn accepts_sender_ipv4_address(&self, sender_ipv4_address: Ipv4Addr) -> bool {
        match self {
            ArpReplyAcceptance::SubnetScope {
                source_ipv4_address,
                network_bits,
                broadcast_bits,
            } => ipv4_sender_is_probed_target(
                sender_ipv4_address,
                *source_ipv4_address,
                *network_bits,
                *broadcast_bits,
            ),
            ArpReplyAcceptance::ExactTarget {
                target_ipv4_address,
            } => sender_ipv4_address == *target_ipv4_address,
        }
    }
}

/// MAC, interface IPv4, and on-wire options used when sending ARP requests.
#[derive(Clone)]
pub(crate) struct ScanTransmitContext {
    /// Scanning interface Ethernet address (`ar$sha`).
    pub source_mac_address: MacAddress,
    /// Scanning interface IPv4 address, used when [`ScanWireOptions::sender_protocol_address`] is
    /// [`crate::application_command::ArpSenderProtocolAddress::Interface`].
    pub interface_ipv4_address: Ipv4Addr,
    /// VLAN tag, `ar$spa` override, LLC/SNAP framing, and Ethernet/ARP field overrides.
    pub wire: ScanWireOptions,
}

fn run_address_resolution_request_rounds(
    endpoint: &impl LinkLayerEndpoint,
    target_ipv4_addresses: &[Ipv4Addr],
    transmit: &ScanTransmitContext,
    scan_round_count: NonZeroU64,
    pacing_between_scan_rounds: Duration,
    clock: &impl ScanClock,
    warnings: &mut Vec<String>,
) {
    let total_rounds = scan_round_count.get();
    for round_index in 0..total_rounds {
        for target_ipv4_address in target_ipv4_addresses {
            send_one_address_resolution_request(endpoint, transmit, *target_ipv4_address, warnings);
        }
        if should_apply_pacing_after_scan_round(
            round_index,
            total_rounds,
            pacing_between_scan_rounds,
        ) {
            clock.sleep_for(pacing_between_scan_rounds);
        }
    }
}

fn send_one_address_resolution_request(
    endpoint: &impl LinkLayerEndpoint,
    transmit: &ScanTransmitContext,
    target_ipv4_address: Ipv4Addr,
    warnings: &mut Vec<String>,
) {
    let sender_protocol_address = transmit
        .wire
        .sender_protocol_address
        .ipv4_address_for_target(transmit.interface_ipv4_address, target_ipv4_address);
    let layout = transmit.wire.address_resolution_request_layout(
        transmit.source_mac_address,
        sender_protocol_address,
        target_ipv4_address,
    );
    let frame = encode_address_resolution_request_from_layout(layout);
    if let Err(source) = endpoint.send_ethernet_frame(&frame) {
        warnings.push(format!(
            "failed to send ARP request to {target_ipv4_address}: {source}"
        ));
    }
}

fn collect_address_resolution_replies_until_clock_deadline<E, C>(
    endpoint: &mut E,
    receive_buffer: &mut [u8],
    deadline: C::Timestamp,
    clock: &C,
    reply_acceptance: &ArpReplyAcceptance,
    warnings: &mut Vec<String>,
) -> Result<BTreeMap<Ipv4Addr, MacAddress>, AppError>
where
    E: LinkLayerEndpoint,
    C: ScanClock,
{
    let mut discovered_hosts: BTreeMap<Ipv4Addr, MacAddress> = BTreeMap::new();
    while clock.now() < deadline {
        let remaining = clock.saturating_duration_since(deadline, clock.now());
        if remaining.is_zero() {
            break;
        }
        let timeout_milliseconds = poll_timeout_milliseconds_for_receive_wait(remaining);
        if endpoint.wait_until_readable(timeout_milliseconds)? {
            drain_buffered_reply_frames(
                endpoint,
                receive_buffer,
                reply_acceptance,
                &mut discovered_hosts,
                warnings,
            )?;
        } else {
            clock.advance_after_unreadable_wait(remaining);
        }
    }
    Ok(discovered_hosts)
}

fn drain_buffered_reply_frames(
    endpoint: &mut impl LinkLayerEndpoint,
    receive_buffer: &mut [u8],
    reply_acceptance: &ArpReplyAcceptance,
    discovered_hosts: &mut BTreeMap<Ipv4Addr, MacAddress>,
    warnings: &mut Vec<String>,
) -> Result<(), AppError> {
    while let Some(bytes_received) = endpoint.try_receive_ethernet_frame(receive_buffer)? {
        let frame_slice = &receive_buffer[..bytes_received];
        if ethernet_frame_is_not_address_resolution_protocol(frame_slice) {
            continue;
        }
        match try_parse_address_resolution_ipv4_over_ethernet(frame_slice) {
            Ok(parsed) if parsed.opcode == ARP_OPERATION_REPLY => {
                if reply_acceptance.accepts_sender_ipv4_address(parsed.sender_protocol) {
                    merge_address_resolution_reply_sender_into_discovered_hosts(
                        discovered_hosts,
                        parsed.sender_protocol,
                        parsed.sender_hardware,
                        warnings,
                    );
                }
            }
            Ok(_) => {
                // Well-formed ARP that is not a reply (request, RARP, and so on) is expected LAN
                // noise, including possible copies of our own requests. It is not a malformation.
            }
            Err(reason) => {
                warnings.push(format!("received malformed Ethernet/ARP frame: {reason}"));
            }
        }
    }

    Ok(())
}

/// Returns whether `frame_slice` is Ethernet that is not IPv4 ARP (including frames that cannot be
/// parsed as Ethernet). Those arrivals are expected when the capture socket is bound to every
/// protocol, and they are not operator-facing malformation warnings. Well-formed ARP that is not a
/// reply is filtered after this check and is also not treated as malformed.
fn ethernet_frame_is_not_address_resolution_protocol(frame_slice: &[u8]) -> bool {
    match try_parse_ethernet_frame(frame_slice) {
        Ok(parsed) => parsed.ether_type != ETHERNET_PROTOCOL_ARP,
        Err(_) => true,
    }
}

/// The ordered target list and reply-acceptance rule for a full-subnet scan.
#[derive(Debug)]
pub(crate) struct SubnetScanPlan {
    /// Targets to probe, interior hosts first, then the interface address when it lies on an edge.
    pub targets: Vec<Ipv4Addr>,
    /// Reply acceptance scoped to the interface subnet.
    pub acceptance: ArpReplyAcceptance,
}

/// Validates the interface subnet and builds the full-subnet scan plan.
///
/// This is the portable, pre-socket step: callers run it before opening a link-layer endpoint so a
/// subnet that cannot be scanned (for example `/31` or `/32`) is rejected first.
///
/// # Errors
///
/// Returns [`AppError::Ipv4NetmaskInvalid`] or [`AppError::Ipv4SubnetUnsupported`] when the
/// interface subnet cannot be scanned.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn full_subnet_scan_plan(
    addresses: &InterfaceScanAddresses,
) -> Result<SubnetScanPlan, AppError> {
    let host_address_iterator = Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(
        addresses.source_ipv4_address,
        addresses.ipv4_netmask,
    )?;

    let mask_bits = addresses.ipv4_netmask.to_bits();
    let network_bits = addresses.source_ipv4_address.to_bits() & mask_bits;
    let broadcast_bits = network_bits | !mask_bits;

    let targets = ipv4_scan_target_address_sequence(
        host_address_iterator,
        addresses.source_ipv4_address,
        network_bits,
        broadcast_bits,
    );

    Ok(SubnetScanPlan {
        targets,
        acceptance: ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: addresses.source_ipv4_address,
            network_bits,
            broadcast_bits,
        },
    })
}

/// Sends the request rounds and collects replies on an already-open `endpoint`, returning the
/// discovered hosts and any warnings.
///
/// `transmit` is the scanning interface MAC/IPv4 plus on-wire options (VLAN, `ar$spa`, LLC/SNAP). `acceptance` decides which
/// reply senders are recorded (full subnet versus a single probed target). The timing parameters
/// match the public scan contract: `receive_timeout_after_last_request` bounds the receive phase
/// after the final round, `pacing_between_scan_rounds` sleeps after each round except the last, and
/// `scan_round_count` is the number of rounds.
///
/// # Errors
///
/// Returns [`AppError`] when the receive poll loop fails fatally.
///
/// # Panics
///
/// This function does not panic.
/// Targets, timing, and optional outbound rate for one scan over an already-open endpoint.
pub(crate) struct EndpointScanRequest<'a> {
    /// IPv4 addresses to probe, in send order.
    pub targets: &'a [Ipv4Addr],
    /// Source MAC, interface IPv4, and on-wire options.
    pub transmit: &'a ScanTransmitContext,
    /// Which reply senders are recorded.
    pub acceptance: &'a ArpReplyAcceptance,
    /// Base receive window. On the burst path this follows the last round; on the rate-limited
    /// path it is the round-zero window before backoff.
    pub receive_timeout_after_last_request: Duration,
    /// Extra delay between rounds, added after the rate-limited inter-send deadline.
    pub pacing_between_scan_rounds: Duration,
    /// How many send rounds to plan.
    pub scan_round_count: NonZeroU64,
    /// `None` keeps burst-within-round sends.
    pub rate_limit: Option<RateLimitedScanTiming>,
}

#[cfg(test)]
pub(crate) fn collect_scan_over_endpoint(
    endpoint: &mut impl LinkLayerEndpoint,
    target_ipv4_addresses: &[Ipv4Addr],
    transmit: &ScanTransmitContext,
    acceptance: &ArpReplyAcceptance,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
) -> Result<ScanOutcome, AppError> {
    collect_scan_over_endpoint_with_rate_and_clock(
        endpoint,
        &EndpointScanRequest {
            targets: target_ipv4_addresses,
            transmit,
            acceptance,
            receive_timeout_after_last_request,
            pacing_between_scan_rounds,
            scan_round_count,
            rate_limit: None,
        },
        &crate::scan_timing::SystemScanClock,
    )
}

pub(crate) fn collect_scan_over_endpoint_with_rate_and_clock<E, C>(
    endpoint: &mut E,
    request: &EndpointScanRequest<'_>,
    clock: &C,
) -> Result<ScanOutcome, AppError>
where
    E: LinkLayerEndpoint,
    C: ScanClock,
{
    request.transmit.wire.validate_ieee_8021q_tag_stack()?;
    request.transmit.wire.validate_ieee_8023_mac_client_data()?;
    let scheduled_rate = validate_scan_timing_before_socket(
        request.receive_timeout_after_last_request,
        request.pacing_between_scan_rounds,
        request.scan_round_count,
        &request.transmit.wire,
        request.rate_limit,
    )?;
    let mut warnings = Vec::new();
    let mut receive_buffer = [0u8; 4096];

    let discovered_hosts = if let Some(scheduled_rate) = scheduled_rate {
        run_rate_limited_rounds(
            endpoint,
            request,
            &scheduled_rate,
            clock,
            &mut receive_buffer,
            &mut warnings,
        )?
    } else {
        run_address_resolution_request_rounds(
            endpoint,
            request.targets,
            request.transmit,
            request.scan_round_count,
            request.pacing_between_scan_rounds,
            clock,
            &mut warnings,
        );
        let deadline = clock
            .checked_add(clock.now(), request.receive_timeout_after_last_request)
            .ok_or(AppError::ScanTimingExceedsLimit {
                limit: crate::error::ScanTimingLimit::MonotonicDeadline,
            })?;
        collect_address_resolution_replies_until_clock_deadline(
            endpoint,
            &mut receive_buffer,
            deadline,
            clock,
            request.acceptance,
            &mut warnings,
        )?
    };

    let hosts: Vec<DiscoveredHost> = discovered_hosts
        .into_iter()
        .map(
            |(ipv4_address, media_access_control_address)| DiscoveredHost {
                ipv4_address,
                media_access_control_address,
            },
        )
        .collect();

    Ok(ScanOutcome {
        discovered_hosts: hosts,
        warnings,
        timing_summary: None,
    })
}

/// Positional adapter so scripted tests can pass timing fields without building a request value.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn collect_scripted_scan<E, C>(
    endpoint: &mut E,
    targets: &[Ipv4Addr],
    transmit: &ScanTransmitContext,
    acceptance: &ArpReplyAcceptance,
    receive_timeout_after_last_request: Duration,
    pacing_between_scan_rounds: Duration,
    scan_round_count: NonZeroU64,
    rate_limit: Option<RateLimitedScanTiming>,
    clock: &C,
) -> Result<ScanOutcome, AppError>
where
    E: LinkLayerEndpoint,
    C: ScanClock,
{
    collect_scan_over_endpoint_with_rate_and_clock(
        endpoint,
        &EndpointScanRequest {
            targets,
            transmit,
            acceptance,
            receive_timeout_after_last_request,
            pacing_between_scan_rounds,
            scan_round_count,
            rate_limit,
        },
        clock,
    )
}

fn run_rate_limited_rounds<E, C>(
    endpoint: &mut E,
    request: &EndpointScanRequest<'_>,
    scheduled_rate: &ScheduledRateLimit,
    clock: &C,
    receive_buffer: &mut [u8],
    warnings: &mut Vec<String>,
) -> Result<BTreeMap<Ipv4Addr, MacAddress>, AppError>
where
    E: LinkLayerEndpoint,
    C: ScanClock,
{
    if request.targets.is_empty() {
        let deadline = monotonic_deadline(clock, request.receive_timeout_after_last_request)?;
        return collect_address_resolution_replies_until_clock_deadline(
            endpoint,
            receive_buffer,
            deadline,
            clock,
            request.acceptance,
            warnings,
        );
    }

    let mut unanswered_targets = request.targets.to_vec();
    let mut discovered_hosts = BTreeMap::new();
    let mut last_send: Option<C::Timestamp> = None;
    let total_rounds = request.scan_round_count.get();

    for round_index in 0..total_rounds {
        if unanswered_targets.is_empty() {
            break;
        }
        for (index, target_ipv4_address) in unanswered_targets.iter().copied().enumerate() {
            if index > 0 {
                wait_until_interval_after_last_send(clock, last_send, scheduled_rate.interval)?;
            }
            send_one_address_resolution_request(
                endpoint,
                request.transmit,
                target_ipv4_address,
                warnings,
            );
            clock.after_send();
            last_send = Some(clock.now());
        }

        let receive_window = retry_receive_window(
            request.receive_timeout_after_last_request,
            scheduled_rate.backoff_factor,
            round_index,
        )?;
        let receive_deadline = monotonic_deadline(clock, receive_window)?;
        let round_hosts = collect_address_resolution_replies_until_clock_deadline(
            endpoint,
            receive_buffer,
            receive_deadline,
            clock,
            request.acceptance,
            warnings,
        )?;
        merge_discovered_host_maps(&mut discovered_hosts, round_hosts, warnings);
        unanswered_targets
            .retain(|target_ipv4_address| !discovered_hosts.contains_key(target_ipv4_address));
        if unanswered_targets.is_empty() {
            break;
        }
        if round_index.saturating_add(1) < total_rounds {
            wait_until_next_round(
                clock,
                last_send,
                scheduled_rate.interval,
                request.pacing_between_scan_rounds,
            )?;
        }
    }

    Ok(discovered_hosts)
}

fn wait_until_interval_after_last_send<C: ScanClock>(
    clock: &C,
    last_send: Option<C::Timestamp>,
    interval: Duration,
) -> Result<(), AppError> {
    let Some(last_send) = last_send else {
        return Ok(());
    };
    let earliest = monotonic_deadline_from(clock, last_send, interval)?;
    clock.sleep_until(earliest);
    Ok(())
}

fn wait_until_next_round<C: ScanClock>(
    clock: &C,
    last_send: Option<C::Timestamp>,
    interval: Duration,
    pacing_between_scan_rounds: Duration,
) -> Result<(), AppError> {
    let Some(last_send) = last_send else {
        return Ok(());
    };
    let inter_send_deadline = monotonic_deadline_from(clock, last_send, interval)?;
    let baseline = inter_send_deadline.max(clock.now());
    let next_round = monotonic_deadline_from(clock, baseline, pacing_between_scan_rounds)?;
    clock.sleep_until(next_round);
    Ok(())
}

fn monotonic_deadline<C: ScanClock>(
    clock: &C,
    duration: Duration,
) -> Result<C::Timestamp, AppError> {
    monotonic_deadline_from(clock, clock.now(), duration)
}

fn monotonic_deadline_from<C: ScanClock>(
    clock: &C,
    timestamp: C::Timestamp,
    duration: Duration,
) -> Result<C::Timestamp, AppError> {
    clock
        .checked_add(timestamp, duration)
        .ok_or(AppError::ScanTimingExceedsLimit {
            limit: crate::error::ScanTimingLimit::MonotonicDeadline,
        })
}

fn merge_discovered_host_maps(
    discovered_hosts: &mut BTreeMap<Ipv4Addr, MacAddress>,
    additional_hosts: BTreeMap<Ipv4Addr, MacAddress>,
    warnings: &mut Vec<String>,
) {
    for (ipv4_address, media_access_control_address) in additional_hosts {
        merge_address_resolution_reply_sender_into_discovered_hosts(
            discovered_hosts,
            ipv4_address,
            media_access_control_address,
            warnings,
        );
    }
}

#[cfg(test)]
mod poll_timeout_milliseconds_for_receive_wait_tests {
    use super::poll_timeout_milliseconds_for_receive_wait;
    use std::time::Duration;

    #[test]
    fn maps_zero_duration_to_zero_milliseconds() {
        // Arrange
        let remaining = Duration::ZERO;

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome, 0,
            "zero remaining time should map to immediate poll timeout"
        );
    }

    #[test]
    fn maps_small_duration_to_matching_milliseconds() {
        // Arrange
        let remaining = Duration::from_millis(1500);

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome, 1500,
            "poll timeout should match remaining milliseconds when it fits c_int"
        );
    }

    #[test]
    fn clamps_duration_when_milliseconds_exceed_c_int_maximum() {
        // Arrange
        let remaining = Duration::from_millis(u64::from(libc::c_int::MAX as u32).saturating_add(1));

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome,
            libc::c_int::MAX,
            "oversized millisecond span should clamp to c_int::MAX for poll(2)"
        );
    }

    #[test]
    fn maps_duration_when_milliseconds_equal_c_int_maximum_without_clamping() {
        // Arrange
        let remaining = Duration::from_millis(libc::c_int::MAX as u64);

        // Act
        let outcome = poll_timeout_milliseconds_for_receive_wait(remaining);

        // Assert
        assert_eq!(
            outcome,
            libc::c_int::MAX,
            "exactly representable maximum poll timeout should pass through unchanged"
        );
    }
}

#[cfg(test)]
mod ipv4_scan_target_address_sequence_tests {
    use super::ipv4_scan_target_address_sequence;
    use std::net::Ipv4Addr;

    fn network_and_broadcast_slash_24() -> (u32, u32) {
        let network = Ipv4Addr::new(192, 168, 1, 0);
        let broadcast = Ipv4Addr::new(192, 168, 1, 255);
        (network.to_bits(), broadcast.to_bits())
    }

    #[test]
    fn appends_source_when_source_is_not_strictly_inside_open_host_interval() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 0);
        let interior = [Ipv4Addr::new(192, 168, 1, 10)];

        // Act
        let targets = ipv4_scan_target_address_sequence(
            interior.into_iter(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 0),
            ],
            "interface address on the subnet boundary should be probed after interior hosts"
        );
    }

    #[test]
    fn does_not_append_source_when_source_is_strictly_inside_open_host_interval() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 50);
        let interior = [
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
        ];

        // Act
        let targets = ipv4_scan_target_address_sequence(
            interior.into_iter(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
            ],
            "strictly interior interface address should not duplicate as trailing self-probe"
        );
    }

    #[test]
    fn appends_broadcast_source_after_interior_hosts_when_broadcast_is_interface_address() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 255);
        let interior = [Ipv4Addr::new(192, 168, 1, 10)];

        // Act
        let targets = ipv4_scan_target_address_sequence(
            interior.into_iter(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 255),
            ],
            "broadcast interface address should still receive a trailing self-probe"
        );
    }

    #[test]
    fn yields_only_broadcast_source_when_interior_iterator_is_empty_and_source_is_broadcast() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 255);

        // Act
        let targets = ipv4_scan_target_address_sequence(
            core::iter::empty(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert_eq!(
            targets,
            vec![Ipv4Addr::new(192, 168, 1, 255)],
            "empty interior range with broadcast source should still probe that address once"
        );
    }

    #[test]
    fn yields_empty_target_list_when_interior_iterator_is_empty_and_source_is_strictly_inside() {
        // Arrange
        let (network_bits, broadcast_bits) = network_and_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let targets = ipv4_scan_target_address_sequence(
            core::iter::empty(),
            source,
            network_bits,
            broadcast_bits,
        );

        // Assert
        assert!(
            targets.is_empty(),
            "strictly interior source with no interior iterator should not add duplicate self row"
        );
    }
}

#[cfg(test)]
mod should_apply_pacing_after_scan_round_tests {
    use super::should_apply_pacing_after_scan_round;
    use std::time::Duration;

    #[test]
    fn returns_true_when_more_rounds_remain_and_pacing_is_nonzero() {
        // Arrange
        let pacing = Duration::from_millis(5);

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 3, pacing);

        // Assert
        assert!(
            outcome,
            "pacing should apply between first and second round when pacing is nonzero"
        );
    }

    #[test]
    fn returns_false_on_final_round_even_when_pacing_is_nonzero() {
        // Arrange
        let pacing = Duration::from_millis(5);

        // Act
        let outcome = should_apply_pacing_after_scan_round(2, 3, pacing);

        // Assert
        assert!(!outcome, "pacing must not run after the final round");
    }

    #[test]
    fn returns_false_when_only_one_round_is_planned() {
        // Arrange
        let pacing = Duration::from_millis(5);

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 1, pacing);

        // Assert
        assert!(
            !outcome,
            "single-round scan should not sleep after the only round"
        );
    }

    #[test]
    fn returns_false_when_pacing_duration_is_zero() {
        // Arrange
        let pacing = Duration::ZERO;

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 5, pacing);

        // Assert
        assert!(
            !outcome,
            "zero pacing should never schedule sleeps between rounds"
        );
    }

    #[test]
    fn returns_false_when_total_rounds_is_zero_even_with_nonzero_pacing() {
        // Arrange
        let pacing = Duration::from_millis(1);

        // Act
        let outcome = should_apply_pacing_after_scan_round(0, 0, pacing);

        // Assert
        assert!(!outcome, "empty round plan must not schedule pacing sleeps");
    }

    #[test]
    fn returns_true_for_middle_round_when_more_than_two_rounds_remain() {
        // Arrange
        let pacing = Duration::from_millis(1);

        // Act
        let outcome = should_apply_pacing_after_scan_round(1, 4, pacing);

        // Assert
        assert!(
            outcome,
            "middle rounds should still schedule pacing when more rounds follow"
        );
    }
}

#[cfg(test)]
mod scan_round_schedule_tests {
    use super::{
        inter_round_sleep_count_for_scan_schedule, should_apply_pacing_after_scan_round,
        total_address_resolution_request_send_count,
    };
    use std::num::NonZeroU64;
    use std::time::Duration;

    #[test]
    fn total_send_count_is_zero_when_target_count_is_zero() {
        // Arrange
        let rounds = NonZeroU64::new(5).expect("five is non-zero");

        // Act
        let outcome = total_address_resolution_request_send_count(0, rounds);

        // Assert
        assert_eq!(
            outcome,
            Some(0),
            "empty target list should yield zero sends regardless of rounds"
        );
    }

    #[test]
    fn total_send_count_multiplies_targets_by_rounds() {
        // Arrange
        let rounds = NonZeroU64::new(4).expect("four is non-zero");

        // Act
        let outcome = total_address_resolution_request_send_count(7, rounds);

        // Assert
        assert_eq!(
            outcome,
            Some(28),
            "seven targets across four rounds should schedule twenty-eight sends"
        );
    }

    #[test]
    fn total_send_count_returns_none_when_product_overflows_u64() {
        // Arrange
        let rounds = NonZeroU64::new(u64::MAX).expect("maximum is non-zero");

        // Act
        let outcome = total_address_resolution_request_send_count(2, rounds);

        // Assert
        assert_eq!(
            outcome, None,
            "overflowing send count should surface as None instead of wrapping"
        );
    }

    #[test]
    fn inter_round_sleep_count_matches_sum_of_pacing_gates_for_each_round_index() {
        // Arrange
        let pacing = Duration::from_nanos(1);

        for total_rounds in 0_u64..=6_u64 {
            // Act
            let expected = inter_round_sleep_count_for_scan_schedule(total_rounds, pacing);
            let summed = (0..total_rounds)
                .filter(|&round_index| {
                    should_apply_pacing_after_scan_round(round_index, total_rounds, pacing)
                })
                .count() as u64;

            // Assert
            assert_eq!(
                summed, expected,
                "aggregated pacing gates should match closed-form count for total_rounds={total_rounds}"
            );
        }
    }

    #[test]
    fn inter_round_sleep_count_is_zero_when_pacing_is_zero_even_with_many_rounds() {
        // Arrange
        let pacing = Duration::ZERO;

        // Act
        let outcome = inter_round_sleep_count_for_scan_schedule(50, pacing);

        // Assert
        assert_eq!(
            outcome, 0,
            "zero pacing should never schedule sleeps between rounds"
        );
    }
}

#[cfg(test)]
mod merge_address_resolution_reply_sender_into_discovered_hosts_tests {
    use super::merge_address_resolution_reply_sender_into_discovered_hosts;
    use crate::mac_address::MacAddress;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    #[test]
    fn inserts_first_reply_for_each_ipv4_address() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let first_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            first_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(
            map.get(&ip).copied(),
            Some(first_mac),
            "first reply should populate the table"
        );
        assert!(
            warnings.is_empty(),
            "first insert should not warn, got: {warnings:?}"
        );
    }

    #[test]
    fn ignores_identical_duplicate_replies_without_warning() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(map.get(&ip).copied(), Some(mac));
        assert!(
            warnings.is_empty(),
            "same media access control should not warn, got: {warnings:?}"
        );
    }

    #[test]
    fn keeps_first_mac_and_emits_warning_for_each_conflicting_duplicate() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let first_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let second_mac = MacAddress::from_octets([9, 8, 7, 6, 5, 4]);
        let third_mac = MacAddress::from_octets([0xAA; 6]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            first_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            second_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            third_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(map.get(&ip).copied(), Some(first_mac));
        assert_eq!(
            warnings.len(),
            2,
            "each conflicting duplicate should warn once, got: {warnings:?}"
        );
        assert!(
            warnings[0].contains("conflicting") && warnings[0].contains("ignoring"),
            "warning should describe conflict, got: {}",
            warnings[0]
        );
    }

    #[test]
    fn tracks_independent_ipv4_addresses_without_cross_talk() {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let first_ip = Ipv4Addr::new(10, 0, 0, 2);
        let second_ip = Ipv4Addr::new(10, 0, 0, 3);
        let first_mac = MacAddress::from_octets([1, 1, 1, 1, 1, 1]);
        let second_mac = MacAddress::from_octets([2, 2, 2, 2, 2, 2]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            first_ip,
            first_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            second_ip,
            second_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(
            map.len(),
            2,
            "two distinct IPv4 addresses should both be stored"
        );
        assert_eq!(map.get(&first_ip).copied(), Some(first_mac));
        assert_eq!(map.get(&second_ip).copied(), Some(second_mac));
        assert!(
            warnings.is_empty(),
            "independent first inserts should not warn, got: {warnings:?}"
        );
    }

    #[test]
    fn emits_separate_warning_each_time_the_same_conflicting_media_access_control_address_returns()
    {
        // Arrange
        let mut map = BTreeMap::new();
        let mut warnings = Vec::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let first_mac = MacAddress::from_octets([1, 2, 3, 4, 5, 6]);
        let conflicting_mac = MacAddress::from_octets([9, 9, 9, 9, 9, 9]);

        // Act
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            first_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            conflicting_mac,
            &mut warnings,
        );
        merge_address_resolution_reply_sender_into_discovered_hosts(
            &mut map,
            ip,
            conflicting_mac,
            &mut warnings,
        );

        // Assert
        assert_eq!(map.get(&ip).copied(), Some(first_mac));
        assert_eq!(
            warnings.len(),
            2,
            "repeated identical conflicting sender should still warn each time, got: {warnings:?}"
        );
        for (index, warning) in warnings.iter().enumerate() {
            assert!(
                warning.contains("10.0.0.5")
                    && warning.contains("01:02:03:04:05:06")
                    && warning.contains("09:09:09:09:09:09"),
                "warning {index} should name the IPv4 and both media access control addresses, got: {warning}"
            );
        }
    }
}

#[cfg(test)]
mod ipv4_sender_is_probed_target_tests {
    use super::ipv4_sender_is_probed_target;
    use std::net::Ipv4Addr;

    fn network_broadcast_slash_24() -> (u32, u32) {
        let net = Ipv4Addr::new(192, 168, 1, 0);
        let bcast = Ipv4Addr::new(192, 168, 1, 255);
        (net.to_bits(), bcast.to_bits())
    }

    #[test]
    fn treats_interface_source_address_as_in_scope_even_when_not_strictly_inside_open_interval() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 1);

        // Act
        let outcome = ipv4_sender_is_probed_target(source, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            outcome,
            "gateway-style interface address on the subnet edge should still count as in-scope"
        );
    }

    #[test]
    fn interior_subnet_address_is_in_scope() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let sender = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let outcome = ipv4_sender_is_probed_target(sender, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            outcome,
            "strictly interior host addresses should be accepted"
        );
    }

    #[test]
    fn network_and_broadcast_addresses_are_out_of_scope_when_not_source() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let network = Ipv4Addr::new(192, 168, 1, 0);
        let broadcast = Ipv4Addr::new(192, 168, 1, 255);

        // Act
        let network_outcome =
            ipv4_sender_is_probed_target(network, source, network_bits, broadcast_bits);
        let broadcast_outcome =
            ipv4_sender_is_probed_target(broadcast, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            !network_outcome,
            "network address should not match strict interior rule"
        );
        assert!(
            !broadcast_outcome,
            "broadcast address should not match strict interior rule"
        );
    }

    #[test]
    fn address_outside_subnet_is_rejected_when_distinct_from_source() {
        // Arrange
        let (network_bits, broadcast_bits) = network_broadcast_slash_24();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let outsider = Ipv4Addr::new(10, 0, 0, 1);

        // Act
        let outcome = ipv4_sender_is_probed_target(outsider, source, network_bits, broadcast_bits);

        // Assert
        assert!(
            !outcome,
            "off-subnet senders should be ignored unless they equal the interface address"
        );
    }
}

#[cfg(test)]
mod full_subnet_scan_plan_tests {
    use super::ArpReplyAcceptance;
    use super::full_subnet_scan_plan;
    use crate::error::AppError;
    use crate::link_layer_backend::InterfaceScanAddresses;
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;

    fn slash_24_addresses(source: Ipv4Addr) -> InterfaceScanAddresses {
        InterfaceScanAddresses {
            source_ipv4_address: source,
            ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
            source_mac_address: MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
        }
    }

    #[test]
    fn plans_interior_slash_24_targets_and_subnet_scope_acceptance() {
        // Arrange
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let addresses = slash_24_addresses(source);

        // Act
        let plan = full_subnet_scan_plan(&addresses).expect("/24 should be scannable");

        // Assert
        assert_eq!(
            plan.targets.first().copied(),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            plan.targets.last().copied(),
            Some(Ipv4Addr::new(192, 168, 1, 254))
        );
        assert_eq!(plan.targets.len(), 254);
        assert!(plan.targets.contains(&source));
        match plan.acceptance {
            ArpReplyAcceptance::SubnetScope {
                source_ipv4_address,
                ..
            } => assert_eq!(source_ipv4_address, source),
            ArpReplyAcceptance::ExactTarget { .. } => {
                panic!("full-subnet plan should use subnet-scope acceptance")
            }
        }
    }

    #[test]
    fn rejects_slash_31_subnet_as_unsupported() {
        // Arrange
        let addresses = InterfaceScanAddresses {
            source_ipv4_address: Ipv4Addr::new(192, 168, 1, 0),
            ipv4_netmask: Ipv4Addr::new(255, 255, 255, 254),
            source_mac_address: MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
        };

        // Act
        let outcome = full_subnet_scan_plan(&addresses);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4SubnetUnsupported { .. })),
            "/31 has no interior hosts, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_non_contiguous_netmask() {
        // Arrange
        let addresses = InterfaceScanAddresses {
            source_ipv4_address: Ipv4Addr::new(192, 168, 1, 10),
            ipv4_netmask: Ipv4Addr::new(255, 255, 0, 255),
            source_mac_address: MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
        };

        // Act
        let outcome = full_subnet_scan_plan(&addresses);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4NetmaskInvalid { .. })),
            "non-contiguous netmask should be invalid, got: {outcome:?}"
        );
    }
}

#[cfg(test)]
mod arp_reply_acceptance_tests {
    use super::ArpReplyAcceptance;
    use std::net::Ipv4Addr;

    #[test]
    fn exact_target_accepts_only_matching_sender() {
        // Arrange
        let target = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target,
        };

        // Act
        let match_outcome = acceptance.accepts_sender_ipv4_address(target);
        let other_interior = acceptance.accepts_sender_ipv4_address(Ipv4Addr::new(192, 168, 1, 51));

        // Assert
        assert!(match_outcome, "exact target should accept matching sender");
        assert!(
            !other_interior,
            "different interior sender should be ignored in exact-target mode"
        );
    }

    #[test]
    fn subnet_scope_matches_ipv4_sender_is_probed_target_rules() {
        // Arrange
        let network = Ipv4Addr::new(192, 168, 1, 0).to_bits();
        let broadcast = Ipv4Addr::new(192, 168, 1, 255).to_bits();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let acceptance = ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: source,
            network_bits: network,
            broadcast_bits: broadcast,
        };

        // Act
        let interior = acceptance.accepts_sender_ipv4_address(Ipv4Addr::new(192, 168, 1, 20));

        // Assert
        assert!(
            interior,
            "subnet scope should accept interior senders like full scan"
        );
    }

    #[test]
    fn subnet_scope_rejects_sender_outside_local_subnet_when_not_equal_to_source() {
        // Arrange
        let network = Ipv4Addr::new(192, 168, 1, 0).to_bits();
        let broadcast = Ipv4Addr::new(192, 168, 1, 255).to_bits();
        let source = Ipv4Addr::new(192, 168, 1, 10);
        let acceptance = ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: source,
            network_bits: network,
            broadcast_bits: broadcast,
        };

        // Act
        let outsider = Ipv4Addr::new(10, 0, 0, 1);
        let outcome = acceptance.accepts_sender_ipv4_address(outsider);

        // Assert
        assert!(
            !outcome,
            "off-subnet sender should be rejected in subnet scope unless it equals the interface address"
        );
    }
}

#[cfg(test)]
mod collect_scan_over_endpoint_vlan_and_capture_noise_tests {
    use super::ArpReplyAcceptance;
    use super::ScanTransmitContext;
    use super::collect_scan_over_endpoint;
    use super::collect_scripted_scan;
    use crate::address_resolution_protocol::{
        ARP_OPERATION_REPLY, ARP_OPERATION_REQUEST, build_address_resolution_request_ethernet_frame,
    };
    use crate::application_command::{ArpSenderProtocolAddress, ScanWireOptions};
    use crate::error::AppError;
    use crate::ethernet_frame::{
        ETHERNET_II_HEADER_LENGTH, ETHERNET_PROTOCOL_ARP, ETHERNET_PROTOCOL_IPV4,
        ETHERNET_PROTOCOL_VLAN_TAG, ETHERNET_PROTOCOL_VLAN_TAG_SERVICE, Ieee8021qPriorityCodePoint,
        Ieee8021qTagControlInformation, Ieee8021qTagStack, Ieee8021qVlanIdentifier,
        encode_ethernet_ii_frame, encode_ethernet_ii_frame_with_optional_ieee_8021q_tag,
        encode_ieee_8023_rfc_1042_llc_snap_frame,
    };
    use crate::link_layer_backend::LinkLayerEndpoint;
    use crate::mac_address::MacAddress;
    use crate::scan_timing::FakeScanClock;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::time::Duration;

    struct ScriptedEndpoint {
        sent: RefCell<Vec<Vec<u8>>>,
        inbound: Vec<Vec<u8>>,
    }

    impl LinkLayerEndpoint for ScriptedEndpoint {
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
            buffer[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }
    }

    fn ipv4_ethernet_arp_frame_with_opcode(
        opcode: u16,
        sender_mac: MacAddress,
        sender_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let mut frame = build_address_resolution_request_ethernet_frame(
            sender_mac,
            sender_ip,
            Ipv4Addr::new(192, 168, 1, 1),
        )
        .to_vec();
        let opcode_offset = ETHERNET_II_HEADER_LENGTH + 6;
        frame[opcode_offset..opcode_offset + 2].copy_from_slice(&opcode.to_be_bytes());
        frame
    }

    #[test]
    fn sends_ieee_8021q_tagged_request_when_vlan_identifier_is_set() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits in 12 bits");
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    vlan_identifier: Some(vlan_identifier),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(sent.len(), 1, "one target and one round should send once");
        assert_eq!(&sent[0][12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(&sent[0][14..16], &10u16.to_be_bytes());
        assert_eq!(&sent[0][16..18], &[0x08, 0x06]);
        assert!(
            outcome.warnings.is_empty(),
            "successful tagged send should not warn, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn sends_ieee_8021q_priority_code_point_and_drop_eligible_indicator() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let vlan_identifier = Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits in 12 bits");
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    vlan_identifier: Some(vlan_identifier),
                    vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(5)
                        .expect("PCP 5 fits"),
                    vlan_drop_eligible_indicator: true,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(&sent[0][12..14], &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        assert_eq!(
            &sent[0][14..16],
            &0xB00Au16.to_be_bytes(),
            "PCP 5, DEI 1, VID 10 should encode as TCI 0xB00A"
        );
    }

    #[test]
    fn sends_custom_padding_after_arp_payload() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };
        let padding = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    padding: padding.clone(),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        let payload_start = 14 + 28;
        assert_eq!(
            &sent[0][payload_start..payload_start + 4],
            padding.as_slice()
        );
        assert_eq!(sent[0].len(), 60);
    }

    #[test]
    fn collect_rejects_padding_that_exceeds_ieee_8023_mac_client_data() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    llc_snap: true,
                    padding: vec![0; 1465],
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::Ieee8023MacClientDataExceedsMaximum { .. })
            ),
            "SNAP padding of 1465 octets must exceed the 1500-octet MAC client data maximum, got: {outcome:?}"
        );
        assert!(
            endpoint.sent.borrow().is_empty(),
            "oversize padding must not transmit a frame"
        );
    }

    #[test]
    fn ignores_non_arp_ethernet_frames_without_malformed_warning() {
        // Arrange
        let ipv4_frame = encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            ETHERNET_PROTOCOL_IPV4,
            &[0x45, 0x00],
        );
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![ipv4_frame],
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions::default(),
            },
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(
            outcome.discovered_hosts.is_empty(),
            "IPv4 frames must not be recorded as ARP replies"
        );
        assert!(
            outcome.warnings.is_empty(),
            "non-ARP capture noise should not produce malformed-frame warnings, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn ignores_inbound_arp_request_without_malformed_warning_or_host() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let request =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REQUEST, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![request],
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions::default(),
            },
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(
            outcome.discovered_hosts.is_empty(),
            "ARP requests must not be recorded as discovered hosts"
        );
        assert!(
            outcome.warnings.is_empty(),
            "well-formed ARP requests should not produce malformed-frame warnings, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn records_inbound_arp_reply_sender() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let reply = ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![reply],
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions::default(),
            },
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, target_ip);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            sender_mac
        );
        assert!(
            outcome.warnings.is_empty(),
            "a well-formed reply should not warn, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn warns_when_inbound_arp_opcode_is_reserved_by_rfc_5494() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let reserved = ipv4_ethernet_arp_frame_with_opcode(65535, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![reserved],
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions::default(),
            },
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(outcome.discovered_hosts.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(
            outcome.warnings[0].contains("reserved by RFC 5494"),
            "reserved opcode should remain a malformed-frame warning, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn sends_rfc_5227_probe_when_sender_protocol_address_is_unspecified() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    sender_protocol_address: ArpSenderProtocolAddress::Explicit(
                        Ipv4Addr::UNSPECIFIED,
                    ),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(
            &sent[0][28..32],
            &[0, 0, 0, 0],
            "RFC 5227 Probe SPA is 0.0.0.0"
        );
        assert_eq!(&sent[0][38..42], &target_ip.octets());
    }

    #[test]
    fn sends_rfc_5227_announcement_when_sender_protocol_address_is_destination_target() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    sender_protocol_address: ArpSenderProtocolAddress::DestinationTarget,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(
            &sent[0][28..32],
            &target_ip.octets(),
            "RFC 5227 Announcement sets ar$spa to the target"
        );
        assert_eq!(&sent[0][38..42], &target_ip.octets());
    }

    #[test]
    fn sends_rfc_1042_llc_snap_when_llc_snap_is_set() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    llc_snap: true,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(
            &sent[0][14..17],
            &[0xAA, 0xAA, 0x03],
            "RFC 1042 LLC header should precede SNAP"
        );
        assert_eq!(
            &sent[0][20..22],
            &[0x08, 0x06],
            "SNAP EtherType should be ARP"
        );
        assert_eq!(
            &sent[0][12..14],
            &36u16.to_be_bytes(),
            "IEEE 802.3 length is LLC/SNAP plus ARP (36), not an Ethernet-header-inclusive size"
        );
    }

    #[test]
    fn sends_unicast_ethernet_destination_and_independent_arp_sender_hardware() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let destination = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ethernet_source = MacAddress::from_octets([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        let sender_hardware = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };

        // Act
        collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    ethernet_destination: Some(destination),
                    ethernet_source: Some(ethernet_source),
                    arp_sender_hardware: Some(sender_hardware),
                    arp_hardware_type: 6,
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(&sent[0][0..6], &destination.octets());
        assert_eq!(&sent[0][6..12], &ethernet_source.octets());
        assert_eq!(&sent[0][22..28], &sender_hardware.octets());
        assert_eq!(&sent[0][14..16], &6u16.to_be_bytes());
    }

    fn default_exact_target_context() -> (
        MacAddress,
        Ipv4Addr,
        Ipv4Addr,
        ScanTransmitContext,
        ArpReplyAcceptance,
    ) {
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);
        let transmit = ScanTransmitContext {
            source_mac_address: source_mac,
            interface_ipv4_address: source_ip,
            wire: ScanWireOptions::default(),
        };
        let acceptance = ArpReplyAcceptance::ExactTarget {
            target_ipv4_address: target_ip,
        };
        (source_mac, source_ip, target_ip, transmit, acceptance)
    }

    #[test]
    fn warns_when_sending_an_address_resolution_request_fails() {
        // Arrange
        struct FailingSendEndpoint;
        impl LinkLayerEndpoint for FailingSendEndpoint {
            fn send_ethernet_frame(&self, _frame: &[u8]) -> std::io::Result<()> {
                Err(std::io::Error::other("link send failed"))
            }

            fn wait_until_readable(
                &self,
                _timeout_milliseconds: libc::c_int,
            ) -> Result<bool, AppError> {
                Ok(false)
            }

            fn try_receive_ethernet_frame(
                &mut self,
                _buffer: &mut [u8],
            ) -> Result<Option<usize>, AppError> {
                Ok(None)
            }
        }
        let mut endpoint = FailingSendEndpoint;
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("send failure is a warning, not a fatal error");

        // Assert
        assert!(outcome.discovered_hosts.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(
            outcome.warnings[0].contains("failed to send ARP request")
                && outcome.warnings[0].contains("192.168.1.50"),
            "send failure should name the target, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn ignores_truncated_ethernet_without_malformed_warning() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![vec![0u8; 10]],
        };
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(outcome.discovered_hosts.is_empty());
        assert!(
            outcome.warnings.is_empty(),
            "unparseable Ethernet is capture noise, not a malformed ARP warning, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn warns_when_arp_ethertype_payload_is_truncated() {
        // Arrange
        let truncated = encode_ethernet_ii_frame(
            MacAddress::BROADCAST,
            MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
            ETHERNET_PROTOCOL_ARP,
            &[0u8; 10],
        );
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![truncated],
        };
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(outcome.discovered_hosts.is_empty());
        assert_eq!(outcome.warnings.len(), 1);
        assert!(
            outcome.warnings[0].contains("malformed Ethernet/ARP")
                && outcome.warnings[0].contains("shorter than IPv4 over Ethernet"),
            "truncated ARP payload should warn, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn ignores_unknown_non_reserved_arp_opcode_without_malformed_warning_or_host() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let rarp = ipv4_ethernet_arp_frame_with_opcode(3, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![rarp],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(outcome.discovered_hosts.is_empty());
        assert!(
            outcome.warnings.is_empty(),
            "RARP should be ignored without a malformation warning, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn ignores_reply_whose_sender_is_not_the_exact_target() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let other_ip = Ipv4Addr::new(192, 168, 1, 51);
        let reply = ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, other_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![reply],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(
            outcome.discovered_hosts.is_empty(),
            "ExactTarget must not record a different sender IPv4"
        );
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn records_reply_after_ignoring_an_inbound_request_in_the_same_drain() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let request =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REQUEST, sender_mac, target_ip);
        let reply = ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![request, reply],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, target_ip);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            sender_mac
        );
        assert!(
            outcome.warnings.is_empty(),
            "a well-formed request must not poison a later reply, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn records_ieee_8021q_tagged_inbound_reply() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let arp_payload =
            untagged[ETHERNET_II_HEADER_LENGTH..ETHERNET_II_HEADER_LENGTH + 28].to_vec();
        let tagged = encode_ethernet_ii_frame_with_optional_ieee_8021q_tag(
            MacAddress::BROADCAST,
            sender_mac,
            Some(Ieee8021qTagStack::Customer(
                Ieee8021qTagControlInformation::from_vlan_identifier(
                    Ieee8021qVlanIdentifier::new(10).expect("VID 10 fits"),
                ),
            )),
            ETHERNET_PROTOCOL_ARP,
            &arp_payload,
        );
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![tagged],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, target_ip);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            sender_mac
        );
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn records_rfc_1042_llc_snap_inbound_reply() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let arp_payload =
            untagged[ETHERNET_II_HEADER_LENGTH..ETHERNET_II_HEADER_LENGTH + 28].to_vec();
        let snap = encode_ieee_8023_rfc_1042_llc_snap_frame(
            MacAddress::BROADCAST,
            sender_mac,
            None,
            ETHERNET_PROTOCOL_ARP,
            &arp_payload,
        );
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![snap],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, target_ip);
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn collect_rejects_ethernet_ii_padding_that_exceeds_ieee_8023_mac_client_data() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let (source_mac, source_ip, target_ip, _transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    padding: vec![0; 1473],
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::Ieee8023MacClientDataExceedsMaximum { .. })
            ),
            "Ethernet II padding of 1473 octets must exceed the 1500-octet MAC client data maximum, got: {outcome:?}"
        );
        assert!(endpoint.sent.borrow().is_empty());
    }

    #[test]
    fn keeps_first_mac_when_conflicting_replies_arrive_during_receive() {
        // Arrange
        let first_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let second_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 3]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let first = ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, first_mac, target_ip);
        let second =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, second_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![first, second],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            first_mac
        );
        assert_eq!(outcome.warnings.len(), 1);
        assert!(
            outcome.warnings[0].contains("conflicting address resolution reply"),
            "second MAC should warn, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn returns_error_when_wait_until_readable_fails() {
        // Arrange
        struct FailingWaitEndpoint;
        impl LinkLayerEndpoint for FailingWaitEndpoint {
            fn send_ethernet_frame(&self, _frame: &[u8]) -> std::io::Result<()> {
                Ok(())
            }

            fn wait_until_readable(
                &self,
                _timeout_milliseconds: libc::c_int,
            ) -> Result<bool, AppError> {
                Err(AppError::from(std::io::Error::other("poll failed")))
            }

            fn try_receive_ethernet_frame(
                &mut self,
                _buffer: &mut [u8],
            ) -> Result<Option<usize>, AppError> {
                Ok(None)
            }
        }
        let mut endpoint = FailingWaitEndpoint;
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        );

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Io(_))),
            "poll failure should be fatal, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_try_receive_ethernet_frame_fails() {
        // Arrange
        struct FailingReceiveEndpoint;
        impl LinkLayerEndpoint for FailingReceiveEndpoint {
            fn send_ethernet_frame(&self, _frame: &[u8]) -> std::io::Result<()> {
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
                _buffer: &mut [u8],
            ) -> Result<Option<usize>, AppError> {
                Err(AppError::from(std::io::Error::other("recv failed")))
            }
        }
        let mut endpoint = FailingReceiveEndpoint;
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        );

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Io(_))),
            "receive failure should be fatal, got: {outcome:?}"
        );
    }

    #[test]
    fn applies_inter_round_pacing_sleep_when_more_than_one_round_is_planned() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();

        let clock = FakeScanClock::new();

        // Act
        collect_scripted_scan(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::ZERO,
            Duration::from_nanos(1),
            NonZeroU64::new(2).expect("two rounds"),
            None,
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(
            endpoint.sent.borrow().len(),
            2,
            "two rounds should send twice"
        );
        assert_eq!(
            clock.sleeps(),
            vec![Duration::from_nanos(1)],
            "burst rounds sleep only between rounds"
        );
    }

    /// The S-TAG/C-TAG pair used by the `QinQ` scanner tests: service PCP 5, DEI 1, S-VID 100 and
    /// customer PCP 0, DEI 0, C-VID 10.
    fn service_and_customer_tag_stack() -> Ieee8021qTagStack {
        Ieee8021qTagStack::ServiceAndCustomer {
            service: Ieee8021qTagControlInformation::new(
                Ieee8021qPriorityCodePoint::new(5).expect("PCP 5 fits in 3 bits"),
                true,
                Ieee8021qVlanIdentifier::new(100).expect("S-VID 100 fits in 12 bits"),
            ),
            customer: Ieee8021qTagControlInformation::from_vlan_identifier(
                Ieee8021qVlanIdentifier::new(10).expect("C-VID 10 fits in 12 bits"),
            ),
        }
    }

    /// Wire options that transmit the same S-TAG/C-TAG pair.
    fn service_and_customer_wire_options() -> ScanWireOptions {
        ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
            service_vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(5)
                .expect("PCP 5 fits in 3 bits"),
            service_vlan_drop_eligible_indicator: true,
            ..ScanWireOptions::default()
        }
    }

    /// Rebuilds `arp_payload` behind an S-TAG/C-TAG pair in the requested framing.
    fn service_tagged_frame(sender_mac: MacAddress, arp_payload: &[u8], llc_snap: bool) -> Vec<u8> {
        let encode = if llc_snap {
            encode_ieee_8023_rfc_1042_llc_snap_frame
        } else {
            encode_ethernet_ii_frame_with_optional_ieee_8021q_tag
        };
        encode(
            MacAddress::BROADCAST,
            sender_mac,
            Some(service_and_customer_tag_stack()),
            ETHERNET_PROTOCOL_ARP,
            arp_payload,
        )
    }

    /// Extracts the 28-octet ARP PDU from an untagged Ethernet II ARP frame.
    fn arp_payload_of(frame: &[u8]) -> Vec<u8> {
        frame[ETHERNET_II_HEADER_LENGTH..ETHERNET_II_HEADER_LENGTH + 28].to_vec()
    }

    #[test]
    fn sends_service_and_customer_tagged_request_when_service_vlan_identifier_is_set() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let source_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let source_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: service_and_customer_wire_options(),
            },
            &ArpReplyAcceptance::ExactTarget {
                target_ipv4_address: target_ip,
            },
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent = endpoint.sent.borrow();
        assert_eq!(sent.len(), 1, "one target and one round should send once");
        assert_eq!(
            &sent[0][12..14],
            &ETHERNET_PROTOCOL_VLAN_TAG_SERVICE.to_be_bytes(),
            "the outer TPID is the IEEE 802.1Q service EtherType"
        );
        assert_eq!(&sent[0][14..16], &0xB064u16.to_be_bytes(), "service TCI");
        assert_eq!(
            &sent[0][16..18],
            &ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes(),
            "the inner TPID is the customer EtherType"
        );
        assert_eq!(&sent[0][18..20], &0x000Au16.to_be_bytes(), "customer TCI");
        assert_eq!(&sent[0][20..22], &[0x08, 0x06], "then the ARP EtherType");
        assert_eq!(
            sent[0].len(),
            60,
            "stacked tags still pad to the IEEE 802.3 60-octet minimum without FCS"
        );
        assert!(
            outcome.warnings.is_empty(),
            "successful stacked send should not warn, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn records_service_and_customer_tagged_inbound_reply() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![service_tagged_frame(
                sender_mac,
                &arp_payload_of(&untagged),
                false,
            )],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, target_ip);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            sender_mac
        );
        assert!(
            outcome.warnings.is_empty(),
            "a well-formed QinQ reply is not a malformed frame, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn records_qinq_reply_whose_outer_service_tag_the_kernel_stripped() {
        // Arrange: on Linux ingress the kernel always moves the outermost TPID + TCI into skb
        // metadata before an `AF_PACKET` socket sees the frame (`skb_vlan_untag()`, Linux 3.16,
        // commit 0d5501c1c828), so on a real IEEE 802.1ad trunk the reply arrives leading with the
        // inner customer tag. Recording must not depend on seeing the service tag inline.
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 2]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let on_the_wire = service_tagged_frame(sender_mac, &arp_payload_of(&untagged), false);
        let mut kernel_stripped = on_the_wire[..12].to_vec();
        kernel_stripped.extend_from_slice(&on_the_wire[16..]);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![kernel_stripped],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(
            outcome.discovered_hosts.len(),
            1,
            "a reply reduced to its customer tag by the kernel must still be recorded"
        );
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, target_ip);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            sender_mac
        );
        assert!(
            outcome.warnings.is_empty(),
            "a kernel-untagged QinQ reply is not a malformed frame, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn records_service_and_customer_tagged_rfc_1042_llc_snap_inbound_reply() {
        // Arrange
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 3]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![service_tagged_frame(
                sender_mac,
                &arp_payload_of(&untagged),
                true,
            )],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            sender_mac
        );
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn ignores_service_and_customer_tagged_inbound_request_without_malformed_warning() {
        // Arrange: a well-formed QinQ ARP request is ordinary LAN noise, including a copy of our
        // own broadcast, so it must neither be recorded nor warned about.
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 4]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REQUEST, sender_mac, target_ip);
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![service_tagged_frame(
                sender_mac,
                &arp_payload_of(&untagged),
                false,
            )],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(
            outcome.discovered_hosts.is_empty(),
            "an inbound QinQ request must not be recorded as a discovered host"
        );
        assert!(
            outcome.warnings.is_empty(),
            "a well-formed QinQ request is LAN noise, not a malformed frame, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn ignores_unsupported_tag_arrangements_without_malformed_warning() {
        // Arrange: a lone S-TAG and a three-tag stack are unparseable Ethernet, which the scanner
        // treats as capture noise rather than an operator-facing malformation.
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 5]);
        let (_source_mac, _source_ip, target_ip, transmit, acceptance) =
            default_exact_target_context();
        let untagged =
            ipv4_ethernet_arp_frame_with_opcode(ARP_OPERATION_REPLY, sender_mac, target_ip);
        let arp_payload = arp_payload_of(&untagged);

        let mut lone_service_tag = Vec::new();
        lone_service_tag.extend_from_slice(&MacAddress::BROADCAST.octets());
        lone_service_tag.extend_from_slice(&sender_mac.octets());
        lone_service_tag.extend_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG_SERVICE.to_be_bytes());
        lone_service_tag.extend_from_slice(&0xB064u16.to_be_bytes());
        lone_service_tag.extend_from_slice(&ETHERNET_PROTOCOL_ARP.to_be_bytes());
        lone_service_tag.extend_from_slice(&arp_payload);

        let mut three_tags = Vec::new();
        three_tags.extend_from_slice(&MacAddress::BROADCAST.octets());
        three_tags.extend_from_slice(&sender_mac.octets());
        three_tags.extend_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG_SERVICE.to_be_bytes());
        three_tags.extend_from_slice(&0xB064u16.to_be_bytes());
        three_tags.extend_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        three_tags.extend_from_slice(&0x000Au16.to_be_bytes());
        three_tags.extend_from_slice(&ETHERNET_PROTOCOL_VLAN_TAG.to_be_bytes());
        three_tags.extend_from_slice(&0x0003u16.to_be_bytes());
        three_tags.extend_from_slice(&ETHERNET_PROTOCOL_ARP.to_be_bytes());
        three_tags.extend_from_slice(&arp_payload);

        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: vec![lone_service_tag, three_tags],
        };

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &transmit,
            &acceptance,
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::MIN,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(
            outcome.discovered_hosts.is_empty(),
            "an unsupported tag arrangement must never yield a discovered host"
        );
        assert!(
            outcome.warnings.is_empty(),
            "unparseable tagging is capture noise, not a malformed ARP warning, got: {:?}",
            outcome.warnings
        );
    }

    #[test]
    fn collect_rejects_a_service_tag_without_a_customer_tag_before_sending_anything() {
        // Arrange
        let mut endpoint = ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: Vec::new(),
        };
        let (source_mac, source_ip, target_ip, _transmit, acceptance) =
            default_exact_target_context();

        // Act
        let outcome = collect_scan_over_endpoint(
            &mut endpoint,
            &[target_ip],
            &ScanTransmitContext {
                source_mac_address: source_mac,
                interface_ipv4_address: source_ip,
                wire: ScanWireOptions {
                    vlan_identifier: None,
                    service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
                    ..ScanWireOptions::default()
                },
            },
            &acceptance,
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ServiceVlanTagRequiresCustomerVlanTag {
                    service_vlan_identifier: 100
                })
            ),
            "a lone service tag must fail before transmit, got: {outcome:?}"
        );
        assert!(
            endpoint.sent.borrow().is_empty(),
            "no frame should reach the wire when the tag stack is invalid"
        );
    }
}

#[cfg(test)]
mod rate_limited_scan_timing_tests {
    use super::{ArpReplyAcceptance, ScanTransmitContext, collect_scripted_scan};
    use crate::address_resolution_protocol::{
        ARP_OPERATION_REPLY, build_address_resolution_request_ethernet_frame,
    };
    use crate::application_command::{
        InterTargetSendRate, RateLimitedScanTiming, RetryBackoffFactor, ScanWireOptions,
    };
    use crate::error::{AppError, ScanTimingLimit};
    use crate::ethernet_frame::ETHERNET_II_HEADER_LENGTH;
    use crate::link_layer_backend::LinkLayerEndpoint;
    use crate::mac_address::MacAddress;
    use crate::scan_timing::{FakeScanClock, SystemScanClock};
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::time::Duration;

    struct ScriptedEndpoint {
        sent: RefCell<Vec<Vec<u8>>>,
        inbound: RefCell<Vec<Vec<u8>>>,
        fail_sends: bool,
    }

    impl LinkLayerEndpoint for ScriptedEndpoint {
        fn send_ethernet_frame(&self, frame: &[u8]) -> std::io::Result<()> {
            self.sent.borrow_mut().push(frame.to_vec());
            if self.fail_sends {
                return Err(std::io::Error::other("injected send failure"));
            }
            Ok(())
        }

        fn wait_until_readable(
            &self,
            _timeout_milliseconds: libc::c_int,
        ) -> Result<bool, AppError> {
            Ok(!self.inbound.borrow().is_empty())
        }

        fn try_receive_ethernet_frame(
            &mut self,
            buffer: &mut [u8],
        ) -> Result<Option<usize>, AppError> {
            let mut inbound = self.inbound.borrow_mut();
            if inbound.is_empty() {
                return Ok(None);
            }
            let frame = inbound.remove(0);
            buffer[..frame.len()].copy_from_slice(&frame);
            Ok(Some(frame.len()))
        }
    }

    fn transmit() -> ScanTransmitContext {
        ScanTransmitContext {
            source_mac_address: MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]),
            interface_ipv4_address: Ipv4Addr::new(192, 168, 1, 1),
            wire: ScanWireOptions::default(),
        }
    }

    fn subnet_acceptance() -> ArpReplyAcceptance {
        ArpReplyAcceptance::SubnetScope {
            source_ipv4_address: Ipv4Addr::new(192, 168, 1, 1),
            network_bits: u32::from(Ipv4Addr::new(192, 168, 1, 0)),
            broadcast_bits: u32::from(Ipv4Addr::new(192, 168, 1, 255)),
        }
    }

    fn interval_limit(milliseconds: u64, backoff: f64) -> RateLimitedScanTiming {
        RateLimitedScanTiming::new(
            InterTargetSendRate::interval(Duration::from_millis(milliseconds))
                .expect("test interval is positive"),
            RetryBackoffFactor::new(backoff).expect("test backoff is at least 1"),
        )
    }

    fn reply_from(sender_ip: Ipv4Addr) -> Vec<u8> {
        let sender_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 9]);
        let mut frame = build_address_resolution_request_ethernet_frame(
            sender_mac,
            sender_ip,
            Ipv4Addr::new(192, 168, 1, 1),
        )
        .to_vec();
        let opcode_offset = ETHERNET_II_HEADER_LENGTH + 6;
        frame[opcode_offset..opcode_offset + 2].copy_from_slice(&ARP_OPERATION_REPLY.to_be_bytes());
        frame
    }

    fn target_ipv4(frame: &[u8]) -> Ipv4Addr {
        let octets: [u8; 4] = frame[38..42]
            .try_into()
            .expect("untagged ARP target protocol address occupies octets 38..42");
        Ipv4Addr::from(octets)
    }

    fn endpoint(inbound: Vec<Vec<u8>>, fail_sends: bool) -> ScriptedEndpoint {
        ScriptedEndpoint {
            sent: RefCell::new(Vec::new()),
            inbound: RefCell::new(inbound),
            fail_sends,
        }
    }

    #[test]
    fn spaces_each_later_send_by_the_interval_and_does_not_sleep_before_the_first() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();
        let targets = [
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
            Ipv4Addr::new(192, 168, 1, 12),
        ];

        // Act
        collect_scripted_scan(
            &mut link,
            &targets,
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(interval_limit(10, 1.5)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(10); 2]);
        let sent = link.sent.borrow();
        assert_eq!(
            sent.iter()
                .map(|frame| target_ipv4(frame))
                .collect::<Vec<_>>(),
            targets
        );
    }

    #[test]
    fn keeps_the_full_interval_after_a_late_send_instead_of_catching_up() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();
        clock.arm_stall_after_next_send(Duration::from_millis(100));
        let targets = [
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
            Ipv4Addr::new(192, 168, 1, 12),
        ];

        // Act
        collect_scripted_scan(
            &mut link,
            &targets,
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(interval_limit(10, 1.0)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(
            clock.sleeps(),
            vec![Duration::from_millis(10), Duration::from_millis(10)]
        );
    }

    #[test]
    fn adds_round_pacing_after_the_inter_send_deadline_and_the_receive_window() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();
        let targets = [
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 11),
        ];

        // Act
        collect_scripted_scan(
            &mut link,
            &targets,
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::from_millis(5),
            NonZeroU64::new(2).expect("two rounds"),
            Some(interval_limit(10, 1.0)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(
            clock.sleeps(),
            vec![
                Duration::from_millis(10),
                Duration::from_millis(15),
                Duration::from_millis(10),
            ]
        );
        assert_eq!(link.sent.borrow().len(), 4);
    }

    #[test]
    fn stretches_each_unanswered_receive_window_by_the_backoff_factor() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();

        // Act
        collect_scripted_scan(
            &mut link,
            &[Ipv4Addr::new(192, 168, 1, 10)],
            &transmit(),
            &subnet_acceptance(),
            Duration::from_millis(1000),
            Duration::ZERO,
            NonZeroU64::new(3).expect("three rounds"),
            Some(interval_limit(10, 1.5)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(
            clock.unreadable_waits(),
            vec![
                Duration::from_millis(1000),
                Duration::from_millis(1500),
                Duration::from_millis(2250),
            ]
        );
        assert!(
            clock.sleeps().is_empty(),
            "a receive window that already covers the next send leaves no extra gap, got: {:?}",
            clock.sleeps()
        );
        assert_eq!(link.sent.borrow().len(), 3);
    }

    #[test]
    fn retries_only_targets_that_have_not_answered() {
        // Arrange
        let first = Ipv4Addr::new(192, 168, 1, 10);
        let second = Ipv4Addr::new(192, 168, 1, 11);
        let mut link = endpoint(vec![reply_from(first)], false);
        let clock = FakeScanClock::new();

        // Act
        let outcome = collect_scripted_scan(
            &mut link,
            &[first, second],
            &transmit(),
            &subnet_acceptance(),
            Duration::from_millis(20),
            Duration::ZERO,
            NonZeroU64::new(2).expect("two rounds"),
            Some(interval_limit(10, 1.0)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        let sent_targets: Vec<Ipv4Addr> = link
            .sent
            .borrow()
            .iter()
            .map(|frame| target_ipv4(frame))
            .collect();
        assert_eq!(sent_targets, vec![first, second, second]);
        assert_eq!(outcome.discovered_hosts.len(), 1);
        assert_eq!(outcome.discovered_hosts[0].ipv4_address, first);
        assert_eq!(
            outcome.discovered_hosts[0].media_access_control_address,
            MacAddress::from_octets([0x02, 0, 0, 0, 0, 9])
        );
    }

    #[test]
    fn stops_before_later_rounds_when_every_target_has_answered() {
        // Arrange
        let first = Ipv4Addr::new(192, 168, 1, 10);
        let second = Ipv4Addr::new(192, 168, 1, 11);
        let mut link = endpoint(vec![reply_from(first), reply_from(second)], false);
        let clock = FakeScanClock::new();

        // Act
        let outcome = collect_scripted_scan(
            &mut link,
            &[first, second],
            &transmit(),
            &subnet_acceptance(),
            Duration::from_millis(20),
            Duration::from_millis(50),
            NonZeroU64::new(3).expect("three rounds"),
            Some(interval_limit(10, 1.5)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(link.sent.borrow().len(), 2);
        let discovered: Vec<Ipv4Addr> = outcome
            .discovered_hosts
            .iter()
            .map(|host| host.ipv4_address)
            .collect();
        assert_eq!(discovered, vec![first, second]);
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(10)]);
        assert_eq!(
            clock.unreadable_waits(),
            vec![Duration::from_millis(20)],
            "an answered round still consumes its full receive window"
        );
    }

    #[test]
    fn counts_a_failed_send_as_a_consumed_schedule_slot() {
        // Arrange
        let mut link = endpoint(Vec::new(), true);
        let clock = FakeScanClock::new();

        // Act
        let outcome = collect_scripted_scan(
            &mut link,
            &[
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
            ],
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(interval_limit(10, 1.0)),
            &clock,
        )
        .expect("a failed send is a warning, not a fatal error");

        // Assert
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(10); 2]);
        assert_eq!(
            outcome.warnings,
            vec![
                "failed to send ARP request to 192.168.1.10: injected send failure".to_string(),
                "failed to send ARP request to 192.168.1.11: injected send failure".to_string(),
                "failed to send ARP request to 192.168.1.12: injected send failure".to_string(),
            ]
        );
        assert!(outcome.discovered_hosts.is_empty());
    }

    #[test]
    fn burst_path_does_not_insert_inter_target_sleeps() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();

        // Act
        collect_scripted_scan(
            &mut link,
            &[
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
            ],
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
            None,
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert!(clock.sleeps().is_empty());
        let sent_targets: Vec<Ipv4Addr> = link
            .sent
            .borrow()
            .iter()
            .map(|frame| target_ipv4(frame))
            .collect();
        assert_eq!(
            sent_targets,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
            ]
        );
    }

    #[test]
    fn derives_a_two_millisecond_gap_from_256_kilobits_per_second() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();
        let rate = RateLimitedScanTiming::new(
            InterTargetSendRate::bandwidth(256_000).expect("256000 is positive"),
            RetryBackoffFactor::DEFAULT,
        );

        // Act
        collect_scripted_scan(
            &mut link,
            &[
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
            ],
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(rate),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(2)]);
    }

    #[test]
    fn still_waits_the_timeout_when_the_target_list_is_empty() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();

        // Act
        collect_scripted_scan(
            &mut link,
            &[],
            &transmit(),
            &subnet_acceptance(),
            Duration::from_millis(5),
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(interval_limit(10, 1.5)),
            &clock,
        )
        .expect("an empty target list should still receive");

        // Assert
        assert!(link.sent.borrow().is_empty());
        assert_eq!(clock.unreadable_waits(), vec![Duration::from_millis(5)]);
    }

    #[test]
    fn adds_only_round_pacing_when_the_receive_window_already_passed_the_send_deadline() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let clock = FakeScanClock::new();

        // Act
        collect_scripted_scan(
            &mut link,
            &[Ipv4Addr::new(192, 168, 1, 10)],
            &transmit(),
            &subnet_acceptance(),
            Duration::from_millis(1000),
            Duration::from_millis(5),
            NonZeroU64::new(2).expect("two rounds"),
            Some(interval_limit(10, 1.0)),
            &clock,
        )
        .expect("scripted endpoint should not fail");

        // Assert
        assert_eq!(clock.sleeps(), vec![Duration::from_millis(5)]);
        assert_eq!(
            clock.unreadable_waits(),
            vec![Duration::from_millis(1000), Duration::from_millis(1000)]
        );
        assert_eq!(link.sent.borrow().len(), 2);
    }

    #[test]
    fn rejects_a_receive_deadline_the_system_clock_cannot_represent() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);

        // Act
        let outcome = collect_scripted_scan(
            &mut link,
            &[],
            &transmit(),
            &subnet_acceptance(),
            Duration::MAX,
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(interval_limit(1, 1.0)),
            &SystemScanClock,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::MonotonicDeadline,
                })
            ),
            "Duration::MAX past Instant::now must fail closed, got: {outcome:?}"
        );
        assert!(link.sent.borrow().is_empty());
    }

    #[test]
    fn burst_path_rejects_a_receive_deadline_the_system_clock_cannot_represent() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);

        // Act
        let outcome = collect_scripted_scan(
            &mut link,
            &[Ipv4Addr::new(192, 168, 1, 10)],
            &transmit(),
            &subnet_acceptance(),
            Duration::MAX,
            Duration::ZERO,
            NonZeroU64::MIN,
            None,
            &SystemScanClock,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::MonotonicDeadline,
                })
            ),
            "the burst receive deadline must fail closed, got: {outcome:?}"
        );
        assert_eq!(link.sent.borrow().len(), 1);
    }

    #[test]
    fn second_send_fails_when_the_interval_does_not_fit_on_the_system_clock() {
        // Arrange
        let mut link = endpoint(Vec::new(), false);
        let rate = RateLimitedScanTiming::new(
            InterTargetSendRate::interval(Duration::MAX).expect("max duration is non-zero"),
            RetryBackoffFactor::new(1.0).expect("unit factor"),
        );

        // Act
        let outcome = collect_scripted_scan(
            &mut link,
            &[
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
            ],
            &transmit(),
            &subnet_acceptance(),
            Duration::ZERO,
            Duration::ZERO,
            NonZeroU64::MIN,
            Some(rate),
            &SystemScanClock,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::MonotonicDeadline,
                })
            ),
            "the second send's deadline must fail closed, got: {outcome:?}"
        );
        assert_eq!(
            link.sent.borrow().len(),
            1,
            "the first send is immediate; the overflow happens before the second"
        );
    }
}
