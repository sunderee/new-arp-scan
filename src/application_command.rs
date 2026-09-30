//! Application commands accepted by [`crate::run`].

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::address_resolution_protocol::{
    ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH, ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH,
    ARP_HARDWARE_TYPE_ETHERNET, ARP_IPV4_PROTOCOL_ADDRESS_LENGTH, ARP_OPERATION_REQUEST,
    AddressResolutionRequestLayout,
};
use crate::ethernet_frame::{
    ETHERNET_PROTOCOL_IPV4, IEEE_8023_LLC_SNAP_HEADER_LENGTH, IEEE_8023_MAXIMUM_LENGTH,
    Ieee8021qPriorityCodePoint, Ieee8021qTagControlInformation, Ieee8021qTagStack,
    Ieee8021qVlanIdentifier,
};
use crate::mac_address::MacAddress;

/// How transmitted ARP requests fill RFC 826 `ar$spa`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpSenderProtocolAddress {
    /// Use the scanning interface IPv4 address (RFC 826 default, original `arp-scan` default).
    Interface,
    /// Override `ar$spa` with this address. [`Ipv4Addr::UNSPECIFIED`] (`0.0.0.0`) is an RFC 5227
    /// ARP Probe.
    Explicit(Ipv4Addr),
    /// Set `ar$spa` to each target's IPv4 address (RFC 5227 ARP Announcement / original `arp-scan`
    /// `--arpspa dest`).
    DestinationTarget,
}

impl ArpSenderProtocolAddress {
    /// Parses an `--arpspa` token: dotted-quad IPv4, or `dest` (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns a message when `token` is neither `dest` nor a dotted-quad IPv4 address.
    pub fn parse_cli_token(token: &str) -> Result<Self, String> {
        if token.eq_ignore_ascii_case("dest") {
            return Ok(Self::DestinationTarget);
        }
        token.parse::<Ipv4Addr>().map(Self::Explicit).map_err(|_| {
            format!("invalid --arpspa value '{token}': expected a dotted-quad IPv4 address or dest")
        })
    }

    /// Returns the `ar$spa` value for one transmitted request.
    #[must_use]
    pub fn ipv4_address_for_target(
        self,
        interface_ipv4_address: Ipv4Addr,
        target_ipv4_address: Ipv4Addr,
    ) -> Ipv4Addr {
        match self {
            Self::Interface => interface_ipv4_address,
            Self::Explicit(address) => address,
            Self::DestinationTarget => target_ipv4_address,
        }
    }
}

/// Parses a decimal or `0x`-prefixed hexadecimal unsigned integer for ARP header CLI flags.
///
/// # Errors
///
/// Returns a message when `token` is not a decimal or hexadecimal integer in range for `T`.
pub fn parse_u16_cli_token(token: &str) -> Result<u16, String> {
    parse_cli_integer(token, "16-bit")
}

/// Parses a decimal or `0x`-prefixed hexadecimal octet for `ar$hln` / `ar$pln`.
///
/// # Errors
///
/// Returns a message when `token` is not a decimal or hexadecimal integer in `0..=255`.
pub fn parse_u8_cli_token(token: &str) -> Result<u8, String> {
    parse_cli_integer(token, "8-bit")
}

fn parse_cli_integer<T>(token: &str, width_name: &str) -> Result<T, String>
where
    T: TryFrom<u128>,
{
    let trimmed = token.trim();
    let parsed = if let Some(hexadecimal) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u128::from_str_radix(hexadecimal, 16).map_err(|_| {
            format!("invalid hexadecimal integer '{token}': expected a {width_name} value")
        })?
    } else {
        trimmed.parse::<u128>().map_err(|_| {
            format!(
                "invalid integer '{token}': expected a decimal or 0x-prefixed {width_name} value"
            )
        })?
    };
    T::try_from(parsed).map_err(|_| format!("integer '{token}' is outside the {width_name} range"))
}

/// On-wire options for transmitted ARP requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanWireOptions {
    /// When set, transmit an IEEE 802.1Q customer tag (TPID `0x8100`) with this VLAN identifier.
    pub vlan_identifier: Option<Ieee8021qVlanIdentifier>,
    /// IEEE 802.1Q customer Priority Code Point. Ignored when [`Self::vlan_identifier`] is
    /// [`None`].
    pub vlan_priority_code_point: Ieee8021qPriorityCodePoint,
    /// IEEE 802.1Q customer Drop Eligible Indicator. Ignored when [`Self::vlan_identifier`] is
    /// [`None`].
    pub vlan_drop_eligible_indicator: bool,
    /// When set, wrap the customer tag in an IEEE 802.1Q service tag (S-TAG, TPID `0x88A8`) with
    /// this VLAN identifier. Requires [`Self::vlan_identifier`]; see
    /// [`Self::validate_ieee_8021q_tag_stack`].
    pub service_vlan_identifier: Option<Ieee8021qVlanIdentifier>,
    /// IEEE 802.1Q service Priority Code Point. Ignored when [`Self::service_vlan_identifier`] is
    /// [`None`].
    pub service_vlan_priority_code_point: Ieee8021qPriorityCodePoint,
    /// IEEE 802.1Q service Drop Eligible Indicator. Ignored when
    /// [`Self::service_vlan_identifier`] is [`None`].
    pub service_vlan_drop_eligible_indicator: bool,
    /// Value encoded in RFC 826 `ar$spa`.
    pub sender_protocol_address: ArpSenderProtocolAddress,
    /// When true, encapsulate ARP in IEEE 802.3 with RFC 1042 LLC/SNAP instead of Ethernet II.
    pub llc_snap: bool,
    /// Ethernet destination. [`None`] means the broadcast address.
    pub ethernet_destination: Option<MacAddress>,
    /// Ethernet source. [`None`] means the scanning interface MAC.
    pub ethernet_source: Option<MacAddress>,
    /// RFC 826 `ar$hrd` (default Ethernet / 1).
    pub arp_hardware_type: u16,
    /// RFC 826 `ar$pro` (default IPv4 / `0x0800`).
    pub arp_protocol_type: u16,
    /// RFC 826 `ar$hln` (default 6). Does not change encoded SHA/THA widths.
    pub arp_hardware_length: u8,
    /// RFC 826 `ar$pln` (default 4). Does not change encoded SPA/TPA widths.
    pub arp_protocol_length: u8,
    /// RFC 826 `ar$op` (default request / 1).
    pub arp_operation: u16,
    /// RFC 826 `ar$sha`. [`None`] means the scanning interface MAC.
    pub arp_sender_hardware: Option<MacAddress>,
    /// RFC 826 `ar$tha`. [`None`] means all zeroes.
    pub arp_target_hardware: Option<MacAddress>,
    /// Octets appended after the 28-octet ARP PDU (`--padding`). IEEE 802.3 minimum-frame zeroes
    /// are applied after this payload when the frame is still shorter than 60 octets.
    pub padding: Vec<u8>,
}

impl Default for ScanWireOptions {
    fn default() -> Self {
        Self {
            vlan_identifier: None,
            vlan_priority_code_point: Ieee8021qPriorityCodePoint::ZERO,
            vlan_drop_eligible_indicator: false,
            service_vlan_identifier: None,
            service_vlan_priority_code_point: Ieee8021qPriorityCodePoint::ZERO,
            service_vlan_drop_eligible_indicator: false,
            sender_protocol_address: ArpSenderProtocolAddress::Interface,
            llc_snap: false,
            ethernet_destination: None,
            ethernet_source: None,
            arp_hardware_type: ARP_HARDWARE_TYPE_ETHERNET,
            arp_protocol_type: ETHERNET_PROTOCOL_IPV4,
            arp_hardware_length: ARP_ETHERNET_HARDWARE_ADDRESS_LENGTH,
            arp_protocol_length: ARP_IPV4_PROTOCOL_ADDRESS_LENGTH,
            arp_operation: ARP_OPERATION_REQUEST,
            arp_sender_hardware: None,
            arp_target_hardware: None,
            padding: Vec::new(),
        }
    }
}

impl ScanWireOptions {
    /// Resolves CLI/library wire options against one interface and target into an on-wire layout.
    #[must_use]
    pub(crate) fn address_resolution_request_layout(
        &self,
        interface_mac_address: MacAddress,
        sender_protocol_address: Ipv4Addr,
        target_protocol_address: Ipv4Addr,
    ) -> AddressResolutionRequestLayout<'_> {
        AddressResolutionRequestLayout {
            ethernet_destination: self.ethernet_destination.unwrap_or(MacAddress::BROADCAST),
            ethernet_source: self.ethernet_source.unwrap_or(interface_mac_address),
            vlan_tag: self.ieee_8021q_tag_stack(),
            llc_snap: self.llc_snap,
            hardware_type: self.arp_hardware_type,
            protocol_type: self.arp_protocol_type,
            hardware_length: self.arp_hardware_length,
            protocol_length: self.arp_protocol_length,
            opcode: self.arp_operation,
            sender_hardware: self.arp_sender_hardware.unwrap_or(interface_mac_address),
            sender_protocol: sender_protocol_address,
            target_hardware: self.arp_target_hardware.unwrap_or(MacAddress::ZERO),
            target_protocol: target_protocol_address,
            padding: &self.padding,
        }
    }

    /// Resolves the configured VLAN tagging into the encodable tag stack.
    ///
    /// Returns [`None`] when no customer tag is configured. A service tag without a customer tag
    /// cannot be encoded and is reported by [`Self::validate_ieee_8021q_tag_stack`]; it is dropped
    /// here rather than silently emitted as a lone S-TAG.
    #[must_use]
    pub(crate) fn ieee_8021q_tag_stack(&self) -> Option<Ieee8021qTagStack> {
        let customer = Ieee8021qTagControlInformation::new(
            self.vlan_priority_code_point,
            self.vlan_drop_eligible_indicator,
            self.vlan_identifier?,
        );
        let service = self.service_vlan_identifier.map(|service_vlan_identifier| {
            Ieee8021qTagControlInformation::new(
                self.service_vlan_priority_code_point,
                self.service_vlan_drop_eligible_indicator,
                service_vlan_identifier,
            )
        });
        Some(Ieee8021qTagStack::new(service, customer))
    }

    /// Rejects an IEEE 802.1Q service tag that has no customer tag to wrap.
    ///
    /// IEEE 802.1ad provider bridging stacks an S-TAG (`0x88A8`) on a C-TAG (`0x8100`); a lone
    /// S-TAG is not a frame this tool transmits, and the receive parser rejects it too. The CLI
    /// blocks the combination with clap `requires`, so this guards library callers.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError::ServiceVlanTagRequiresCustomerVlanTag`] when
    /// [`Self::service_vlan_identifier`] is set while [`Self::vlan_identifier`] is [`None`].
    pub fn validate_ieee_8021q_tag_stack(&self) -> Result<(), crate::error::AppError> {
        match (self.service_vlan_identifier, self.vlan_identifier) {
            (Some(service_vlan_identifier), None) => Err(
                crate::error::AppError::ServiceVlanTagRequiresCustomerVlanTag {
                    service_vlan_identifier: service_vlan_identifier.as_u16(),
                },
            ),
            _ => Ok(()),
        }
    }

    /// IEEE 802.3 MAC client data length for one transmitted request (LLC/SNAP, ARP, and padding).
    ///
    /// VLAN tags sit before the IEEE 802.3 length field and are therefore not counted here.
    #[must_use]
    pub fn ieee_8023_mac_client_data_octet_count(&self) -> usize {
        let arp_and_padding =
            ADDRESS_RESOLUTION_PROTOCOL_IPV4_PAYLOAD_LENGTH.saturating_add(self.padding.len());
        if self.llc_snap {
            IEEE_8023_LLC_SNAP_HEADER_LENGTH.saturating_add(arp_and_padding)
        } else {
            arp_and_padding
        }
    }

    /// Rejects custom padding that would make MAC client data exceed 1500 octets.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError::Ieee8023MacClientDataExceedsMaximum`] when LLC/SNAP (if
    /// used), the 28-octet ARP PDU, and [`Self::padding`] exceed [`IEEE_8023_MAXIMUM_LENGTH`].
    pub fn validate_ieee_8023_mac_client_data(&self) -> Result<(), crate::error::AppError> {
        let octet_count = self.ieee_8023_mac_client_data_octet_count();
        if octet_count > usize::from(IEEE_8023_MAXIMUM_LENGTH) {
            Err(
                crate::error::AppError::Ieee8023MacClientDataExceedsMaximum {
                    octet_count,
                    maximum: IEEE_8023_MAXIMUM_LENGTH,
                },
            )
        } else {
            Ok(())
        }
    }
}

/// Hex-decoded `--padding` octets. A newtype so clap does not treat `Option<Vec<u8>>` as a list of
/// `u8` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetPaddingOctets(Vec<u8>);

impl EthernetPaddingOctets {
    /// Returns the decoded octets.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the decoded octets.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// Parses original `arp-scan` `--padding` hex: even number of digits, no `0x` prefix.
///
/// # Errors
///
/// Returns a message when `token` is empty, has a `0x` prefix, has an odd number of digits,
/// contains a non-hexadecimal character, or decodes to more than 1472 octets (Ethernet II ARP
/// maximum: IEEE 802.3 MAC client data 1500 minus the 28-octet ARP PDU). SNAP scans may still
/// reject a shorter oversize payload in [`ScanWireOptions::validate_ieee_8023_mac_client_data`].
pub fn parse_ethernet_padding_hex(token: &str) -> Result<EthernetPaddingOctets, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(
            "invalid --padding value: expected an even number of hexadecimal digits".to_string(),
        );
    }
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        return Err("invalid --padding value: hex digits must not include a 0x prefix".to_string());
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err(
            "invalid --padding value: expected an even number of hexadecimal digits".to_string(),
        );
    }
    if !trimmed.bytes().all(|octet| octet.is_ascii_hexdigit()) {
        return Err("invalid --padding value: expected hexadecimal digits".to_string());
    }

    let maximum_octets =
        crate::address_resolution_protocol::maximum_arp_request_padding_octet_count(false);
    let octet_count = trimmed.len() / 2;
    if octet_count > maximum_octets {
        return Err(format!(
            "invalid --padding value: {octet_count} octets exceeds the IEEE 802.3 MAC client data maximum after the 28-octet ARP payload ({maximum_octets} octets)"
        ));
    }

    let digits = trimmed.as_bytes();
    let mut padding = Vec::with_capacity(octet_count);
    let mut index = 0;
    while index < digits.len() {
        let pair = std::str::from_utf8(&digits[index..index + 2])
            .map_err(|_| "invalid --padding value: expected hexadecimal digits".to_string())?;
        let octet = u8::from_str_radix(pair, 16)
            .map_err(|_| "invalid --padding value: expected hexadecimal digits".to_string())?;
        padding.push(octet);
        index += 2;
    }
    Ok(EthernetPaddingOctets(padding))
}

/// Original `arp-scan` backoff factor, used when outbound rate limiting is enabled and `--backoff`
/// is omitted.
pub const DEFAULT_RETRY_BACKOFF_FACTOR: f64 = 1.5;

/// A [`Duration`] that is strictly greater than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PositiveDuration(Duration);

impl PositiveDuration {
    /// Rejects a zero interval.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError::InterTargetIntervalRejected`] when `duration` is zero.
    pub fn new(duration: Duration) -> Result<Self, crate::error::AppError> {
        if duration.is_zero() {
            Err(crate::error::AppError::InterTargetIntervalRejected)
        } else {
            Ok(Self(duration))
        }
    }

    /// Returns the wrapped duration.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

/// Finite retry multiplier of at least `1.0`.
///
/// Equality compares the IEEE-754 bit pattern, so distinct NaN payloads cannot be constructed.
#[derive(Debug, Clone, Copy)]
pub struct RetryBackoffFactor {
    bits: u64,
}

impl PartialEq for RetryBackoffFactor {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits
    }
}

impl Eq for RetryBackoffFactor {}

impl RetryBackoffFactor {
    /// [`DEFAULT_RETRY_BACKOFF_FACTOR`] (`1.5`).
    pub const DEFAULT: Self = Self {
        bits: DEFAULT_RETRY_BACKOFF_FACTOR.to_bits(),
    };

    /// Accepts a finite factor greater than or equal to one.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError::RetryBackoffFactorRejected`] when `factor` is NaN,
    /// infinite, or less than one.
    pub fn new(factor: f64) -> Result<Self, crate::error::AppError> {
        if !factor.is_finite() || factor < 1.0 {
            return Err(crate::error::AppError::RetryBackoffFactorRejected);
        }
        Ok(Self {
            bits: factor.to_bits(),
        })
    }

    /// Returns the factor as `f64`.
    #[must_use]
    pub const fn as_f64(self) -> f64 {
        f64::from_bits(self.bits)
    }
}

/// How a rate-limited scan spaces consecutive address-resolution requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InterTargetSendRate {
    /// Positive bits per second. The scanner derives the interval from the frame that is about to
    /// be sent.
    Bandwidth(NonZeroU64),
    /// Explicit minimum gap between consecutive sends.
    Interval(PositiveDuration),
}

impl InterTargetSendRate {
    /// Rejects a zero bit rate.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError::InterTargetBandwidthRejected`] when `bits_per_second` is
    /// zero. Whether the derived interval fits in [`Duration`] depends on the encoded frame and is
    /// checked when the scan is validated.
    pub fn bandwidth(bits_per_second: u64) -> Result<Self, crate::error::AppError> {
        NonZeroU64::new(bits_per_second)
            .map(Self::Bandwidth)
            .ok_or(crate::error::AppError::InterTargetBandwidthRejected)
    }

    /// Rejects a zero interval.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError::InterTargetIntervalRejected`] when `interval` is zero.
    pub fn interval(interval: Duration) -> Result<Self, crate::error::AppError> {
        Ok(Self::Interval(PositiveDuration::new(interval)?))
    }
}

/// Opt-in outbound rate limit and the retry backoff that applies only on that path.
///
/// When this value is absent from [`ApplicationCommand::Scan`], each round still bursts every
/// target and [`ApplicationCommand::Scan`]'s `pacing` sleeps only between rounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimitedScanTiming {
    send_rate: InterTargetSendRate,
    backoff_factor: RetryBackoffFactor,
}

impl RateLimitedScanTiming {
    /// Builds timing from an already validated rate and backoff factor.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use new_arp_scan::{
    ///     InterTargetSendRate, RateLimitedScanTiming, RetryBackoffFactor,
    /// };
    ///
    /// let timing = RateLimitedScanTiming::new(
    ///     InterTargetSendRate::interval(Duration::from_millis(2))?,
    ///     RetryBackoffFactor::DEFAULT,
    /// );
    /// assert_eq!(timing.backoff_factor().as_f64().to_bits(), 1.5_f64.to_bits());
    /// # Ok::<(), new_arp_scan::AppError>(())
    /// ```
    #[must_use]
    pub const fn new(send_rate: InterTargetSendRate, backoff_factor: RetryBackoffFactor) -> Self {
        Self {
            send_rate,
            backoff_factor,
        }
    }

    /// Returns the outbound send rate.
    #[must_use]
    pub const fn send_rate(self) -> InterTargetSendRate {
        self.send_rate
    }

    /// Returns the per-round retry multiplier.
    #[must_use]
    pub const fn backoff_factor(self) -> RetryBackoffFactor {
        self.backoff_factor
    }
}

/// Parses `--bandwidth`: a positive decimal integer with an optional `K` or `M` decimal suffix.
///
/// `K` is 1,000 and `M` is 1,000,000. The suffix is case-insensitive. Fractional mantissas are
/// rejected.
///
/// # Errors
///
/// Returns a message when `token` is empty, not a positive integer, uses an unknown suffix, or the
/// scaled bit rate does not fit in `u64`.
pub fn parse_bandwidth_bits_per_second(token: &str) -> Result<NonZeroU64, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(
            "invalid --bandwidth value: expected a positive integer bit rate with an optional K or M decimal suffix"
                .to_string(),
        );
    }
    let last = trimmed.as_bytes()[trimmed.len() - 1];
    let (digits, multiplier) = match last {
        b'K' | b'k' => (&trimmed[..trimmed.len() - 1], 1_000_u64),
        b'M' | b'm' => (&trimmed[..trimmed.len() - 1], 1_000_000_u64),
        byte if byte.is_ascii_digit() => (trimmed, 1_u64),
        byte => {
            return Err(format!(
                "invalid --bandwidth value '{token}': unknown suffix '{}'",
                char::from(byte)
            ));
        }
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "invalid --bandwidth value '{token}': expected a positive integer bit rate with an optional K or M decimal suffix"
        ));
    }
    let magnitude = digits.parse::<u64>().map_err(|_| {
        format!("invalid --bandwidth value '{token}': bit rate does not fit in a 64-bit integer")
    })?;
    let bits_per_second = magnitude.checked_mul(multiplier).ok_or_else(|| {
        format!("invalid --bandwidth value '{token}': bit rate does not fit in a 64-bit integer")
    })?;
    NonZeroU64::new(bits_per_second).ok_or_else(|| {
        format!("invalid --bandwidth value '{token}': bandwidth must be greater than zero")
    })
}

/// Parses `--backoff`: a finite decimal factor greater than or equal to one.
///
/// # Errors
///
/// Returns a message when `token` is not a finite factor of at least one.
pub fn parse_retry_backoff_factor(token: &str) -> Result<RetryBackoffFactor, String> {
    let trimmed = token.trim();
    let factor = trimmed.parse::<f64>().map_err(|_| {
        format!(
            "invalid --backoff value '{token}': expected a finite factor greater than or equal to 1"
        )
    })?;
    RetryBackoffFactor::new(factor).map_err(|_| {
        format!(
            "invalid --backoff value '{token}': expected a finite factor greater than or equal to 1"
        )
    })
}

/// Default global receive window after the last address resolution request is sent.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(3);

/// Default delay between full scan rounds (no pacing between rounds).
pub const DEFAULT_SCAN_PACING: Duration = Duration::ZERO;

/// Default number of times each target address receives at least one address resolution request.
pub const DEFAULT_SCAN_ATTEMPTS: NonZeroU64 = NonZeroU64::MIN;

/// Default passive listen window.
pub const DEFAULT_MONITOR_TIMEOUT: Duration = Duration::from_secs(30);

/// A command dispatched from the binary after command-line parsing.
///
/// New commands may be added. Match with a wildcard outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplicationCommand {
    /// Scan the given data-link interface’s local IPv4 subnet using address resolution protocol.
    Scan {
        /// Operating system name of the network interface (for example `eth0`), or [`None`] to
        /// select automatically when exactly one usable interface exists.
        interface_name: Option<String>,
        /// When set, probe only this IPv4 address (strictly interior on the interface subnet).
        target_ipv4_address: Option<Ipv4Addr>,
        /// Global receive window after the final request transmission.
        timeout: Duration,
        /// Delay after each full round of target sends except the last round.
        pacing: Duration,
        /// Total request rounds: each round sends one broadcast request per target.
        attempts: NonZeroU64,
        /// Outbound inter-target rate limit and retry backoff. [`None`] keeps the burst-within-round
        /// path.
        rate_limit: Option<RateLimitedScanTiming>,
        /// IEEE 802.1Q tagging (customer and optional service tag), RFC 826 field overrides,
        /// Ethernet addressing, and RFC 1042 LLC/SNAP.
        wire: ScanWireOptions,
    },
    /// Listen for ARP on one interface without transmitting.
    ///
    /// `timeout` must be greater than zero. `interface_name` uses the same selection rules as
    /// [`Self::Scan`].
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::{AppError, ApplicationCommand, run};
    /// use std::time::Duration;
    ///
    /// let outcome = run(ApplicationCommand::Monitor {
    ///     interface_name: Some("eth0".to_string()),
    ///     timeout: Duration::ZERO,
    /// });
    /// assert!(matches!(outcome, Err(AppError::MonitorTimeoutRejected)));
    /// ```
    Monitor {
        /// Operating system interface name, or [`None`] to select the single usable interface.
        interface_name: Option<String>,
        /// Positive listen window. Zero is rejected before a socket is opened.
        timeout: Duration,
    },
    /// List interfaces that are usable for ARP scanning on Linux.
    UsableInterfacesList,
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationCommand, ArpSenderProtocolAddress, DEFAULT_SCAN_ATTEMPTS, DEFAULT_SCAN_PACING,
        DEFAULT_SCAN_TIMEOUT, EthernetPaddingOctets, InterTargetSendRate, RateLimitedScanTiming,
        RetryBackoffFactor, ScanWireOptions, parse_bandwidth_bits_per_second,
        parse_ethernet_padding_hex, parse_retry_backoff_factor, parse_u8_cli_token,
        parse_u16_cli_token,
    };
    use crate::ethernet_frame::{
        Ieee8021qPriorityCodePoint, Ieee8021qTagControlInformation, Ieee8021qTagStack,
        Ieee8021qVlanIdentifier,
    };
    use crate::mac_address::MacAddress;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::time::Duration;

    #[test]
    fn default_monitor_timeout_is_thirty_seconds() {
        // Arrange
        // Act
        let timeout = super::DEFAULT_MONITOR_TIMEOUT;

        // Assert
        assert_eq!(
            timeout,
            Duration::from_secs(30),
            "passive monitoring should default to a thirty-second listen"
        );
    }

    #[test]
    fn monitor_commands_compare_timeout_and_interface_only() {
        // Arrange
        let first = ApplicationCommand::Monitor {
            interface_name: None,
            timeout: super::DEFAULT_MONITOR_TIMEOUT,
        };
        let second = ApplicationCommand::Monitor {
            interface_name: Some("eth0".to_string()),
            timeout: Duration::from_millis(1),
        };

        // Act
        // Assert
        assert_ne!(first, second);
        assert_eq!(first.clone(), first);
    }

    #[test]
    fn default_scan_timeout_matches_three_seconds() {
        // Arrange
        // Act
        let timeout = DEFAULT_SCAN_TIMEOUT;

        // Assert
        assert_eq!(
            timeout,
            Duration::from_secs(3),
            "default scan timeout should match historical three-second receive window"
        );
    }

    #[test]
    fn default_scan_pacing_is_zero() {
        // Arrange
        // Act
        let pacing = DEFAULT_SCAN_PACING;

        // Assert
        assert_eq!(
            pacing,
            Duration::ZERO,
            "default scan pacing should impose no delay between scan rounds"
        );
    }

    #[test]
    fn default_scan_attempts_is_one() {
        // Arrange
        // Act
        let attempts = DEFAULT_SCAN_ATTEMPTS;

        // Assert
        assert_eq!(
            attempts.get(),
            1,
            "default scan attempts should preserve historical single-round behavior"
        );
    }

    #[test]
    fn scan_command_variants_compare_equal_when_fields_match() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_millis(500),
            pacing: Duration::from_millis(1),
            attempts: NonZeroU64::new(2).expect("two is non-zero"),
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_millis(500),
            pacing: Duration::from_millis(1),
            attempts: NonZeroU64::new(2).expect("two is non-zero"),
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            equal,
            "scan commands with identical fields should compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_timeout_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_secs(1),
            pacing: Duration::ZERO,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: Duration::from_secs(2),
            pacing: Duration::ZERO,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different timeout values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_pacing_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: Duration::from_millis(1),
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: Duration::from_millis(2),
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different pacing values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_interface_name_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth1".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different interface names must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_explicit_interface_differs_from_automatic_none() {
        // Arrange
        let automatic = ApplicationCommand::Scan {
            interface_name: None,
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let explicit = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = automatic == explicit;

        // Assert
        assert!(
            !equal,
            "automatic versus explicit interface selection should not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_attempts_differs() {
        // Arrange
        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: NonZeroU64::new(1).expect("one is non-zero"),
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: NonZeroU64::new(3).expect("three is non-zero"),
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different attempts values must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_target_ipv4_address_differs() {
        // Arrange
        use std::net::Ipv4Addr;

        let subnet_only = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let single_target = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(192, 168, 1, 50)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = subnet_only == single_target;

        // Assert
        assert!(
            !equal,
            "scan commands with different target IPv4 addresses must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_equal_when_target_ipv4_address_is_some_on_both_sides() {
        // Arrange
        use std::net::Ipv4Addr;

        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 7)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 7)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            equal,
            "scan commands with identical non-None targets should compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_both_targets_are_some_but_ipv4_differs() {
        // Arrange
        use std::net::Ipv4Addr;

        let first = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let second = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 2)),
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };

        // Act
        let equal = first == second;

        // Assert
        assert!(
            !equal,
            "scan commands with different Some targets must not compare equal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_vlan_identifier_differs() {
        // Arrange
        let untagged = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let tagged = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions {
                vlan_identifier: Ieee8021qVlanIdentifier::new(10),
                ..ScanWireOptions::default()
            },
        };

        // Act
        let equal = untagged == tagged;

        // Assert
        assert!(
            !equal,
            "scan commands with different VLAN identifiers must not compare equal"
        );
    }

    #[test]
    fn parse_cli_token_accepts_dest_case_insensitively() {
        // Arrange
        // Act
        let lower = ArpSenderProtocolAddress::parse_cli_token("dest");
        let upper = ArpSenderProtocolAddress::parse_cli_token("DEST");
        let mixed = ArpSenderProtocolAddress::parse_cli_token("Dest");

        // Assert
        assert_eq!(
            lower,
            Ok(ArpSenderProtocolAddress::DestinationTarget),
            "lowercase dest should select each target as ar$spa"
        );
        assert_eq!(upper, Ok(ArpSenderProtocolAddress::DestinationTarget));
        assert_eq!(mixed, Ok(ArpSenderProtocolAddress::DestinationTarget));
    }

    #[test]
    fn parse_cli_token_accepts_dotted_quad_including_unspecified() {
        // Arrange
        // Act
        let unspecified = ArpSenderProtocolAddress::parse_cli_token("0.0.0.0");
        let explicit = ArpSenderProtocolAddress::parse_cli_token("10.0.0.9");

        // Assert
        assert_eq!(
            unspecified,
            Ok(ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED)),
            "0.0.0.0 is an RFC 5227 ARP Probe sender protocol address"
        );
        assert_eq!(
            explicit,
            Ok(ArpSenderProtocolAddress::Explicit(Ipv4Addr::new(
                10, 0, 0, 9
            )))
        );
    }

    #[test]
    fn parse_cli_token_rejects_unknown_tokens() {
        // Arrange
        // Act
        let destination_word = ArpSenderProtocolAddress::parse_cli_token("destination");
        let not_ipv4 = ArpSenderProtocolAddress::parse_cli_token("not-an-address");

        // Assert
        let destination_error = destination_word.expect_err("destination is not dest");
        assert!(
            destination_error.contains("invalid --arpspa"),
            "error should name the flag, got: {destination_error}"
        );
        assert!(
            not_ipv4.is_err(),
            "non-IPv4 tokens should fail, got: {not_ipv4:?}"
        );
    }

    #[test]
    fn ipv4_address_for_target_selects_interface_explicit_or_destination() {
        // Arrange
        let interface = Ipv4Addr::new(192, 168, 1, 1);
        let target = Ipv4Addr::new(192, 168, 1, 50);
        let override_address = Ipv4Addr::new(10, 0, 0, 9);

        // Act
        let from_interface =
            ArpSenderProtocolAddress::Interface.ipv4_address_for_target(interface, target);
        let from_explicit = ArpSenderProtocolAddress::Explicit(override_address)
            .ipv4_address_for_target(interface, target);
        let from_probe = ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED)
            .ipv4_address_for_target(interface, target);
        let from_destination =
            ArpSenderProtocolAddress::DestinationTarget.ipv4_address_for_target(interface, target);

        // Assert
        assert_eq!(from_interface, interface);
        assert_eq!(from_explicit, override_address);
        assert_eq!(from_probe, Ipv4Addr::UNSPECIFIED);
        assert_eq!(from_destination, target);
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_sender_protocol_address_or_llc_snap_differs() {
        // Arrange
        let default = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let probe = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions {
                sender_protocol_address: ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED),
                ..ScanWireOptions::default()
            },
        };
        let llc_snap = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions {
                llc_snap: true,
                ..ScanWireOptions::default()
            },
        };

        // Act
        let probe_differs = default == probe;
        let llc_differs = default == llc_snap;

        // Assert
        assert!(
            !probe_differs,
            "RFC 5227 Probe SPA must distinguish Scan commands"
        );
        assert!(
            !llc_differs,
            "RFC 1042 LLC/SNAP framing must distinguish Scan commands"
        );
    }

    #[test]
    fn parse_u16_cli_token_accepts_decimal_and_hexadecimal() {
        // Arrange
        // Act
        let decimal = parse_u16_cli_token("6");
        let hexadecimal = parse_u16_cli_token("0x0800");
        let too_large = parse_u16_cli_token("0x10000");

        // Assert
        assert_eq!(decimal, Ok(6));
        assert_eq!(hexadecimal, Ok(0x0800));
        assert!(
            too_large
                .expect_err("0x10000 exceeds u16")
                .contains("range"),
            "overflow should mention the integer range"
        );
    }

    #[test]
    fn parse_u8_cli_token_rejects_values_above_255() {
        // Arrange
        // Act
        let maximum = parse_u8_cli_token("0xff");
        let overflow = parse_u8_cli_token("256");

        // Assert
        assert_eq!(maximum, Ok(255));
        assert!(overflow.is_err(), "256 is outside an 8-bit field");
    }

    #[test]
    fn request_layout_uses_broadcast_and_interface_mac_by_default() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let spa = Ipv4Addr::new(192, 168, 1, 1);
        let tpa = Ipv4Addr::new(192, 168, 1, 50);

        // Act
        let wire = ScanWireOptions::default();
        let layout = wire.address_resolution_request_layout(interface_mac, spa, tpa);

        // Assert
        assert_eq!(layout.ethernet_destination, MacAddress::BROADCAST);
        assert_eq!(layout.ethernet_source, interface_mac);
        assert_eq!(layout.sender_hardware, interface_mac);
        assert_eq!(layout.target_hardware, MacAddress::ZERO);
        assert_eq!(layout.hardware_type, 1);
        assert_eq!(layout.opcode, 1);
        assert_eq!(layout.sender_protocol, spa);
        assert_eq!(layout.target_protocol, tpa);
    }

    #[test]
    fn request_layout_applies_ethernet_and_arp_hardware_overrides() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let destination = MacAddress::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ethernet_source = MacAddress::from_octets([0x0A; 6]);
        let sender_hardware = MacAddress::from_octets([0xBB; 6]);
        let target_hardware = MacAddress::from_octets([0xCC; 6]);
        let wire = ScanWireOptions {
            ethernet_destination: Some(destination),
            ethernet_source: Some(ethernet_source),
            arp_hardware_type: 6,
            arp_operation: 1,
            arp_sender_hardware: Some(sender_hardware),
            arp_target_hardware: Some(target_hardware),
            ..ScanWireOptions::default()
        };

        // Act
        let layout = wire.address_resolution_request_layout(
            interface_mac,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );

        // Assert
        assert_eq!(layout.ethernet_destination, destination);
        assert_eq!(layout.ethernet_source, ethernet_source);
        assert_eq!(layout.sender_hardware, sender_hardware);
        assert_eq!(layout.target_hardware, target_hardware);
        assert_eq!(layout.hardware_type, 6);
        assert_ne!(layout.ethernet_source, layout.sender_hardware);
    }

    #[test]
    fn parse_ethernet_padding_hex_accepts_even_digits_without_prefix() {
        // Arrange
        // Act
        let padding = parse_ethernet_padding_hex("deadBEEF");

        // Assert
        assert_eq!(
            padding.map(EthernetPaddingOctets::into_vec),
            Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn parse_ethernet_padding_hex_rejects_prefix_odd_length_and_non_hex() {
        // Arrange
        // Act
        let prefixed = parse_ethernet_padding_hex("0xdead");
        let odd = parse_ethernet_padding_hex("abc");
        let not_hex = parse_ethernet_padding_hex("gg");

        // Assert
        assert!(
            prefixed
                .expect_err("0x prefix is not original arp-scan hex")
                .contains("0x"),
            "prefixed padding should mention the 0x restriction"
        );
        assert!(odd.expect_err("odd length").contains("even"));
        assert!(not_hex.is_err(), "non-hex digits should fail");
    }

    #[test]
    fn request_layout_applies_vlan_pcp_dei_and_padding() {
        // Arrange
        let interface_mac = MacAddress::from_octets([0x02, 0, 0, 0, 0, 1]);
        let wire = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(5).expect("PCP 5 fits"),
            vlan_drop_eligible_indicator: true,
            padding: vec![0xDE, 0xAD],
            ..ScanWireOptions::default()
        };

        // Act
        let layout = wire.address_resolution_request_layout(
            interface_mac,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );

        // Assert
        let tag = layout.vlan_tag.expect("VLAN tag should be present");
        assert_eq!(
            tag.customer_tag_control_information().as_u16(),
            0xB00A,
            "PCP 5, DEI 1, VID 10 should encode as customer TCI 0xB00A"
        );
        assert_eq!(
            tag.service_tag_control_information(),
            None,
            "no --svlan means no service tag"
        );
        assert_eq!(layout.padding, &[0xDE, 0xAD]);
    }

    #[test]
    fn snap_padding_that_exceeds_ieee_8023_maximum_is_rejected() {
        // Arrange
        let wire = ScanWireOptions {
            llc_snap: true,
            padding: vec![0; 1465],
            ..ScanWireOptions::default()
        };

        // Act
        let outcome = wire.validate_ieee_8023_mac_client_data();

        // Assert
        assert!(
            matches!(
                outcome,
                Err(crate::error::AppError::Ieee8023MacClientDataExceedsMaximum { .. })
            ),
            "SNAP MAC client data of 8+28+1465 must exceed 1500, got: {outcome:?}"
        );
    }

    #[test]
    fn ethernet_ii_padding_at_ieee_8023_maximum_is_accepted_and_one_octet_over_is_rejected() {
        // Arrange
        let maximum = ScanWireOptions {
            padding: vec![0; 1472],
            ..ScanWireOptions::default()
        };
        let oversize = ScanWireOptions {
            padding: vec![0; 1473],
            ..ScanWireOptions::default()
        };

        // Act
        let accepted = maximum.validate_ieee_8023_mac_client_data();
        let rejected = oversize.validate_ieee_8023_mac_client_data();

        // Assert
        assert!(
            accepted.is_ok(),
            "28+1472 octets is exactly 1500 MAC client data, got: {accepted:?}"
        );
        assert!(
            matches!(
                rejected,
                Err(crate::error::AppError::Ieee8023MacClientDataExceedsMaximum { .. })
            ),
            "28+1473 octets must exceed 1500, got: {rejected:?}"
        );
    }

    #[test]
    fn parse_ethernet_padding_hex_rejects_empty_uppercase_prefix_and_oversize() {
        // Arrange
        // Act
        let empty = parse_ethernet_padding_hex("");
        let whitespace = parse_ethernet_padding_hex("  ");
        let uppercase_prefix = parse_ethernet_padding_hex("0Xdead");
        let oversize = parse_ethernet_padding_hex(&"aa".repeat(1473));
        let maximum = parse_ethernet_padding_hex(&"aa".repeat(1472));

        // Assert
        assert!(
            empty
                .expect_err("empty padding should fail")
                .contains("even number"),
            "empty padding should mention even hex digits"
        );
        assert!(whitespace.is_err(), "whitespace-only padding should fail");
        assert!(
            uppercase_prefix
                .expect_err("0X prefix is not original arp-scan hex")
                .contains("0x"),
            "uppercase 0X prefix should be rejected"
        );
        assert!(
            oversize
                .expect_err("1473 padding octets exceed Ethernet II maximum")
                .contains("1473"),
            "oversize padding should name the octet count"
        );
        assert_eq!(
            maximum
                .expect("1472 padding octets is the Ethernet II maximum")
                .as_slice()
                .len(),
            1472
        );
    }

    #[test]
    fn parse_u8_cli_token_rejects_empty_and_non_integer_tokens() {
        // Arrange
        // Act
        let empty = parse_u8_cli_token("");
        let garbage = parse_u8_cli_token("not-a-number");
        let hexadecimal = parse_u8_cli_token("0X0a");

        // Assert
        assert!(empty.is_err(), "empty 8-bit token should fail");
        assert!(garbage.is_err(), "non-integer 8-bit token should fail");
        assert_eq!(hexadecimal, Ok(10), "0X prefix should parse as hexadecimal");
        let invalid_hex = parse_u8_cli_token("0xzz");
        assert!(
            invalid_hex
                .expect_err("0xzz is not hexadecimal")
                .contains("hexadecimal"),
            "invalid hex after 0x should mention hexadecimal"
        );
    }

    #[test]
    fn scan_command_variants_compare_unequal_when_padding_or_pcp_differs() {
        // Arrange
        let base = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let padding = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions {
                padding: vec![0xAA],
                ..ScanWireOptions::default()
            },
        };
        let priority = ApplicationCommand::Scan {
            interface_name: Some("eth0".to_string()),
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions {
                vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(1).expect("PCP 1 fits"),
                ..ScanWireOptions::default()
            },
        };

        // Act
        // Assert
        assert_ne!(base, padding);
        assert_ne!(base, priority);
        assert_ne!(padding, priority);
    }

    #[test]
    fn tag_stack_is_none_without_a_customer_tag_and_carries_the_service_tag_with_one() {
        // Arrange
        let untagged = ScanWireOptions::default();
        let customer_only = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            ..ScanWireOptions::default()
        };
        let stacked = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
            service_vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(5)
                .expect("PCP 5 fits"),
            service_vlan_drop_eligible_indicator: true,
            ..ScanWireOptions::default()
        };

        // Act
        let untagged_stack = untagged.ieee_8021q_tag_stack();
        let customer_stack = customer_only.ieee_8021q_tag_stack();
        let stacked_stack = stacked.ieee_8021q_tag_stack();

        // Assert
        assert!(untagged_stack.is_none(), "no --vlan means no tag stack");
        assert_eq!(
            customer_stack.and_then(Ieee8021qTagStack::service_tag_control_information),
            None,
            "--vlan alone must not synthesize a service tag"
        );
        assert_eq!(
            stacked_stack
                .and_then(Ieee8021qTagStack::service_tag_control_information)
                .map(Ieee8021qTagControlInformation::as_u16),
            Some(0xB064),
            "service PCP 5, DEI 1, S-VID 100 should encode as TCI 0xB064"
        );
        assert_eq!(
            stacked_stack.map(|stack| stack.customer_tag_control_information().as_u16()),
            Some(0x000A)
        );
    }

    #[test]
    fn validate_tag_stack_accepts_untagged_customer_only_and_stacked_wire_options() {
        // Arrange
        let untagged = ScanWireOptions::default();
        let customer_only = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(0),
            ..ScanWireOptions::default()
        };
        let stacked = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(4095),
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(4095),
            ..ScanWireOptions::default()
        };

        // Act
        let outcomes = [
            untagged.validate_ieee_8021q_tag_stack(),
            customer_only.validate_ieee_8021q_tag_stack(),
            stacked.validate_ieee_8021q_tag_stack(),
        ];

        // Assert
        for outcome in outcomes {
            assert!(
                outcome.is_ok(),
                "a customer tag (or no tag at all) is always valid, got: {outcome:?}"
            );
        }
    }

    #[test]
    fn validate_tag_stack_rejects_a_service_tag_without_a_customer_tag() {
        // Arrange: the library allows the field combination that clap `requires` blocks on the
        // CLI, so it must be rejected before anything reaches the wire.
        let wire = ScanWireOptions {
            vlan_identifier: None,
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
            ..ScanWireOptions::default()
        };

        // Act
        let outcome = wire.validate_ieee_8021q_tag_stack();

        // Assert
        assert!(
            matches!(
                outcome,
                Err(
                    crate::error::AppError::ServiceVlanTagRequiresCustomerVlanTag {
                        service_vlan_identifier: 100
                    }
                )
            ),
            "a lone service tag should name the offending S-VID, got: {outcome:?}"
        );
    }

    #[test]
    fn request_layout_stacks_the_service_tag_outside_the_customer_tag() {
        // Arrange
        let wire = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
            service_vlan_priority_code_point: Ieee8021qPriorityCodePoint::new(5)
                .expect("PCP 5 fits"),
            service_vlan_drop_eligible_indicator: true,
            ..ScanWireOptions::default()
        };
        let interface_mac = MacAddress::from_octets([2, 0, 0, 0, 0, 1]);

        // Act
        let layout = wire.address_resolution_request_layout(
            interface_mac,
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(192, 168, 1, 50),
        );

        // Assert
        let stack = layout.vlan_tag.expect("tag stack should be present");
        assert_eq!(
            stack.outer_tag_protocol_identifier(),
            0x88A8,
            "the outermost TPID on the wire is the service EtherType"
        );
        assert_eq!(
            stack
                .service_tag_control_information()
                .expect("service tag present")
                .vlan_identifier
                .as_u16(),
            100
        );
        assert_eq!(
            stack
                .customer_tag_control_information()
                .vlan_identifier
                .as_u16(),
            10
        );
    }

    #[test]
    fn service_vlan_tagging_does_not_change_ieee_8023_mac_client_data_accounting() {
        // Arrange: VLAN tags sit before the IEEE 802.3 length field, so they never count toward
        // the 1500-octet MAC client data maximum.
        let untagged = ScanWireOptions {
            llc_snap: true,
            padding: vec![0u8; 8],
            ..ScanWireOptions::default()
        };
        let stacked = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            service_vlan_identifier: Ieee8021qVlanIdentifier::new(100),
            ..untagged.clone()
        };

        // Act
        let untagged_octets = untagged.ieee_8023_mac_client_data_octet_count();
        let stacked_octets = stacked.ieee_8023_mac_client_data_octet_count();

        // Assert
        assert_eq!(
            untagged_octets, stacked_octets,
            "an S-TAG and C-TAG must not shift the IEEE 802.3 length field value"
        );
        assert_eq!(stacked_octets, 8 + 28 + 8, "LLC/SNAP + ARP PDU + padding");
    }

    #[test]
    fn parses_bandwidth_suffixes_and_rejects_zero_fractions_and_overflow() {
        // Arrange
        let accepted = [
            ("256K", 256_000_u64),
            ("256k", 256_000),
            ("  1M", 1_000_000),
            ("1m", 1_000_000),
            ("0001K", 1_000),
            ("256000", 256_000),
            (&u64::MAX.to_string(), u64::MAX),
        ];

        // Act
        for (token, bits_per_second) in accepted {
            let parsed = parse_bandwidth_bits_per_second(token).expect("accepted bandwidth");

            // Assert
            assert_eq!(parsed.get(), bits_per_second, "token {token}");
        }

        let overflow = format!("{}K", (u64::MAX / 1_000) + 1);
        let rejected = [
            ("0", "greater than zero"),
            ("0K", "greater than zero"),
            ("1.5K", "positive integer"),
            ("", "positive integer"),
            ("K", "positive integer"),
            ("1G", "unknown suffix"),
            ("+1", "positive integer"),
            ("0x10", "positive integer"),
            (overflow.as_str(), "does not fit"),
        ];
        for (token, expected_fragment) in rejected {
            let message = parse_bandwidth_bits_per_second(token)
                .expect_err("rejected bandwidth")
                .to_lowercase();
            assert!(
                message.contains(expected_fragment),
                "token {token:?} should mention {expected_fragment}, got: {message}"
            );
        }
    }

    #[test]
    fn parses_retry_backoff_and_rejects_non_finite_or_sub_unit_factors() {
        // Arrange
        let accepted = parse_retry_backoff_factor("1.5").expect("1.5 is the default factor");

        // Act
        let unit = parse_retry_backoff_factor("1").expect("1 is a valid factor");
        let below = parse_retry_backoff_factor("0.5");
        let non_finite = parse_retry_backoff_factor("nan");
        let infinite = parse_retry_backoff_factor("inf");

        // Assert
        assert_eq!(accepted, RetryBackoffFactor::DEFAULT);
        assert_eq!(unit.as_f64().to_bits(), 1.0_f64.to_bits());
        for outcome in [below, non_finite, infinite] {
            let message = outcome.expect_err("rejected backoff").to_lowercase();
            assert!(
                message.contains("finite factor"),
                "rejected backoff should name the constraint, got: {message}"
            );
        }
    }

    #[test]
    fn scan_commands_differ_when_only_the_rate_limit_differs() {
        // Arrange
        let burst = ApplicationCommand::Scan {
            interface_name: None,
            target_ipv4_address: None,
            timeout: DEFAULT_SCAN_TIMEOUT,
            pacing: DEFAULT_SCAN_PACING,
            attempts: DEFAULT_SCAN_ATTEMPTS,
            rate_limit: None,
            wire: ScanWireOptions::default(),
        };
        let ApplicationCommand::Scan {
            interface_name,
            target_ipv4_address,
            timeout,
            pacing,
            attempts,
            wire,
            ..
        } = burst.clone()
        else {
            panic!("fixture is a scan command");
        };
        let paced = ApplicationCommand::Scan {
            interface_name,
            target_ipv4_address,
            timeout,
            pacing,
            attempts,
            wire,
            rate_limit: Some(RateLimitedScanTiming::new(
                InterTargetSendRate::bandwidth(256_000).expect("positive bandwidth"),
                RetryBackoffFactor::DEFAULT,
            )),
        };

        // Act
        let same = burst == burst.clone();
        let different = burst != paced;

        // Assert
        assert!(same);
        assert!(different);
    }

    #[test]
    fn rejects_a_zero_interval_and_a_zero_bandwidth_at_the_typed_boundary() {
        // Arrange
        let zero_interval = InterTargetSendRate::interval(std::time::Duration::ZERO);
        let zero_bandwidth = InterTargetSendRate::bandwidth(0);

        // Act
        let interval_error = zero_interval.expect_err("zero interval");
        let bandwidth_error = zero_bandwidth.expect_err("zero bandwidth");

        // Assert
        assert!(matches!(
            interval_error,
            crate::error::AppError::InterTargetIntervalRejected
        ));
        assert!(matches!(
            bandwidth_error,
            crate::error::AppError::InterTargetBandwidthRejected
        ));
    }
}
