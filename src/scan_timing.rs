//! Checked outbound rate limiting for address-resolution scans.
//!
//! The scan runs on the calling thread. [`ScanClock`] implementations sleep on that thread; they are
//! not shared across tasks, and this module does not start an async runtime.

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::thread;
use std::time::{Duration, Instant};

use crate::address_resolution_protocol::encode_address_resolution_request_from_layout;
use crate::application_command::{
    InterTargetSendRate, RateLimitedScanTiming, RetryBackoffFactor, ScanWireOptions,
};
use crate::error::{AppError, ScanTimingLimit};
use crate::mac_address::MacAddress;

/// Ethernet frame check sequence counted in the on-wire bit budget, but not present in the buffer
/// passed to the kernel.
const ETHERNET_FRAME_CHECK_SEQUENCE_OCTETS: usize = 4;

/// IEEE 802.3 minimum on-wire length including the frame check sequence (64 octets).
const MINIMUM_ON_WIRE_OCTETS: usize = 64;

const NANOSECONDS_PER_SECOND: u128 = 1_000_000_000;

/// Bits in an IEEE-754 binary64 significand, including the implicit leading one.
const BINARY64_SIGNIFICAND_BITS: u32 = 53;

/// Monotonic time source used by one scan on the calling thread.
pub(crate) trait ScanClock {
    /// Instant type compared and advanced by this clock.
    type Timestamp: Copy + Ord;

    /// Returns the current monotonic time.
    fn now(&self) -> Self::Timestamp;

    /// Adds `duration` to `timestamp` when the result is representable.
    fn checked_add(
        &self,
        timestamp: Self::Timestamp,
        duration: Duration,
    ) -> Option<Self::Timestamp>;

    /// Returns the non-negative span from `earlier` to `later`.
    fn saturating_duration_since(
        &self,
        later: Self::Timestamp,
        earlier: Self::Timestamp,
    ) -> Duration;

    /// Blocks until `deadline` when it is still in the future.
    fn sleep_until(&self, deadline: Self::Timestamp);

    /// Blocks for `duration` when it is non-zero.
    fn sleep_for(&self, duration: Duration);

    /// Accounts for a link-layer wait that already returned not-readable.
    ///
    /// The production clock does nothing because `poll` has already consumed the wait. A fake clock
    /// advances so tests do not busy-spin.
    fn advance_after_unreadable_wait(&self, _waited: Duration) {}

    /// Called after each request transmission so a test clock can inject lateness.
    fn after_send(&self) {}
}

/// Production monotonic clock backed by [`Instant`] and [`thread::sleep`].
#[derive(Debug, Default)]
pub(crate) struct SystemScanClock;

impl ScanClock for SystemScanClock {
    type Timestamp = Instant;

    fn now(&self) -> Self::Timestamp {
        Instant::now()
    }

    fn checked_add(
        &self,
        timestamp: Self::Timestamp,
        duration: Duration,
    ) -> Option<Self::Timestamp> {
        timestamp.checked_add(duration)
    }

    fn saturating_duration_since(
        &self,
        later: Self::Timestamp,
        earlier: Self::Timestamp,
    ) -> Duration {
        later.saturating_duration_since(earlier)
    }

    fn sleep_until(&self, deadline: Self::Timestamp) {
        let now = Instant::now();
        if let Some(delay) = deadline.checked_duration_since(now)
            && !delay.is_zero()
        {
            thread::sleep(delay);
        }
    }

    fn sleep_for(&self, duration: Duration) {
        if !duration.is_zero() {
            thread::sleep(duration);
        }
    }
}

/// Validated inter-target interval and the backoff used for per-round receive windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScheduledRateLimit {
    /// Strict minimum gap between consecutive send completions.
    pub interval: Duration,
    /// Finite factor of at least one applied as `timeout * factor^round`.
    pub backoff_factor: RetryBackoffFactor,
}

/// On-wire octet count used to turn a bit rate into an inter-send interval.
///
/// The count is `max(encoded_frame_len + 4, 64)`: the buffer the scanner hands to the kernel, plus
/// the 4-octet frame check sequence, and at least the IEEE 802.3 64-octet minimum.
#[must_use]
pub(crate) fn on_wire_octets_for_send_rate(encoded_frame_len: usize) -> usize {
    encoded_frame_len
        .saturating_add(ETHERNET_FRAME_CHECK_SEQUENCE_OCTETS)
        .max(MINIMUM_ON_WIRE_OCTETS)
}

/// Ceiling of `on_wire_octets * 8 * 1_000_000_000 / bits_per_second` nanoseconds.
///
/// # Errors
///
/// Returns [`AppError::ScanTimingExceedsLimit`] with [`ScanTimingLimit::BandwidthInterval`] when
/// the ceiling does not fit in [`Duration`].
pub(crate) fn inter_send_interval_from_bandwidth(
    encoded_frame_len: usize,
    bits_per_second: NonZeroU64,
) -> Result<Duration, AppError> {
    let octets = u128::try_from(on_wire_octets_for_send_rate(encoded_frame_len)).map_err(|_| {
        AppError::ScanTimingExceedsLimit {
            limit: ScanTimingLimit::BandwidthInterval,
        }
    })?;
    let nanos = octets
        .checked_mul(8)
        .and_then(|bits| bits.checked_mul(NANOSECONDS_PER_SECOND))
        .ok_or(AppError::ScanTimingExceedsLimit {
            limit: ScanTimingLimit::BandwidthInterval,
        })?;
    let interval_nanos = nanos.div_ceil(u128::from(bits_per_second.get()));
    duration_from_nanos_u128(interval_nanos).ok_or(AppError::ScanTimingExceedsLimit {
        limit: ScanTimingLimit::BandwidthInterval,
    })
}

/// Receive window for zero-based `round_index`: `timeout * backoff^round_index`, rounded up.
///
/// # Errors
///
/// Returns [`AppError::ScanTimingExceedsLimit`] with [`ScanTimingLimit::RetryReceiveWindow`] when
/// the scaled window is not finite or does not fit in [`Duration`].
pub(crate) fn retry_receive_window(
    timeout: Duration,
    backoff_factor: RetryBackoffFactor,
    round_index: u64,
) -> Result<Duration, AppError> {
    scale_duration_by_backoff(timeout, backoff_factor, round_index).ok_or(
        AppError::ScanTimingExceedsLimit {
            limit: ScanTimingLimit::RetryReceiveWindow,
        },
    )
}

/// Checks rate-limit arithmetic before interface discovery or a raw socket is opened.
///
/// # Errors
///
/// Returns [`AppError::ScanTimingExceedsLimit`] when the derived interval, the inter-round gap, or
/// any planned retry window does not fit in [`Duration`].
pub(crate) fn validate_scan_timing_before_socket(
    timeout: Duration,
    pacing: Duration,
    attempts: NonZeroU64,
    wire: &ScanWireOptions,
    rate_limit: Option<RateLimitedScanTiming>,
) -> Result<Option<ScheduledRateLimit>, AppError> {
    let Some(rate_limit) = rate_limit else {
        return Ok(None);
    };
    let interval = match rate_limit.send_rate() {
        InterTargetSendRate::Bandwidth(bits_per_second) => inter_send_interval_from_bandwidth(
            encoded_address_resolution_request_len(wire),
            bits_per_second,
        )?,
        InterTargetSendRate::Interval(interval) => interval.as_duration(),
    };
    if attempts.get() > 1 && interval.checked_add(pacing).is_none() {
        return Err(AppError::ScanTimingExceedsLimit {
            limit: ScanTimingLimit::InterRoundGap,
        });
    }
    let last_round_index = attempts.get() - 1;
    retry_receive_window(timeout, rate_limit.backoff_factor(), last_round_index)?;
    Ok(Some(ScheduledRateLimit {
        interval,
        backoff_factor: rate_limit.backoff_factor(),
    }))
}

fn encoded_address_resolution_request_len(wire: &ScanWireOptions) -> usize {
    let layout = wire.address_resolution_request_layout(
        MacAddress::ZERO,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
    );
    encode_address_resolution_request_from_layout(layout).len()
}

fn scale_duration_by_backoff(
    duration: Duration,
    backoff_factor: RetryBackoffFactor,
    exponent: u64,
) -> Option<Duration> {
    if exponent == 0 || duration.is_zero() {
        return Some(duration);
    }
    let factor = backoff_factor.as_f64();
    if factor.to_bits() == 1.0_f64.to_bits() {
        return Some(duration);
    }
    let exponent = i32::try_from(exponent).ok()?;
    let power = factor.powi(exponent);
    if !power.is_finite() || power < 1.0 {
        return None;
    }
    let scaled_nanos = checked_mul_ceil_u128_f64(duration.as_nanos(), power)?;
    duration_from_nanos_u128(scaled_nanos)
}

/// Ceiling of `value * factor` for a finite `factor` of at least one, using integer arithmetic.
fn checked_mul_ceil_u128_f64(value: u128, factor: f64) -> Option<u128> {
    if !factor.is_finite() || factor < 1.0 {
        return None;
    }
    if value == 0 || factor.to_bits() == 1.0_f64.to_bits() {
        return Some(value);
    }
    let bits = factor.to_bits();
    let exponent_field = i32::try_from((bits >> 52) & 0x7ff).ok()?;
    if exponent_field == 0 || exponent_field == 0x7ff {
        return None;
    }
    let fraction_field = bits & ((1_u64 << (BINARY64_SIGNIFICAND_BITS - 1)) - 1);
    let significand = (1_u128 << (BINARY64_SIGNIFICAND_BITS - 1)) | u128::from(fraction_field);
    let shift = exponent_field - 1023 - i32::try_from(BINARY64_SIGNIFICAND_BITS - 1).ok()?;
    let product = value.checked_mul(significand)?;
    if shift >= 0 {
        let left_shift = u32::try_from(shift).ok()?;
        return product.checked_shl(left_shift);
    }
    let right_shift = u32::try_from(shift.checked_neg()?).ok()?;
    if right_shift >= u128::BITS {
        return Some(u128::from(product > 0));
    }
    let divisor = 1_u128 << right_shift;
    Some(product.div_ceil(divisor))
}

fn duration_from_nanos_u128(nanos: u128) -> Option<Duration> {
    let seconds = u64::try_from(nanos / NANOSECONDS_PER_SECOND).ok()?;
    let subsecond_nanos = u32::try_from(nanos % NANOSECONDS_PER_SECOND).ok()?;
    Some(Duration::new(seconds, subsecond_nanos))
}

#[cfg(test)]
mod tests {
    use super::{
        MINIMUM_ON_WIRE_OCTETS, NANOSECONDS_PER_SECOND, ScanClock, ScheduledRateLimit,
        SystemScanClock, checked_mul_ceil_u128_f64, inter_send_interval_from_bandwidth,
        on_wire_octets_for_send_rate, retry_receive_window, validate_scan_timing_before_socket,
    };
    use crate::application_command::{
        InterTargetSendRate, RateLimitedScanTiming, RetryBackoffFactor, ScanWireOptions,
    };
    use crate::error::{AppError, ScanTimingLimit};
    use crate::ethernet_frame::Ieee8021qVlanIdentifier;
    use std::num::NonZeroU64;
    use std::time::Duration;

    fn scheduled_interval(wire: &ScanWireOptions, bits_per_second: u64) -> Duration {
        let rate_limit = RateLimitedScanTiming::new(
            InterTargetSendRate::bandwidth(bits_per_second).expect("non-zero bandwidth"),
            RetryBackoffFactor::DEFAULT,
        );
        match validate_scan_timing_before_socket(
            Duration::from_secs(3),
            Duration::ZERO,
            NonZeroU64::MIN,
            wire,
            Some(rate_limit),
        )
        .expect("minimum-frame intervals fit")
        {
            Some(ScheduledRateLimit { interval, .. }) => interval,
            None => panic!("bandwidth scheduling should be present"),
        }
    }

    #[test]
    fn default_arp_request_at_256_kilobits_is_two_milliseconds() {
        // Arrange
        let bits_per_second = NonZeroU64::new(256_000).expect("non-zero");

        // Act
        let interval = inter_send_interval_from_bandwidth(60, bits_per_second).expect("2 ms fits");

        // Assert
        assert_eq!(
            on_wire_octets_for_send_rate(60),
            MINIMUM_ON_WIRE_OCTETS,
            "a 60-octet buffer plus the frame check sequence is the 64-octet floor"
        );
        assert_eq!(interval, Duration::from_millis(2));
    }

    #[test]
    fn interval_grows_when_vlan_llc_or_padding_grows_the_encoded_frame() {
        // Arrange
        let padding_past_minimum = vec![0_u8; 19];
        let minimum = ScanWireOptions::default();
        let vlan_only = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            ..ScanWireOptions::default()
        };
        let padded = ScanWireOptions {
            padding: padding_past_minimum.clone(),
            ..ScanWireOptions::default()
        };
        let vlan_and_padded = ScanWireOptions {
            vlan_identifier: Ieee8021qVlanIdentifier::new(10),
            padding: padding_past_minimum.clone(),
            ..ScanWireOptions::default()
        };
        let llc_and_padded = ScanWireOptions {
            llc_snap: true,
            padding: padding_past_minimum,
            ..ScanWireOptions::default()
        };

        // Act
        let minimum_interval = scheduled_interval(&minimum, 256_000);
        let vlan_interval = scheduled_interval(&vlan_only, 256_000);
        let padded_interval = scheduled_interval(&padded, 256_000);
        let vlan_padded_interval = scheduled_interval(&vlan_and_padded, 256_000);
        let llc_padded_interval = scheduled_interval(&llc_and_padded, 256_000);

        // Assert
        assert_eq!(minimum_interval, Duration::from_millis(2));
        assert_eq!(
            vlan_interval, minimum_interval,
            "a VLAN tag absorbed by the 60-octet pad stays on the 64-octet on-wire floor"
        );
        // 19 octets of padding make an untagged frame 61 octets (65 on the wire with FCS).
        // A customer tag adds 4 octets (69 on the wire). LLC/SNAP adds 8 octets to the
        // untagged header (73 on the wire). 256 kbit/s divides each of those bit budgets evenly.
        assert_eq!(padded_interval, Duration::from_nanos(2_031_250));
        assert_eq!(vlan_padded_interval, Duration::from_nanos(2_156_250));
        assert_eq!(llc_padded_interval, Duration::from_nanos(2_281_250));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn rejects_bandwidth_interval_that_does_not_fit_in_duration() {
        // Arrange
        let bits_per_second = NonZeroU64::new(1).expect("non-zero");
        let encoded_frame_len = usize::try_from(3_000_000_000_000_000_000_u64)
            .expect("the length fits in 64-bit usize");

        // Act
        let outcome = inter_send_interval_from_bandwidth(encoded_frame_len, bits_per_second);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::BandwidthInterval,
                })
            ),
            "a multi-exabyte frame at 1 bit/s cannot be a Duration, got: {outcome:?}"
        );
    }

    #[test]
    fn maximum_bit_rate_still_waits_one_nanosecond_for_the_minimum_frame() {
        // Arrange
        let bits_per_second = NonZeroU64::MAX;

        // Act
        let interval = inter_send_interval_from_bandwidth(60, bits_per_second)
            .expect("ceil of a fraction of a nanosecond is one nanosecond");

        // Assert
        assert_eq!(interval, Duration::from_nanos(1));
    }

    #[test]
    fn retry_windows_follow_backoff_and_reject_overflow() {
        // Arrange
        let timeout = Duration::from_millis(1_000);
        let backoff = RetryBackoffFactor::new(1.5).expect("1.5 is a valid factor");

        // Act
        let first = retry_receive_window(timeout, backoff, 0).expect("round zero is the timeout");
        let second = retry_receive_window(timeout, backoff, 1).expect("1.5x fits");
        let third = retry_receive_window(timeout, backoff, 2).expect("2.25x fits");
        let overflow = retry_receive_window(Duration::from_secs(3), backoff, 10_000);

        // Assert
        assert_eq!(first, timeout);
        assert_eq!(second, Duration::from_millis(1_500));
        assert_eq!(third, Duration::from_millis(2_250));
        assert!(
            matches!(
                overflow,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::RetryReceiveWindow,
                })
            ),
            "a huge exponent must fail closed, got: {overflow:?}"
        );
        let zero_later_round = retry_receive_window(Duration::ZERO, backoff, 4)
            .expect("a zero timeout stays zero on later rounds");
        assert_eq!(zero_later_round, Duration::ZERO);
        let exponent_past_i32 = u64::try_from(i32::MAX).expect("i32::MAX fits in u64") + 1;
        let exponent_overflow =
            retry_receive_window(Duration::from_millis(1), backoff, exponent_past_i32);
        assert!(
            matches!(
                exponent_overflow,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::RetryReceiveWindow,
                })
            ),
            "an exponent that does not fit in i32 must fail closed, got: {exponent_overflow:?}"
        );
        let scaled_past_duration = retry_receive_window(Duration::from_secs(u64::MAX), backoff, 1);
        assert!(
            matches!(
                scaled_past_duration,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::RetryReceiveWindow,
                })
            ),
            "1.5 times the maximum whole-second timeout must not fit in Duration, got: {scaled_past_duration:?}"
        );
    }

    #[test]
    fn unit_backoff_accepts_the_maximum_attempt_count_without_iterating_rounds() {
        // Arrange
        let rate_limit = RateLimitedScanTiming::new(
            InterTargetSendRate::interval(Duration::from_millis(1)).expect("1 ms"),
            RetryBackoffFactor::new(1.0).expect("unit factor"),
        );

        // Act
        let outcome = validate_scan_timing_before_socket(
            Duration::from_secs(3),
            Duration::ZERO,
            NonZeroU64::MAX,
            &ScanWireOptions::default(),
            Some(rate_limit),
        );

        // Assert
        let scheduled = outcome
            .expect("backoff 1 must not scale the window or walk every round")
            .expect("a rate limit is present");
        assert_eq!(scheduled.interval, Duration::from_millis(1));
        assert_eq!(
            scheduled.backoff_factor.as_f64().to_bits(),
            1.0_f64.to_bits()
        );
    }

    #[test]
    fn one_round_accepts_an_interval_that_cannot_be_added_to_pacing() {
        // Arrange: pacing is not applied after the only round, so the sum is never formed.
        let rate_limit = RateLimitedScanTiming::new(
            InterTargetSendRate::interval(Duration::MAX).expect("max duration is non-zero"),
            RetryBackoffFactor::new(1.0).expect("unit factor"),
        );

        // Act
        let outcome = validate_scan_timing_before_socket(
            Duration::ZERO,
            Duration::from_nanos(1),
            NonZeroU64::MIN,
            &ScanWireOptions::default(),
            Some(rate_limit),
        );

        // Assert
        let scheduled = outcome
            .expect(
                "a single round must not reject an interval that overflows when added to pacing",
            )
            .expect("a rate limit is present");
        assert_eq!(scheduled.interval, Duration::MAX);
    }

    #[test]
    fn rejects_inter_round_gap_that_overflows_duration() {
        // Arrange
        let rate_limit = RateLimitedScanTiming::new(
            InterTargetSendRate::interval(Duration::MAX).expect("max duration is non-zero"),
            RetryBackoffFactor::DEFAULT,
        );

        // Act
        let outcome = validate_scan_timing_before_socket(
            Duration::ZERO,
            Duration::from_nanos(1),
            NonZeroU64::new(2).expect("two rounds"),
            &ScanWireOptions::default(),
            Some(rate_limit),
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::ScanTimingExceedsLimit {
                    limit: ScanTimingLimit::InterRoundGap,
                })
            ),
            "interval plus pacing must fail before a socket would open, got: {outcome:?}"
        );
    }

    #[test]
    fn absent_rate_limit_skips_schedule_validation() {
        // Arrange
        // Act
        let outcome = validate_scan_timing_before_socket(
            Duration::from_secs(3),
            Duration::MAX,
            NonZeroU64::MAX,
            &ScanWireOptions::default(),
            None,
        );

        // Assert
        assert_eq!(outcome.expect("the burst path has no rate schedule"), None);
    }

    #[test]
    fn integer_scaling_ceil_matches_exact_binary_factors() {
        // Arrange
        let value = 2_000_000_000_u128;

        // Act
        let same = checked_mul_ceil_u128_f64(value, 1.0);
        let one_and_a_half = checked_mul_ceil_u128_f64(value, 1.5);
        let doubled = checked_mul_ceil_u128_f64(value, 2.0);

        // Assert
        assert_eq!(same, Some(value));
        assert_eq!(one_and_a_half, Some(3_000_000_000));
        assert_eq!(doubled, Some(4_000_000_000));
        assert_eq!(
            checked_mul_ceil_u128_f64(3, 1.5),
            Some(5),
            "a half-step must round away from zero"
        );
        assert_eq!(checked_mul_ceil_u128_f64(0, 1.5), Some(0));
        assert_eq!(checked_mul_ceil_u128_f64(4, f64::NAN), None);
        assert_eq!(checked_mul_ceil_u128_f64(4, f64::INFINITY), None);
        assert_eq!(checked_mul_ceil_u128_f64(4, 0.5), None);
        assert_eq!(checked_mul_ceil_u128_f64(u128::MAX, 1.5), None);
        let two_to_the_53 = 2.0_f64.powi(53);
        assert_eq!(
            checked_mul_ceil_u128_f64(3, two_to_the_53),
            Some(3_u128 << 53),
            "an exact power of two at or above 2^52 takes the left-shift path"
        );
    }

    #[test]
    fn system_clock_checked_add_rejects_a_duration_past_the_monotonic_limit() {
        // Arrange
        let clock = SystemScanClock;
        let now = clock.now();

        // Act
        let outcome = clock.checked_add(now, Duration::MAX);

        // Assert
        assert!(
            outcome.is_none(),
            "adding Duration::MAX to a live Instant is not representable"
        );
    }

    proptest::proptest! {
        #[test]
        fn bandwidth_interval_is_the_shortest_duration_that_covers_the_bit_budget(
            encoded_frame_len in 0_usize..4_096,
            bits_per_second in 1_u64..50_000_000,
        ) {
            let bits = std::num::NonZeroU64::new(bits_per_second).expect("generator starts at 1");
            let interval = inter_send_interval_from_bandwidth(encoded_frame_len, bits)
                .expect("these bounds fit in Duration");
            let on_wire_bits =
                u128::try_from(on_wire_octets_for_send_rate(encoded_frame_len)).expect("usize fits in u128")
                    * 8;
            let nanos = interval.as_nanos();
            let rate = u128::from(bits_per_second);
            let carried_bits = nanos.saturating_mul(rate) / NANOSECONDS_PER_SECOND;
            proptest::prop_assert!(carried_bits >= on_wire_bits);
            if nanos > 0 {
                let shorter = nanos - 1;
                let short_bits = shorter.saturating_mul(rate) / NANOSECONDS_PER_SECOND;
                proptest::prop_assert!(short_bits < on_wire_bits);
            }
        }
    }
}

#[cfg(test)]
pub(crate) use fake_clock::FakeScanClock;

#[cfg(test)]
mod fake_clock {
    use super::{ScanClock, duration_from_nanos_u128};
    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    /// Deterministic monotonic clock for scan scheduling tests.
    #[derive(Debug)]
    pub(crate) struct FakeScanClock {
        now_ns: Cell<u128>,
        sleeps: RefCell<Vec<Duration>>,
        unreadable_waits: RefCell<Vec<Duration>>,
        stall_after_next_send: Cell<Duration>,
    }

    impl FakeScanClock {
        pub(crate) fn new() -> Self {
            Self {
                now_ns: Cell::new(0),
                sleeps: RefCell::new(Vec::new()),
                unreadable_waits: RefCell::new(Vec::new()),
                stall_after_next_send: Cell::new(Duration::ZERO),
            }
        }

        pub(crate) fn arm_stall_after_next_send(&self, stall: Duration) {
            self.stall_after_next_send.set(stall);
        }

        pub(crate) fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.borrow().clone()
        }

        pub(crate) fn unreadable_waits(&self) -> Vec<Duration> {
            self.unreadable_waits.borrow().clone()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) struct FakeTimestamp(u128);

    impl ScanClock for FakeScanClock {
        type Timestamp = FakeTimestamp;

        fn now(&self) -> Self::Timestamp {
            FakeTimestamp(self.now_ns.get())
        }

        fn checked_add(
            &self,
            timestamp: Self::Timestamp,
            duration: Duration,
        ) -> Option<Self::Timestamp> {
            timestamp
                .0
                .checked_add(duration.as_nanos())
                .map(FakeTimestamp)
        }

        fn saturating_duration_since(
            &self,
            later: Self::Timestamp,
            earlier: Self::Timestamp,
        ) -> Duration {
            duration_from_nanos_u128(later.0.saturating_sub(earlier.0)).unwrap_or(Duration::MAX)
        }

        fn sleep_until(&self, deadline: Self::Timestamp) {
            let now = self.now_ns.get();
            if deadline.0 > now {
                let delta = deadline.0 - now;
                if let Some(duration) = duration_from_nanos_u128(delta) {
                    self.sleeps.borrow_mut().push(duration);
                    self.now_ns.set(deadline.0);
                }
            }
        }

        fn sleep_for(&self, duration: Duration) {
            if duration.is_zero() {
                return;
            }
            self.sleeps.borrow_mut().push(duration);
            self.now_ns
                .set(self.now_ns.get().saturating_add(duration.as_nanos()));
        }

        fn advance_after_unreadable_wait(&self, waited: Duration) {
            if waited.is_zero() {
                return;
            }
            self.unreadable_waits.borrow_mut().push(waited);
            self.now_ns
                .set(self.now_ns.get().saturating_add(waited.as_nanos()));
        }

        fn after_send(&self) {
            let stall = self.stall_after_next_send.replace(Duration::ZERO);
            if !stall.is_zero() {
                self.now_ns
                    .set(self.now_ns.get().saturating_add(stall.as_nanos()));
            }
        }
    }

    #[test]
    fn sleep_until_records_nothing_when_the_deadline_is_already_past() {
        // Arrange
        let clock = FakeScanClock::new();
        clock.sleep_for(Duration::from_millis(50));
        clock.sleeps.borrow_mut().clear();

        // Act
        clock.sleep_until(
            clock
                .checked_add(clock.now(), Duration::ZERO)
                .expect("zero add"),
        );
        let earlier = FakeTimestamp(0);
        clock.sleep_until(earlier);

        // Assert
        assert!(
            clock.sleeps().is_empty(),
            "a deadline that is not in the future must not create a catch-up sleep, got: {:?}",
            clock.sleeps()
        );
    }
}
