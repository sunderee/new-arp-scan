//! IPv4 classless inter-domain routing notation parsing and lazy host address expansion.

use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::error::AppError;
use crate::ipv4_subnet::inclusive_host_address_range_excluding_edges;

/// Parsed IPv4 address plus prefix length (for example `192.168.1.10/24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    /// Any IPv4 address inside the subnet (typically the network address or interface address).
    pub ipv4_address: Ipv4Addr,
    /// Prefix length in bits (`0` through `32`, inclusive).
    pub prefix_length: u8,
}

impl Ipv4Cidr {
    /// Returns an iterator over usable host addresses, excluding network and broadcast, using the
    /// same rules as [`inclusive_host_address_range_excluding_edges`](crate::ipv4_subnet::inclusive_host_address_range_excluding_edges).
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Ipv4SubnetUnsupported`] when the prefix is `/31`, `/32`, or when no
    /// interior host range exists. Returns [`AppError::Ipv4NetmaskInvalid`] when the subnet netmask
    /// implied by `prefix_length` is rejected by the shared subnet helper (should not occur for
    /// integral `prefix_length` values in `0..=32`).
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::Ipv4Cidr;
    /// use std::convert::TryFrom;
    ///
    /// let cidr = Ipv4Cidr::try_from("192.168.1.10/24")?;
    /// let mut iterator = cidr.host_address_iterator()?;
    /// assert_eq!(iterator.next(), Some(std::net::Ipv4Addr::new(192, 168, 1, 1)));
    /// # Ok::<(), new_arp_scan::AppError>(())
    /// ```
    pub fn host_address_iterator(&self) -> Result<Ipv4HostAddressIterator, AppError> {
        let ipv4_netmask = contiguous_ipv4_netmask_from_prefix_length(self.prefix_length);
        Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(self.ipv4_address, ipv4_netmask)
    }
}

/// Iterator over IPv4 host addresses between network and broadcast (exclusive), without allocating
/// the full sequence.
#[derive(Clone, Debug)]
pub struct Ipv4HostAddressIterator {
    next_host_bits: Option<u32>,
    last_host_bits: u32,
}

impl Ipv4HostAddressIterator {
    /// Builds an iterator from an on-wire IPv4 address and contiguous subnet netmask.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Ipv4SubnetUnsupported`] or [`AppError::Ipv4NetmaskInvalid`] with the
    /// same conditions as [`inclusive_host_address_range_excluding_edges`](crate::ipv4_subnet::inclusive_host_address_range_excluding_edges).
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::Ipv4HostAddressIterator;
    /// use std::net::Ipv4Addr;
    ///
    /// let netmask = Ipv4Addr::new(255, 255, 255, 0);
    /// let mut iterator = Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(
    ///     Ipv4Addr::new(192, 168, 1, 10),
    ///     netmask,
    /// )?;
    /// assert_eq!(iterator.next(), Some(Ipv4Addr::new(192, 168, 1, 1)));
    /// # Ok::<(), new_arp_scan::AppError>(())
    /// ```
    pub fn try_from_ipv4_address_on_subnet(
        ipv4_address: Ipv4Addr,
        ipv4_netmask: Ipv4Addr,
    ) -> Result<Self, AppError> {
        let (first_host_bits, last_host_bits) =
            inclusive_host_address_range_excluding_edges(ipv4_address, ipv4_netmask)?;
        Ok(Self {
            next_host_bits: Some(first_host_bits),
            last_host_bits,
        })
    }
}

impl Iterator for Ipv4HostAddressIterator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        let current_bits = self.next_host_bits?;
        let item = Ipv4Addr::from_bits(current_bits);
        if current_bits == self.last_host_bits {
            self.next_host_bits = None;
        } else {
            self.next_host_bits = Some(current_bits + 1);
        }
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.next_host_bits {
            None => (0, Some(0)),
            Some(first_host_bits) => {
                let span = u64::from(self.last_host_bits - first_host_bits).saturating_add(1);
                // Interior IPv4 host ranges contain at most `2^32 - 2` addresses, which fits
                // `usize` on every host this crate is built and tested on.
                match usize::try_from(span) {
                    Ok(count) => (count, Some(count)),
                    Err(_) => (0, None),
                }
            }
        }
    }
}

impl TryFrom<&str> for Ipv4Cidr {
    type Error = AppError;

    /// Parses `value` as `dotted_decimal_ipv4 '/' decimal_prefix` after trimming leading and
    /// trailing ASCII whitespace only.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Ipv4CidrStringInvalid`] when the string is empty, missing exactly one
    /// slash separator, contains extra `/` segments, fails IPv4 address parsing, has a non-decimal
    /// prefix, or has a prefix greater than `32`.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::Ipv4Cidr;
    /// use std::convert::TryFrom;
    ///
    /// let cidr = Ipv4Cidr::try_from(" 10.0.0.0/8 ")?;
    /// assert_eq!(cidr.prefix_length, 8);
    /// # Ok::<(), new_arp_scan::AppError>(())
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let trimmed = value.trim_matches(|character: char| character.is_ascii_whitespace());
        if trimmed.is_empty() {
            return Err(AppError::Ipv4CidrStringInvalid {
                source: value.to_string(),
                message: "input is empty after trimming leading and trailing ASCII whitespace only"
                    .to_string(),
            });
        }

        let (before_slash, after_slash) =
            trimmed
                .split_once('/')
                .ok_or_else(|| AppError::Ipv4CidrStringInvalid {
                    source: trimmed.to_string(),
                    message: "expected a '/' separating the IPv4 address and prefix length"
                        .to_string(),
                })?;

        if after_slash.contains('/') {
            return Err(AppError::Ipv4CidrStringInvalid {
                source: trimmed.to_string(),
                message: "expected exactly one '/' in the classless inter-domain routing notation"
                    .to_string(),
            });
        }

        let address_part =
            before_slash.trim_matches(|character: char| character.is_ascii_whitespace());
        let prefix_part =
            after_slash.trim_matches(|character: char| character.is_ascii_whitespace());

        let ipv4_address: Ipv4Addr =
            address_part
                .parse()
                .map_err(|_| AppError::Ipv4CidrStringInvalid {
                    source: trimmed.to_string(),
                    message: format!("could not parse `{address_part}` as an IPv4 address"),
                })?;

        let prefix_length = parse_decimal_prefix_length(prefix_part, trimmed)?;

        Ok(Self {
            ipv4_address,
            prefix_length,
        })
    }
}

impl FromStr for Ipv4Cidr {
    type Err = AppError;

    /// Parses using the same rules as [`TryFrom::try_from`] for [`Ipv4Cidr`].
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Self::try_from(string)
    }
}

fn contiguous_ipv4_netmask_from_prefix_length(prefix_length: u8) -> Ipv4Addr {
    match prefix_length {
        0 => Ipv4Addr::UNSPECIFIED,
        32 => Ipv4Addr::BROADCAST,
        interior_prefix_length => {
            let host_bit_count = 32u8.saturating_sub(interior_prefix_length);
            Ipv4Addr::from_bits(u32::MAX << u32::from(host_bit_count))
        }
    }
}

fn parse_decimal_prefix_length(raw: &str, diagnostic_source: &str) -> Result<u8, AppError> {
    let trimmed = raw.trim_matches(|character: char| character.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Err(AppError::Ipv4CidrStringInvalid {
            source: diagnostic_source.to_string(),
            message: "prefix length segment is empty".to_string(),
        });
    }

    if !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::Ipv4CidrStringInvalid {
            source: diagnostic_source.to_string(),
            message: format!("prefix length `{trimmed}` must contain only ASCII decimal digits"),
        });
    }

    let parsed: u32 = trimmed
        .parse()
        .map_err(|_| AppError::Ipv4CidrStringInvalid {
            source: diagnostic_source.to_string(),
            message: format!("prefix length `{trimmed}` is not a valid decimal number"),
        })?;

    if parsed > 32 {
        return Err(AppError::Ipv4CidrStringInvalid {
            source: diagnostic_source.to_string(),
            message: format!("prefix length {parsed} is greater than 32"),
        });
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "`parsed` is at most 32 after the check above, so the cast cannot truncate"
    )]
    let prefix_length = parsed as u8;
    Ok(prefix_length)
}

#[cfg(test)]
mod tests {
    use super::Ipv4Cidr;
    use super::Ipv4HostAddressIterator;
    use crate::error::AppError;
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn slash_24_cidr_iterator_matches_subnet_helper_endpoints() {
        // Arrange
        let address = Ipv4Addr::new(192, 168, 1, 10);
        let netmask = Ipv4Addr::new(255, 255, 255, 0);
        let cidr = Ipv4Cidr::try_from("192.168.1.10/24").expect("fixture CIDR should parse");

        // Act
        let from_cidr = cidr
            .host_address_iterator()
            .expect("fixture /24 should yield a host iterator");
        let from_subnet =
            Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(address, netmask)
                .expect("fixture subnet should yield a host iterator");

        // Assert
        assert_eq!(
            from_cidr.size_hint(),
            from_subnet.size_hint(),
            "iterator length should match between CIDR and subnet construction"
        );
        assert!(
            from_cidr.eq(from_subnet),
            "CIDR-derived iterator should match subnet-derived iterator for the same /24"
        );
    }

    #[test]
    fn slash_24_host_iterator_reports_size_hint_254_and_counts_without_vec_allocation() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.168.1.0/24").expect("fixture CIDR should parse");
        let iterator = cidr
            .host_address_iterator()
            .expect("fixture /24 should yield a host iterator");

        // Act
        let (lower_bound, upper_bound) = iterator.size_hint();
        let counted = iterator.count();

        // Assert
        assert_eq!(
            upper_bound,
            Some(254),
            "expected 254 usable hosts in /24 size hint upper bound"
        );
        assert_eq!(
            lower_bound, 254,
            "expected 254 usable hosts in /24 size hint lower bound"
        );
        assert_eq!(counted, 254, "count should match size hint");
    }

    #[test]
    fn slash_30_iterator_yields_two_hosts_matching_size_hint() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.168.1.4/30").expect("fixture CIDR should parse");
        let iterator = cidr
            .host_address_iterator()
            .expect("fixture /30 should yield a host iterator");

        // Act
        let (lower_bound, upper_bound) = iterator.size_hint();
        let collected: Vec<Ipv4Addr> = iterator.collect();

        // Assert
        assert_eq!(upper_bound, Some(2), "/30 should expose two interior hosts");
        assert_eq!(lower_bound, 2, "/30 size hint lower bound should match");
        assert_eq!(
            collected,
            vec![Ipv4Addr::new(192, 168, 1, 5), Ipv4Addr::new(192, 168, 1, 6),]
        );
    }

    #[test]
    fn try_from_returns_error_when_input_is_empty_after_trim() {
        // Arrange
        let input = "   ";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "whitespace-only input should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_slash_is_missing() {
        // Arrange
        let input = "192.168.1.1";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "missing slash should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_is_not_decimal() {
        // Arrange
        let input = "192.168.1.0/2a";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "non-decimal prefix should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_exceeds_32() {
        // Arrange
        let input = "10.0.0.0/33";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "prefix above 32 should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_extra_slash_segments_exist() {
        // Arrange
        let input = "10.0.0.0/8/extra";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "extra slash segments should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn from_str_matches_try_from() {
        // Arrange
        let text = "192.0.2.0/24";

        // Act
        let from_trait = Ipv4Cidr::from_str(text);
        let from_try = Ipv4Cidr::try_from(text);

        // Assert
        assert_eq!(
            from_trait.expect("FromStr should parse fixture"),
            from_try.expect("TryFrom should parse fixture"),
            "FromStr and TryFrom should agree"
        );
    }

    #[test]
    fn slash_31_cidr_host_iterator_returns_subnet_unsupported() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.0.2.0/31").expect("fixture CIDR should parse");

        // Act
        let outcome = cidr.host_address_iterator();

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4SubnetUnsupported { .. })),
            "/31 expansion should be unsupported, got: {outcome:?}"
        );
    }

    #[test]
    fn slash_32_cidr_host_iterator_returns_subnet_unsupported() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.0.2.1/32").expect("fixture CIDR should parse");

        // Act
        let outcome = cidr.host_address_iterator();

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4SubnetUnsupported { .. })),
            "/32 expansion should be unsupported, got: {outcome:?}"
        );
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn size_hint_returns_unknown_when_interior_span_does_not_fit_usize() {
        // Arrange: synthetic iterator state (not produced by the subnet helper on tier-one hosts,
        // but valid for exercising `usize::try_from(span)` failure on 32-bit `usize`).
        let iterator = Ipv4HostAddressIterator {
            next_host_bits: Some(0),
            last_host_bits: u32::MAX,
        };

        // Act
        let hint = iterator.size_hint();

        // Assert
        assert_eq!(
            hint,
            (0, None),
            "when the span does not fit `usize`, the upper bound must be unknown"
        );
    }

    #[test]
    fn interior_space_in_address_part_is_rejected() {
        // Arrange
        let input = "192.168. 1.1/24";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "interior space inside the IPv4 address should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_accepts_outer_ascii_whitespace_including_tabs_and_newlines() {
        // Arrange
        let input = "\t192.168.0.1/16\n";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        let parsed = outcome.expect("tab and newline padding should parse");
        assert_eq!(parsed.prefix_length, 16, "expected /16 prefix length");
        assert_eq!(parsed.ipv4_address, Ipv4Addr::new(192, 168, 0, 1));
    }

    #[test]
    fn try_from_returns_error_when_address_segment_before_slash_is_empty() {
        // Arrange
        let input = "/24";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "empty address segment should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_segment_after_slash_is_empty() {
        // Arrange
        let input = "192.168.1.1/";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "empty prefix segment should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_contains_interior_ascii_whitespace() {
        // Arrange
        let input = "192.168.1.1/2 4";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "interior whitespace inside the prefix should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_accepts_decimal_prefix_with_leading_zeros() {
        // Arrange
        let input = "192.168.1.10/024";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        let parsed = outcome.expect("leading zeros on decimal prefix should parse");
        assert_eq!(parsed.prefix_length, 24);
    }

    #[test]
    fn try_from_returns_error_when_prefix_decimal_overflows_u32() {
        // Arrange
        let input = "1.1.1.1/999999999999999999999999999999999999999999999999999999999999";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        let error = outcome.expect_err("overlong decimal prefix should not parse as u32");
        let displayed = error.to_string();
        assert!(
            displayed.contains("not a valid decimal number"),
            "display should mention invalid decimal prefix, got: {displayed}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_decimal_parse_succeeds_but_exceeds_slash_32() {
        // Arrange: `u32::MAX` parses, but prefix length must be at most 32.
        let input = "1.1.1.1/4294967295";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        let error = outcome.expect_err("prefix above 32 should be rejected even when it parses");
        let displayed = error.to_string();
        assert!(
            displayed.contains("greater than 32"),
            "display should explain the slash 32 upper bound, got: {displayed}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_contains_non_ascii_decimal_digit() {
        // Arrange
        let input = "192.168.1.1/２4";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4CidrStringInvalid { .. })),
            "fullwidth digits must not be accepted as prefix, got: {outcome:?}"
        );
    }

    #[test]
    fn slash_25_host_iterator_counts_126_interior_hosts() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.168.0.0/25").expect("fixture CIDR should parse");
        let iterator = cidr
            .host_address_iterator()
            .expect("fixture /25 should yield a host iterator");

        // Act
        let counted = iterator.count();

        // Assert
        assert_eq!(counted, 126, "/25 should expose 126 interior hosts");
    }

    #[test]
    fn slash_16_host_iterator_counts_65534_interior_hosts() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("10.0.0.0/16").expect("fixture CIDR should parse");
        let iterator = cidr
            .host_address_iterator()
            .expect("fixture /16 should yield a host iterator");

        // Act
        let counted = iterator.count();

        // Assert
        assert_eq!(
            counted, 65534,
            "/16 should expose 2^16 minus two reserved addresses"
        );
    }

    #[test]
    fn slash_zero_iterator_starts_at_first_usable_host_without_counting_entire_space() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("0.0.0.0/0").expect("fixture CIDR should parse");
        let mut iterator = cidr
            .host_address_iterator()
            .expect("fixture /0 should yield a host iterator");

        // Act
        let first = iterator.next();

        // Assert
        assert_eq!(
            first,
            Some(Ipv4Addr::new(0, 0, 0, 1)),
            "first interior host of default-free /0 should be 0.0.0.1"
        );
    }

    #[test]
    fn exhausted_host_iterator_returns_none_repeatedly_and_reports_zero_size_hint() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.168.1.4/30").expect("fixture CIDR should parse");
        let mut iterator = cidr
            .host_address_iterator()
            .expect("fixture /30 should yield a host iterator");

        // Act
        let _ = iterator.by_ref().count();
        let first_after = iterator.next();
        let second_after = iterator.next();
        let hint_after = iterator.size_hint();

        // Assert
        assert!(
            first_after.is_none() && second_after.is_none(),
            "iterator should stay exhausted after draining, got: {first_after:?} then {second_after:?}"
        );
        assert_eq!(
            hint_after,
            (0, Some(0)),
            "exhausted iterator should report exact zero size hint, got: {hint_after:?}"
        );
    }

    #[test]
    fn cloned_host_iterator_preserves_remaining_sequence() {
        // Arrange
        let cidr = Ipv4Cidr::try_from("192.168.1.0/29").expect("fixture CIDR should parse");
        let mut iterator = cidr
            .host_address_iterator()
            .expect("fixture /29 should yield a host iterator");
        let _ = iterator.next();

        // Act
        let mut clone = iterator.clone();
        let remaining_from_clone: Vec<Ipv4Addr> = clone.by_ref().collect();
        let remaining_from_original: Vec<Ipv4Addr> = iterator.collect();

        // Assert
        assert_eq!(
            remaining_from_clone, remaining_from_original,
            "clone should match the remaining tail of the original iterator"
        );
    }

    #[test]
    fn try_from_ipv4_address_on_subnet_returns_netmask_invalid_for_non_contiguous_netmask() {
        // Arrange
        let ipv4_address = Ipv4Addr::new(192, 168, 1, 1);
        let invalid_netmask = Ipv4Addr::new(255, 0, 255, 0);

        // Act
        let outcome =
            Ipv4HostAddressIterator::try_from_ipv4_address_on_subnet(ipv4_address, invalid_netmask);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::Ipv4NetmaskInvalid { .. })),
            "non-contiguous netmask should surface netmask invalid, got: {outcome:?}"
        );
    }

    #[test]
    fn try_from_returns_error_when_prefix_greater_than_32_message_is_actionable() {
        // Arrange
        let input = "10.0.0.0/33";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        let error = outcome.expect_err("prefix 33 should be rejected");
        let displayed = error.to_string();
        assert!(
            displayed.contains("33") && displayed.contains("32"),
            "operator-facing text should name the bad prefix and the upper bound, got: {displayed}"
        );
    }

    #[test]
    fn try_from_returns_error_when_input_is_empty_string() {
        // Arrange
        let input = "";

        // Act
        let outcome = Ipv4Cidr::try_from(input);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(AppError::Ipv4CidrStringInvalid { ref source, ref message })
                    if source.is_empty() && message.contains("empty")
            ),
            "expected empty input to yield Ipv4CidrStringInvalid, got: {outcome:?}"
        );
    }
}
