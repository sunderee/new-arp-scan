//! Successful outcomes returned from [`crate::run`].
//!
//! Operator-visible bytes match [`ApplicationOutcome::write_operator_streams`], which the
//! `new-arp-scan` binary calls after [`crate::run`]: scan warnings and optional timing on standard
//! error, host lines (or `no hosts found`) on standard output, and interface tables on standard
//! output.

use std::fmt::Write;
use std::io::Write as IoWrite;
use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::mac_address::MacAddress;
use crate::mac_vendor_registry::{MacVendorRegistry, UNKNOWN_MAC_VENDOR_NAME};

const USABLE_INTERFACE_TABLE_NAME_WIDTH: usize = 16;
const USABLE_INTERFACE_TABLE_INDEX_WIDTH: usize = 6;
const USABLE_INTERFACE_TABLE_IPV4_WIDTH: usize = 15;
const USABLE_INTERFACE_TABLE_NETMASK_WIDTH: usize = 15;

/// A host observed on the local data-link segment during an address resolution scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredHost {
    /// IPv4 address reported in the address resolution reply.
    pub ipv4_address: Ipv4Addr,
    /// Ethernet media access control address reported in the address resolution reply.
    pub media_access_control_address: MacAddress,
}

/// Wall-clock and interface context attached to a completed scan for operator-facing summaries.
///
/// [`crate::run`] sets [`ScanOutcome::timing_summary`] to [`Some`] on Linux after a successful scan.
/// Direct callers of the Linux scanner entry points (including [`crate::perform_arp_probe`])
/// receive [`ScanOutcome`] values with [`ScanOutcome::timing_summary`] set to [`None`] unless they
/// attach a summary themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTimingSummary {
    /// Resolved operating system network interface name used for the scan.
    pub network_interface_name: String,
    /// Wall-clock time spent inside the scan implementation for this invocation.
    pub elapsed_wall_time: Duration,
    /// Number of scan rounds that ran (matches the `attempts` command field).
    pub scan_round_count: NonZeroU64,
    /// Number of discovered hosts after merging duplicate replies.
    pub discovered_host_count: usize,
}

impl ScanTimingSummary {
    /// Formats the single-line standard-error timing summary agreed with product documentation.
    ///
    /// The template is stable: `scan complete: interface <NAME>, <N> host(s), <R> round(s), <MS> ms`.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::ScanTimingSummary;
    /// use std::num::NonZeroU64;
    /// use std::time::Duration;
    ///
    /// let summary = ScanTimingSummary {
    ///     network_interface_name: "eth0".to_string(),
    ///     elapsed_wall_time: Duration::from_millis(1),
    ///     scan_round_count: NonZeroU64::MIN,
    ///     discovered_host_count: 0,
    /// };
    /// assert_eq!(
    ///     summary.format_stderr_timing_summary_line(),
    ///     "scan complete: interface eth0, 0 hosts, 1 round, 1 ms"
    /// );
    /// ```
    #[must_use]
    pub fn format_stderr_timing_summary_line(&self) -> String {
        let host_noun = if self.discovered_host_count == 1 {
            "host"
        } else {
            "hosts"
        };
        let round_noun = if self.scan_round_count.get() == 1 {
            "round"
        } else {
            "rounds"
        };
        let milliseconds_wall = elapsed_milliseconds_saturating_u64(self.elapsed_wall_time);
        format!(
            "scan complete: interface {}, {} {}, {} {}, {} ms",
            self.network_interface_name,
            self.discovered_host_count,
            host_noun,
            self.scan_round_count.get(),
            round_noun,
            milliseconds_wall,
        )
    }
}

fn elapsed_milliseconds_saturating_u64(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    u64::try_from(millis.min(u128::from(u64::MAX))).expect("value is bounded by u64::MAX")
}

/// Outcome of an address resolution scan (discovered hosts and non-fatal warnings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Hosts discovered during scanning, sorted by IPv4 ascending.
    pub discovered_hosts: Vec<DiscoveredHost>,
    /// Non-fatal warnings (for example malformed frames, per-target send failures, or conflicting duplicate address resolution replies for the same IPv4).
    pub warnings: Vec<String>,
    /// Optional wall-clock timing summary populated by [`crate::run`] on Linux after a successful scan.
    pub timing_summary: Option<ScanTimingSummary>,
}

impl ScanOutcome {
    /// Attaches a [`ScanTimingSummary`] after a successful scan, using the current host list length.
    ///
    /// The summary field [`ScanTimingSummary::discovered_host_count`] always matches
    /// [`ScanOutcome::discovered_hosts`] length at attach time.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::{DiscoveredHost, MacAddress, ScanOutcome};
    /// use std::net::Ipv4Addr;
    /// use std::num::NonZeroU64;
    /// use std::time::Duration;
    ///
    /// let scan = ScanOutcome {
    ///     discovered_hosts: vec![DiscoveredHost {
    ///         ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
    ///         media_access_control_address: MacAddress::from_octets([1, 2, 3, 4, 5, 6]),
    ///     }],
    ///     warnings: vec![],
    ///     timing_summary: None,
    /// };
    /// let scan_with_timing = scan.with_scan_timing_summary(
    ///     "eth0".to_string(),
    ///     Duration::from_millis(1),
    ///     NonZeroU64::MIN,
    /// );
    /// assert_eq!(
    ///     scan_with_timing
    ///         .timing_summary
    ///         .expect("timing should attach")
    ///         .discovered_host_count,
    ///     1
    /// );
    /// ```
    #[must_use]
    pub fn with_scan_timing_summary(
        self,
        network_interface_name: String,
        elapsed_wall_time: Duration,
        scan_round_count: NonZeroU64,
    ) -> Self {
        let discovered_host_count = self.discovered_hosts.len();
        Self {
            timing_summary: Some(ScanTimingSummary {
                network_interface_name,
                elapsed_wall_time,
                scan_round_count,
                discovered_host_count,
            }),
            ..self
        }
    }
}

/// One row in the usable-interface listing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsableInterfaceListingRow {
    /// Operating system interface name.
    pub interface_name: String,
    /// Linux interface index.
    pub interface_index: u32,
    /// Primary IPv4 address.
    pub ipv4_address: Ipv4Addr,
    /// IPv4 netmask.
    pub ipv4_netmask: Ipv4Addr,
    /// Ethernet hardware address.
    pub media_access_control_address: MacAddress,
}

/// Outcome of listing interfaces that are usable for ARP scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsableInterfacesListOutcome {
    /// Usable interfaces, sorted by interface index then name.
    pub entries: Vec<UsableInterfaceListingRow>,
}

impl UsableInterfacesListOutcome {
    /// Formats a plain-text table with aligned columns, or a single message when there are no
    /// entries.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[must_use]
    pub fn format_plain_columns_table(&self) -> String {
        if self.entries.is_empty() {
            return "no usable interfaces found\n".to_string();
        }

        let mut lines = String::new();
        // `String` implements `std::fmt::Write` without allocation failure; `writeln!` only returns
        // `Err` on formatting errors, which cannot occur for these arguments.
        let _ = writeln!(
            lines,
            "{:<name_width$} {:>index_width$} {:<ipv4_width$} {:<netmask_width$} MAC",
            "NAME",
            "INDEX",
            "IPV4",
            "NETMASK",
            name_width = USABLE_INTERFACE_TABLE_NAME_WIDTH,
            index_width = USABLE_INTERFACE_TABLE_INDEX_WIDTH,
            ipv4_width = USABLE_INTERFACE_TABLE_IPV4_WIDTH,
            netmask_width = USABLE_INTERFACE_TABLE_NETMASK_WIDTH,
        );
        for entry in &self.entries {
            let _ = writeln!(
                lines,
                "{:<name_width$} {:>index_width$} {:<ipv4_width$} {:<netmask_width$} {}",
                entry.interface_name,
                entry.interface_index,
                entry.ipv4_address,
                entry.ipv4_netmask,
                entry.media_access_control_address,
                name_width = USABLE_INTERFACE_TABLE_NAME_WIDTH,
                index_width = USABLE_INTERFACE_TABLE_INDEX_WIDTH,
                ipv4_width = USABLE_INTERFACE_TABLE_IPV4_WIDTH,
                netmask_width = USABLE_INTERFACE_TABLE_NETMASK_WIDTH,
            );
        }
        lines.push('\n');
        lines
    }
}

/// Successful outcome of [`crate::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationOutcome {
    /// Completed scan on Linux.
    Scan(ScanOutcome),
    /// Listed interfaces usable for ARP scanning on Linux.
    UsableInterfacesList(UsableInterfacesListOutcome),
}

impl ApplicationOutcome {
    /// Writes the same bytes the `new-arp-scan` binary writes for this outcome.
    ///
    /// Scan outcomes emit warnings on `standard_error` first, then host lines or `no hosts found`
    /// on `standard_output`, then an optional timing summary line on `standard_error`. Interface
    /// listings write the formatted table to `standard_output` only.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] when writing to either stream fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use new_arp_scan::{ApplicationOutcome, ScanOutcome};
    /// use std::io::Write;
    ///
    /// let outcome = ApplicationOutcome::Scan(ScanOutcome {
    ///     discovered_hosts: vec![],
    ///     warnings: vec![],
    ///     timing_summary: None,
    /// });
    /// let mut standard_output = Vec::new();
    /// let mut standard_error = Vec::new();
    /// outcome
    ///     .write_operator_streams(&mut standard_output, &mut standard_error)
    ///     .expect("in-memory writes should succeed");
    /// assert_eq!(standard_output, b"no hosts found\n");
    /// assert!(standard_error.is_empty());
    /// ```
    pub fn write_operator_streams(
        &self,
        standard_output: &mut impl IoWrite,
        standard_error: &mut impl IoWrite,
    ) -> std::io::Result<()> {
        self.write_operator_streams_with_mac_vendor_registry(standard_output, standard_error, None)
    }

    /// Writes operator output, annotating host lines with IEEE MA-L / MA-M / MA-S / IAB vendor names
    /// when `mac_vendor_registry` is [`Some`].
    ///
    /// With a registry, each host line is `<IPv4> <MAC> <vendor>` (or `(Unknown)` when no prefix
    /// matches). Without a registry, host lines stay `<IPv4> <MAC>`.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] when writing to either stream fails.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn write_operator_streams_with_mac_vendor_registry(
        &self,
        standard_output: &mut impl IoWrite,
        standard_error: &mut impl IoWrite,
        mac_vendor_registry: Option<&MacVendorRegistry>,
    ) -> std::io::Result<()> {
        match self {
            ApplicationOutcome::Scan(scan_outcome) => {
                for warning in &scan_outcome.warnings {
                    writeln!(standard_error, "warning: {warning}")?;
                }

                if scan_outcome.discovered_hosts.is_empty() {
                    writeln!(standard_output, "no hosts found")?;
                } else {
                    for host in &scan_outcome.discovered_hosts {
                        writeln!(
                            standard_output,
                            "{}",
                            format_discovered_host_line(host, mac_vendor_registry)
                        )?;
                    }
                }

                if let Some(timing_summary) = &scan_outcome.timing_summary {
                    writeln!(
                        standard_error,
                        "{}",
                        timing_summary.format_stderr_timing_summary_line()
                    )?;
                }
            }
            ApplicationOutcome::UsableInterfacesList(listing_outcome) => {
                let table = listing_outcome.format_plain_columns_table();
                write!(standard_output, "{table}")?;
            }
        }
        Ok(())
    }
}

fn format_discovered_host_line(
    host: &DiscoveredHost,
    mac_vendor_registry: Option<&MacVendorRegistry>,
) -> String {
    match mac_vendor_registry {
        None => format!(
            "{} {}",
            host.ipv4_address, host.media_access_control_address
        ),
        Some(registry) => {
            let vendor = registry
                .vendor_name_for(host.media_access_control_address)
                .unwrap_or(UNKNOWN_MAC_VENDOR_NAME);
            format!(
                "{} {} {vendor}",
                host.ipv4_address, host.media_access_control_address
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationOutcome;
    use super::DiscoveredHost;
    use super::ScanOutcome;
    use super::ScanTimingSummary;
    use super::UsableInterfaceListingRow;
    use super::UsableInterfacesListOutcome;
    use crate::mac_address::MacAddress;
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU64;
    use std::time::Duration;

    /// Standard output writer that always fails (for negative I/O tests).
    struct StandardOutputWriteAlwaysFails;

    impl Write for StandardOutputWriteAlwaysFails {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let _ = buffer;
            Err(std::io::Error::other("fixture standard output failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Standard error writer that always fails (for negative I/O tests).
    struct StandardErrorWriteAlwaysFails;

    impl Write for StandardErrorWriteAlwaysFails {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            let _ = buffer;
            Err(std::io::Error::other("fixture standard error failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn format_plain_columns_table_returns_message_when_entries_empty() {
        // Arrange
        let outcome = UsableInterfacesListOutcome { entries: vec![] };

        // Act
        let formatted = outcome.format_plain_columns_table();

        // Assert
        assert_eq!(
            formatted, "no usable interfaces found\n",
            "empty listing should print the agreed operator message"
        );
    }

    #[test]
    fn format_plain_columns_table_includes_header_and_rows() {
        // Arrange
        let outcome = UsableInterfacesListOutcome {
            entries: vec![UsableInterfaceListingRow {
                interface_name: "eth0".to_string(),
                interface_index: 2,
                ipv4_address: Ipv4Addr::new(192, 168, 1, 10),
                ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                media_access_control_address: MacAddress::from_octets([
                    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                ]),
            }],
        };

        // Act
        let formatted = outcome.format_plain_columns_table();

        // Assert
        assert!(
            formatted.contains("NAME") && formatted.contains("INDEX"),
            "table should include column headers, got:\n{formatted}"
        );
        assert!(
            formatted.contains("eth0") && formatted.contains("192.168.1.10"),
            "table should include fixture row content, got:\n{formatted}"
        );
    }

    #[test]
    fn format_plain_columns_table_preserves_row_order_from_entries_vector() {
        // Arrange
        let outcome = UsableInterfacesListOutcome {
            entries: vec![
                UsableInterfaceListingRow {
                    interface_name: "z_second_row".to_string(),
                    interface_index: 99,
                    ipv4_address: Ipv4Addr::new(10, 0, 0, 2),
                    ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                    media_access_control_address: MacAddress::from_octets([
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
                    ]),
                },
                UsableInterfaceListingRow {
                    interface_name: "a_first_row".to_string(),
                    interface_index: 5,
                    ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
                    ipv4_netmask: Ipv4Addr::new(255, 255, 255, 0),
                    media_access_control_address: MacAddress::from_octets([
                        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                    ]),
                },
            ],
        };

        // Act
        let formatted = outcome.format_plain_columns_table();

        // Assert
        let first_position = formatted
            .find("z_second_row")
            .expect("first fixture row should appear in output");
        let second_position = formatted
            .find("a_first_row")
            .expect("second fixture row should appear in output");
        assert!(
            first_position < second_position,
            "table rows should follow `entries` order (not lexical sort), got:\n{formatted}"
        );
    }

    #[test]
    fn scan_timing_summary_line_uses_singular_host_and_round_for_single_values() {
        // Arrange
        let summary = ScanTimingSummary {
            network_interface_name: "eth0".to_string(),
            elapsed_wall_time: Duration::from_millis(3124),
            scan_round_count: NonZeroU64::MIN,
            discovered_host_count: 1,
        };

        // Act
        let line = summary.format_stderr_timing_summary_line();

        // Assert
        assert_eq!(
            line, "scan complete: interface eth0, 1 host, 1 round, 3124 ms",
            "singular host and round wording should match the stable template, got: {line}"
        );
    }

    #[test]
    fn scan_timing_summary_line_uses_plural_hosts_and_rounds() {
        // Arrange
        let summary = ScanTimingSummary {
            network_interface_name: "eth1".to_string(),
            elapsed_wall_time: Duration::from_millis(0),
            scan_round_count: NonZeroU64::new(3).expect("three is non-zero"),
            discovered_host_count: 10,
        };

        // Act
        let line = summary.format_stderr_timing_summary_line();

        // Assert
        assert_eq!(
            line, "scan complete: interface eth1, 10 hosts, 3 rounds, 0 ms",
            "plural host and round wording should match the stable template, got: {line}"
        );
    }

    #[test]
    fn scan_timing_summary_line_includes_long_network_interface_name_verbatim() {
        // Arrange
        let long_name = "narp_very_long_interface_name________________";
        let summary = ScanTimingSummary {
            network_interface_name: long_name.to_string(),
            elapsed_wall_time: Duration::from_micros(500),
            scan_round_count: NonZeroU64::MIN,
            discovered_host_count: 0,
        };

        // Act
        let line = summary.format_stderr_timing_summary_line();

        // Assert
        assert!(
            line.contains(long_name),
            "interface name should appear verbatim for operator correlation, got: {line}"
        );
        assert!(
            line.contains("0 hosts"),
            "zero discovered hosts should still use plural hosts label, got: {line}"
        );
        assert!(
            line.ends_with("0 ms"),
            "sub-millisecond elapsed wall time should truncate to zero whole milliseconds, got: {line}"
        );
    }

    #[test]
    fn scan_timing_summary_line_saturates_elapsed_milliseconds_at_u64_maximum() {
        // Arrange
        let summary = ScanTimingSummary {
            network_interface_name: "eth9".to_string(),
            elapsed_wall_time: Duration::MAX,
            scan_round_count: NonZeroU64::MIN,
            discovered_host_count: 0,
        };

        // Act
        let line = summary.format_stderr_timing_summary_line();

        // Assert
        let expected_suffix = format!("{} ms", u64::MAX);
        assert!(
            line.ends_with(&expected_suffix),
            "elapsed wall time display should saturate at u64::MAX whole milliseconds, got: {line}"
        );
    }

    #[test]
    fn write_operator_streams_writes_no_hosts_then_timing_on_separate_streams() {
        // Arrange
        let timing = ScanTimingSummary {
            network_interface_name: "eth0".to_string(),
            elapsed_wall_time: Duration::from_millis(9),
            scan_round_count: NonZeroU64::MIN,
            discovered_host_count: 0,
        };
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![],
            warnings: vec![],
            timing_summary: Some(timing),
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams(&mut standard_output, &mut standard_error)
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(
            standard_output, b"no hosts found\n",
            "empty scan should print the agreed message on standard output"
        );
        assert_eq!(
            standard_error, b"scan complete: interface eth0, 0 hosts, 1 round, 9 ms\n",
            "timing summary should be the only standard-error line for this fixture"
        );
    }

    #[test]
    fn write_operator_streams_emits_warnings_before_hosts_then_timing_on_standard_error() {
        // Arrange
        let host = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 2),
            media_access_control_address: MacAddress::from_octets([
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]),
        };
        let timing = ScanTimingSummary {
            network_interface_name: "eth1".to_string(),
            elapsed_wall_time: Duration::from_millis(2),
            scan_round_count: NonZeroU64::new(2).expect("two is non-zero"),
            discovered_host_count: 1,
        };
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![host],
            warnings: vec!["first warning".to_string(), "second warning".to_string()],
            timing_summary: Some(timing),
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams(&mut standard_output, &mut standard_error)
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(
            standard_output, b"10.0.0.2 aa:bb:cc:dd:ee:ff\n",
            "single host line should match Display for IPv4 and MAC"
        );
        let expected_stderr = concat!(
            "warning: first warning\n",
            "warning: second warning\n",
            "scan complete: interface eth1, 1 host, 2 rounds, 2 ms\n",
        );
        assert_eq!(
            standard_error,
            expected_stderr.as_bytes(),
            "warnings should precede the timing summary on standard error"
        );
    }

    #[test]
    fn write_operator_streams_omits_timing_line_when_timing_summary_is_none() {
        // Arrange
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams(&mut standard_output, &mut standard_error)
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(standard_output, b"no hosts found\n");
        assert!(
            standard_error.is_empty(),
            "direct scanner callers without timing should emit no standard-error lines, got: {:?}",
            String::from_utf8_lossy(&standard_error)
        );
    }

    #[test]
    fn write_operator_streams_writes_usable_interfaces_table_only_to_standard_output() {
        // Arrange
        let outcome = ApplicationOutcome::UsableInterfacesList(UsableInterfacesListOutcome {
            entries: vec![],
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams(&mut standard_output, &mut standard_error)
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(standard_output, b"no usable interfaces found\n");
        assert!(
            standard_error.is_empty(),
            "interfaces listing should not write to standard error, got: {:?}",
            String::from_utf8_lossy(&standard_error)
        );
    }

    #[test]
    fn with_scan_timing_summary_sets_discovered_host_count_from_current_host_vector_length() {
        // Arrange
        let hosts = vec![
            DiscoveredHost {
                ipv4_address: Ipv4Addr::new(192, 168, 0, 1),
                media_access_control_address: MacAddress::from_octets([1, 1, 1, 1, 1, 1]),
            },
            DiscoveredHost {
                ipv4_address: Ipv4Addr::new(192, 168, 0, 2),
                media_access_control_address: MacAddress::from_octets([2, 2, 2, 2, 2, 2]),
            },
        ];
        let scan = ScanOutcome {
            discovered_hosts: hosts,
            warnings: vec![],
            timing_summary: None,
        };

        // Act
        let scan_with_timing = scan.with_scan_timing_summary(
            "br0".to_string(),
            Duration::ZERO,
            NonZeroU64::new(5).expect("five is non-zero"),
        );

        // Assert
        let summary = scan_with_timing
            .timing_summary
            .as_ref()
            .expect("timing summary should attach");
        assert_eq!(
            summary.discovered_host_count, 2,
            "discovered host count should mirror the vector length at attach time"
        );
        assert_eq!(
            summary.network_interface_name, "br0",
            "interface name should be preserved"
        );
        assert_eq!(
            summary.scan_round_count.get(),
            5,
            "round count should match the argument"
        );
    }

    #[test]
    fn write_operator_streams_preserves_discovered_host_vector_order_on_standard_output() {
        // Arrange
        let first = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 9),
            media_access_control_address: MacAddress::from_octets([9, 9, 9, 9, 9, 9]),
        };
        let second = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
            media_access_control_address: MacAddress::from_octets([1, 1, 1, 1, 1, 1]),
        };
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![first, second],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams(&mut standard_output, &mut standard_error)
            .expect("in-memory writes should succeed");

        // Assert
        let expected = concat!(
            "10.0.0.9 09:09:09:09:09:09\n",
            "10.0.0.1 01:01:01:01:01:01\n",
        );
        assert_eq!(
            standard_output,
            expected.as_bytes(),
            "operator output should follow the outcome vector order (callers sort before building the outcome)"
        );
    }

    #[test]
    fn write_operator_streams_with_registry_appends_vendor_or_unknown() {
        // Arrange
        use crate::mac_vendor_registry::MacVendorRegistry;

        let known = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
            media_access_control_address: MacAddress::from_octets([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]),
        };
        let unknown = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 2),
            media_access_control_address: MacAddress::from_octets([
                0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
            ]),
        };
        let registry = MacVendorRegistry::parse_ieee_oui_text("001122\tExample Corp\n")
            .expect("fixture registry should parse");
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![known, unknown],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams_with_mac_vendor_registry(
                &mut standard_output,
                &mut standard_error,
                Some(&registry),
            )
            .expect("in-memory writes should succeed");

        // Assert
        let stdout = String::from_utf8(standard_output).expect("host lines are UTF-8");
        assert_eq!(
            stdout,
            "10.0.0.1 00:11:22:33:44:55 Example Corp\n10.0.0.2 ff:ee:dd:cc:bb:aa (Unknown)\n"
        );
    }

    #[test]
    fn write_operator_streams_with_registry_annotates_iab_prefixes() {
        // Arrange
        use crate::mac_vendor_registry::MacVendorRegistry;

        let host = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 3),
            media_access_control_address: MacAddress::from_octets([
                0x40, 0xD8, 0x55, 0x0D, 0x70, 0x01,
            ]),
        };
        let registry = MacVendorRegistry::parse_ieee_oui_text("40D8550D7\tFixture IAB\n")
            .expect("IAB fixture should parse");
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![host],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams_with_mac_vendor_registry(
                &mut standard_output,
                &mut standard_error,
                Some(&registry),
            )
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(standard_output, b"10.0.0.3 40:d8:55:0d:70:01 Fixture IAB\n");
        assert!(
            standard_error.is_empty(),
            "vendor annotation must not leak onto standard error"
        );
    }

    #[test]
    fn empty_scan_with_registry_still_prints_no_hosts_found() {
        // Arrange
        use crate::mac_vendor_registry::MacVendorRegistry;

        let registry = MacVendorRegistry::parse_ieee_oui_text("001122\tExample Corp\n")
            .expect("fixture registry should parse");
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams_with_mac_vendor_registry(
                &mut standard_output,
                &mut standard_error,
                Some(&registry),
            )
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(standard_output, b"no hosts found\n");
    }

    #[test]
    fn write_operator_streams_without_registry_keeps_two_column_host_lines() {
        // Arrange
        let host = DiscoveredHost {
            ipv4_address: Ipv4Addr::new(10, 0, 0, 1),
            media_access_control_address: MacAddress::from_octets([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]),
        };
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![host],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = Vec::new();

        // Act
        outcome
            .write_operator_streams(&mut standard_output, &mut standard_error)
            .expect("in-memory writes should succeed");

        // Assert
        assert_eq!(standard_output, b"10.0.0.1 00:11:22:33:44:55\n");
    }

    #[test]
    fn write_operator_streams_returns_error_when_standard_output_write_fails_for_empty_scan() {
        // Arrange
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![],
            warnings: vec![],
            timing_summary: None,
        });
        let mut standard_output = StandardOutputWriteAlwaysFails;
        let mut standard_error = Vec::new();

        // Act
        let write_outcome =
            outcome.write_operator_streams(&mut standard_output, &mut standard_error);

        // Assert
        assert!(
            write_outcome.is_err(),
            "a broken standard output stream should surface an I/O error, got: {write_outcome:?}"
        );
        assert!(
            standard_error.is_empty(),
            "no standard-error bytes should be written before standard output fails"
        );
    }

    #[test]
    fn write_operator_streams_returns_error_when_standard_error_write_fails_on_first_warning() {
        // Arrange
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![],
            warnings: vec!["fixture warning".to_string()],
            timing_summary: None,
        });
        let mut standard_output = Vec::new();
        let mut standard_error = StandardErrorWriteAlwaysFails;

        // Act
        let write_outcome =
            outcome.write_operator_streams(&mut standard_output, &mut standard_error);

        // Assert
        assert!(
            write_outcome.is_err(),
            "a broken standard error stream should surface an I/O error, got: {write_outcome:?}"
        );
        assert!(
            standard_output.is_empty(),
            "no standard-output bytes should be written before the first warning write fails"
        );
    }

    #[test]
    fn write_operator_streams_returns_error_when_standard_error_write_fails_on_timing_summary_line()
    {
        // Arrange
        let timing = ScanTimingSummary {
            network_interface_name: "eth0".to_string(),
            elapsed_wall_time: Duration::ZERO,
            scan_round_count: NonZeroU64::MIN,
            discovered_host_count: 0,
        };
        let outcome = ApplicationOutcome::Scan(ScanOutcome {
            discovered_hosts: vec![],
            warnings: vec![],
            timing_summary: Some(timing),
        });
        let mut standard_output = Vec::new();
        let mut standard_error = StandardErrorWriteAlwaysFails;

        // Act
        let write_outcome =
            outcome.write_operator_streams(&mut standard_output, &mut standard_error);

        // Assert
        assert!(
            write_outcome.is_err(),
            "timing summary write should propagate standard-error failures, got: {write_outcome:?}"
        );
        assert_eq!(
            standard_output, b"no hosts found\n",
            "standard output should be written before the timing summary hits standard error"
        );
    }
}
