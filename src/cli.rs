//! Command-line interface definitions for the `new-arp-scan` binary.

use std::net::Ipv4Addr;

use clap::{Args, Parser, Subcommand};

/// Help footer examples appended to `--help` output.
const EXAMPLES: &str = "\
EXAMPLES:
  List interfaces usable for ARP scanning on Linux:
    new-arp-scan interfaces

  Scan the local IPv4 subnet on Linux (requires CAP_NET_RAW or equivalent):
    new-arp-scan scan --interface eth0

  Probe a single strictly interior host on the subnet:
    new-arp-scan scan --interface eth0 --host 192.168.1.50

    Annotate MAC addresses with IEEE MA-L / MA-M / MA-S / IAB vendor names:
    new-arp-scan scan --interface eth0 --mac-vendor-file ieee-oui.txt

  Send IEEE 802.1Q tagged ARP requests on VLAN 10 with PCP 5:
    new-arp-scan scan --interface eth0 --vlan 10 --pcp 5

  Send IEEE 802.1ad QinQ requests: service VLAN 100 wrapping customer VLAN 10:
    new-arp-scan scan --interface eth0 --vlan 10 --svlan 100 --spcp 5

  Append custom payload padding after the ARP PDU:
    new-arp-scan scan --interface eth0 --padding deadbeef

  RFC 5227 ARP Probe (sender protocol address 0.0.0.0):
    new-arp-scan scan --interface eth0 --arpspa 0.0.0.0

  RFC 5227 ARP Announcement (sender protocol address equals each target):
    new-arp-scan scan --interface eth0 --arpspa dest

  RFC 1042 LLC/SNAP framing instead of Ethernet II:
    new-arp-scan scan --interface eth0 --llc

  Unicast ARP to a known Ethernet destination:
    new-arp-scan scan --interface eth0 --destaddr 00:11:22:33:44:55

  Scan using automatic interface selection when exactly one usable interface exists:
    new-arp-scan scan

  Scan with a custom receive window, pacing between scan rounds, and multiple attempts:
    new-arp-scan scan --interface eth0 --timeout-ms 5000 --pacing-ms 10 --attempts 3
";

/// Root command-line interface for `new-arp-scan`.
#[derive(Debug, Parser)]
#[command(
    name = "new-arp-scan",
    version,
    about = "Inspect local networks using ARP scanning (under active development).",
    after_help = EXAMPLES
)]
pub struct CliRoot {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub subcommand: Option<CliSubcommand>,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum CliSubcommand {
    /// Scan the interface's local IPv4 subnet using address resolution protocol requests.
    Scan(ScanArguments),
    /// List interfaces that are usable for ARP scanning on Linux.
    Interfaces,
}

/// Arguments for [`CliSubcommand::Scan`].
#[derive(Debug, Args)]
pub struct ScanArguments {
    /// Network interface name (for example `eth0`). When omitted, a single usable interface must
    /// exist or automatic selection fails.
    #[arg(long = "interface", value_name = "NAME", visible_alias = "iface")]
    pub interface_name: Option<String>,
    /// Probe only this IPv4 address (must be strictly interior on the interface subnet).
    #[arg(long = "host", value_name = "IPv4")]
    pub host_ipv4_address: Option<Ipv4Addr>,
    /// IEEE MA-L / MA-M / MA-S / IAB mapping file (`ieee-oui.txt` from `mac-vendor-updater`).
    ///
    /// When set, host lines become `<IPv4> <MAC> <vendor>`. When omitted, `ieee-oui.txt` in the
    /// current directory is used if that file exists. Builds with `--features bundled-mac-vendors`
    /// then fall back to the compile-time embedded registry. Otherwise host lines stay
    /// `<IPv4> <MAC>`.
    #[arg(long = "mac-vendor-file", value_name = "PATH")]
    pub mac_vendor_file: Option<std::path::PathBuf>,
    /// IEEE 802.1Q VLAN identifier (`0..=4095`). When set, each request is an Ethernet II ARP
    /// frame with a single customer tag (TPID `0x8100`). PCP and DEI default to zero unless
    /// `--pcp` / `--dei` are set. When omitted, requests are untagged.
    #[arg(
        long = "vlan",
        value_name = "VID",
        value_parser = clap::value_parser!(u16).range(0..=4095)
    )]
    pub vlan_identifier: Option<u16>,
    /// IEEE 802.1Q Priority Code Point (`0..=7`). Requires `--vlan`. Default 0.
    #[arg(
        long = "pcp",
        value_name = "PRIORITY",
        value_parser = clap::value_parser!(u8).range(0..=7),
        requires = "vlan_identifier"
    )]
    pub vlan_priority_code_point: Option<u8>,
    /// Set the IEEE 802.1Q Drop Eligible Indicator. Requires `--vlan`.
    #[arg(long = "dei", action = clap::ArgAction::SetTrue, requires = "vlan_identifier")]
    pub vlan_drop_eligible_indicator: bool,
    /// IEEE 802.1Q service VLAN identifier (`0..=4095`) for IEEE 802.1ad provider bridging.
    /// Requires `--vlan`. When set, each request carries an outer service tag (S-TAG, TPID
    /// `0x88A8`) wrapping the `--vlan` customer tag (C-TAG, TPID `0x8100`). Service PCP and DEI
    /// default to zero unless `--spcp` / `--sdei` are set.
    #[arg(
        long = "svlan",
        value_name = "VID",
        value_parser = clap::value_parser!(u16).range(0..=4095),
        requires = "vlan_identifier"
    )]
    pub service_vlan_identifier: Option<u16>,
    /// IEEE 802.1Q service tag Priority Code Point (`0..=7`). Requires `--svlan`. Default 0.
    #[arg(
        long = "spcp",
        value_name = "PRIORITY",
        value_parser = clap::value_parser!(u8).range(0..=7),
        requires = "service_vlan_identifier"
    )]
    pub service_vlan_priority_code_point: Option<u8>,
    /// Set the IEEE 802.1Q service tag Drop Eligible Indicator. Requires `--svlan`.
    #[arg(long = "sdei", action = clap::ArgAction::SetTrue, requires = "service_vlan_identifier")]
    pub service_vlan_drop_eligible_indicator: bool,
    /// Hex-encoded octets appended after the 28-octet ARP PDU (no `0x` prefix, even number of
    /// digits), matching original `arp-scan --padding`. The frame is still zero-padded to 60
    /// octets when shorter. With `--llc`, these octets are included in the IEEE 802.3 length.
    #[arg(
        long = "padding",
        value_name = "HEX",
        num_args = 1,
        value_parser = crate::application_command::parse_ethernet_padding_hex
    )]
    pub ethernet_padding: Option<crate::application_command::EthernetPaddingOctets>,
    /// RFC 826 `ar$spa` (sender IPv4). Dotted quad, or `dest` to use each target address (RFC 5227
    /// Announcement). `0.0.0.0` is an RFC 5227 ARP Probe. When omitted, the interface IPv4 address
    /// is used.
    #[arg(long = "arpspa", value_name = "IPv4|dest", value_parser = crate::application_command::ArpSenderProtocolAddress::parse_cli_token)]
    pub sender_protocol_address: Option<crate::application_command::ArpSenderProtocolAddress>,
    /// Send RFC 1042 LLC/SNAP (IEEE 802.3 length + `AA AA 03` + OUI `00:00:00` + `EtherType`)
    /// instead of Ethernet II. Replies are decoded in either framing regardless of this flag.
    #[arg(long = "llc", action = clap::ArgAction::SetTrue)]
    pub llc_snap: bool,
    /// Ethernet destination MAC. When omitted, the broadcast address is used.
    #[arg(long = "destaddr", value_name = "MAC", value_parser = crate::mac_address::MacAddress::parse_cli_token)]
    pub ethernet_destination: Option<crate::mac_address::MacAddress>,
    /// Ethernet source MAC. When omitted, the scanning interface hardware address is used. This
    /// does not change RFC 826 `ar$sha`; use `--arpsha` for that field.
    #[arg(long = "srcaddr", value_name = "MAC", value_parser = crate::mac_address::MacAddress::parse_cli_token)]
    pub ethernet_source: Option<crate::mac_address::MacAddress>,
    /// RFC 826 `ar$sha`. When omitted, the scanning interface hardware address is used. This does
    /// not change the Ethernet source; use `--srcaddr` for that field.
    #[arg(long = "arpsha", value_name = "MAC", value_parser = crate::mac_address::MacAddress::parse_cli_token)]
    pub arp_sender_hardware: Option<crate::mac_address::MacAddress>,
    /// RFC 826 `ar$tha`. When omitted, all zeroes are used (unused in an ARP request).
    #[arg(long = "arptha", value_name = "MAC", value_parser = crate::mac_address::MacAddress::parse_cli_token)]
    pub arp_target_hardware: Option<crate::mac_address::MacAddress>,
    /// RFC 826 `ar$hrd` (default 1 / Ethernet). Decimal or `0x`-prefixed hexadecimal.
    #[arg(
        long = "arphrd",
        value_name = "UINT",
        default_value_t = 1,
        value_parser = crate::application_command::parse_u16_cli_token
    )]
    pub arp_hardware_type: u16,
    /// RFC 826 `ar$pro` (default `0x0800` / IPv4). Decimal or `0x`-prefixed hexadecimal.
    #[arg(
        long = "arppro",
        value_name = "UINT",
        default_value = "0x0800",
        value_parser = crate::application_command::parse_u16_cli_token
    )]
    pub arp_protocol_type: u16,
    /// RFC 826 `ar$hln` (default 6). Does not change the encoded SHA/THA widths.
    #[arg(
        long = "arphln",
        value_name = "UINT",
        default_value_t = 6,
        value_parser = crate::application_command::parse_u8_cli_token
    )]
    pub arp_hardware_length: u8,
    /// RFC 826 `ar$pln` (default 4). Does not change the encoded SPA/TPA widths.
    #[arg(
        long = "arppln",
        value_name = "UINT",
        default_value_t = 4,
        value_parser = crate::application_command::parse_u8_cli_token
    )]
    pub arp_protocol_length: u8,
    /// RFC 826 `ar$op` (default 1 / request). Decimal or `0x`-prefixed hexadecimal.
    #[arg(
        long = "arpop",
        value_name = "UINT",
        default_value_t = 1,
        value_parser = crate::application_command::parse_u16_cli_token
    )]
    pub arp_operation: u16,
    /// Milliseconds to wait for address resolution replies after the last request is sent.
    #[arg(
        long = "timeout-ms",
        value_name = "MILLISECONDS",
        default_value_t = 3000
    )]
    pub timeout_milliseconds: u64,
    /// Milliseconds to sleep after each full round of target sends except the last round.
    #[arg(long = "pacing-ms", value_name = "MILLISECONDS", default_value_t = 0)]
    pub pacing_milliseconds: u64,
    /// Total scan rounds: each round sends one broadcast request per target (minimum 1).
    #[arg(
        long = "attempts",
        value_name = "COUNT",
        default_value_t = 1,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub attempts: u64,
}

#[cfg(test)]
mod tests {
    use super::CliRoot;
    use crate::application_command::ArpSenderProtocolAddress;
    use crate::mac_address::MacAddress;
    use clap::CommandFactory;
    use clap::Parser;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_scan_subcommand_with_interface_name() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.interface_name.as_deref(),
                    Some("eth0"),
                    "interface name should match flag value"
                );
                assert_eq!(
                    scan.timeout_milliseconds, 3000,
                    "omitted timeout should use default milliseconds"
                );
                assert_eq!(
                    scan.pacing_milliseconds, 0,
                    "omitted pacing should use default milliseconds"
                );
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_iface_visible_alias() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--iface", "enp0s1"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.interface_name.as_deref(),
                    Some("enp0s1"),
                    "visible alias --iface should populate interface name"
                );
                assert_eq!(
                    scan.timeout_milliseconds, 3000,
                    "omitted timeout should use default milliseconds"
                );
                assert_eq!(
                    scan.pacing_milliseconds, 0,
                    "omitted pacing should use default milliseconds"
                );
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_without_interface_name() {
        // Arrange
        let arguments = ["new-arp-scan", "scan"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.interface_name, None,
                    "omitted interface flag should yield None"
                );
                assert_eq!(
                    scan.timeout_milliseconds, 3000,
                    "omitted timeout should use default milliseconds"
                );
                assert_eq!(
                    scan.pacing_milliseconds, 0,
                    "omitted pacing should use default milliseconds"
                );
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_interfaces_subcommand() {
        // Arrange
        let arguments = ["new-arp-scan", "interfaces"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        assert!(
            matches!(subcommand, super::CliSubcommand::Interfaces),
            "expected interfaces subcommand, got: {subcommand:?}"
        );
    }

    #[test]
    fn returns_error_for_unknown_subcommand() {
        // Arrange
        let arguments = ["new-arp-scan", "unknown"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "unknown subcommand should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_unknown_flag() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--not-a-defined-flag"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "undefined scan flags should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_explicit_timeout_milliseconds_and_pacing_milliseconds() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--timeout-ms",
            "5000",
            "--pacing-ms",
            "12",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.timeout_milliseconds, 5000,
                    "explicit timeout should parse"
                );
                assert_eq!(scan.pacing_milliseconds, 12, "explicit pacing should parse");
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_explicit_attempts_alongside_timing_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--timeout-ms",
            "4000",
            "--pacing-ms",
            "7",
            "--attempts",
            "8",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.timeout_milliseconds, 4000);
                assert_eq!(scan.pacing_milliseconds, 7);
                assert_eq!(scan.attempts, 8);
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_non_numeric_timeout_milliseconds() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--timeout-ms", "not-a-number"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "non-numeric timeout should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_negative_timeout_milliseconds_token() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--timeout-ms", "-1"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "negative timeout token should fail parsing for unsigned field, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_negative_pacing_milliseconds_token() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--pacing-ms", "-1"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "negative pacing token should fail parsing for unsigned field, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interfaces_subcommand_receives_trailing_token() {
        // Arrange
        let arguments = ["new-arp-scan", "interfaces", "extra"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "interfaces subcommand should not accept stray positional arguments, got: {outcome:?}"
        );
    }

    #[test]
    fn help_command_factory_builds_without_panicking() {
        // Arrange
        // Act
        let mut command = CliRoot::command();

        // Assert
        let help = command.render_help().to_string();
        assert!(
            help.contains("scan") && help.contains("interfaces"),
            "help should mention scan and interfaces subcommands, got: {help}"
        );
    }

    #[test]
    fn rendered_help_includes_examples_footer() {
        // Arrange
        let mut command = CliRoot::command();

        // Act
        let help = command.render_help().to_string();

        // Assert
        assert!(
            help.contains("EXAMPLES:") && help.contains("new-arp-scan scan"),
            "after_help should surface operator examples, got: {help}"
        );
        assert!(
            help.contains("--host"),
            "root help examples should document single-host scan with --host, got: {help}"
        );
    }

    #[test]
    fn renders_scan_subcommand_long_help_including_timing_flags_and_defaults() {
        // Arrange
        let mut root_command = CliRoot::command();
        let scan_command = root_command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should exist for operator help");

        // Act
        let help = scan_command.render_long_help().to_string();

        // Assert
        assert!(
            help.contains("--timeout-ms")
                && help.contains("--pacing-ms")
                && help.contains("--attempts")
                && help.contains("--host"),
            "scan long help should name timing, attempts, and host flags, got:\n{help}"
        );
        assert!(
            help.contains("3000"),
            "scan long help should document default timeout milliseconds, got:\n{help}"
        );
        let lower = help.to_lowercase();
        assert!(
            lower.contains("round"),
            "scan long help should describe pacing as between scan rounds, got:\n{help}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_zero_timeout_milliseconds() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--timeout-ms",
            "0",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.timeout_milliseconds, 0,
                    "explicit zero timeout should parse as immediate poll loop"
                );
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_large_timeout_milliseconds() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--timeout-ms",
            "18446744073709551615",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.timeout_milliseconds,
                    u64::MAX,
                    "maximum u64 timeout should parse for library clamping downstream"
                );
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_timeout_milliseconds_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--timeout-ms",
            "100",
            "--timeout-ms",
            "250",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate timeout flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_pacing_milliseconds_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--pacing-ms",
            "1",
            "--pacing-ms",
            "2",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate pacing flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_explicit_zero_pacing_milliseconds_alongside_custom_timeout() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--timeout-ms",
            "1",
            "--pacing-ms",
            "0",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.timeout_milliseconds, 1);
                assert_eq!(scan.pacing_milliseconds, 0);
                assert_eq!(
                    scan.attempts, 1,
                    "omitted attempts should use default count"
                );
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_explicit_attempts_count() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--attempts",
            "4",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.attempts, 4, "explicit attempts should parse");
                assert!(
                    scan.host_ipv4_address.is_none(),
                    "omitted --host should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_zero_attempts() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--attempts", "0"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "zero attempts should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_attempts_flags() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--attempts", "2", "--attempts", "3"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate attempts flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_non_numeric_attempts() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--attempts", "x"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "non-numeric attempts should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_non_numeric_pacing_milliseconds() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--pacing-ms", "x"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "non-numeric pacing should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_empty_timeout_milliseconds() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--timeout-ms", ""];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "empty timeout token should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_host_ipv4_address() {
        // Arrange
        use std::net::Ipv4Addr;

        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--host",
            "192.168.1.50",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.host_ipv4_address,
                    Some(Ipv4Addr::new(192, 168, 1, 50)),
                    "--host should parse as IPv4"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_host_alongside_timing_and_attempts_flags() {
        // Arrange
        use std::net::Ipv4Addr;

        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--host",
            "10.0.0.7",
            "--timeout-ms",
            "100",
            "--pacing-ms",
            "5",
            "--attempts",
            "2",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.host_ipv4_address, Some(Ipv4Addr::new(10, 0, 0, 7)));
                assert_eq!(scan.timeout_milliseconds, 100);
                assert_eq!(scan.pacing_milliseconds, 5);
                assert_eq!(scan.attempts, 2);
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_host_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--host",
            "192.168.1.1",
            "--host",
            "192.168.1.2",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate --host flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_mac_vendor_file() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--mac-vendor-file",
            "ieee-oui.txt",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.mac_vendor_file.as_deref(),
                    Some(std::path::Path::new("ieee-oui.txt")),
                    "--mac-vendor-file should populate the mapping path"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn omitted_mac_vendor_file_is_none() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert!(
                    scan.mac_vendor_file.is_none(),
                    "omitted --mac-vendor-file should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_vlan_identifier() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--vlan",
            "10",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.vlan_identifier,
                    Some(10),
                    "--vlan should populate the 12-bit VLAN identifier"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn omitted_vlan_identifier_is_none() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert!(
                    scan.vlan_identifier.is_none(),
                    "omitted --vlan should yield None"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn accepts_vlan_identifier_zero_and_4095() {
        // Arrange
        let zero = ["new-arp-scan", "scan", "--vlan", "0"];
        let maximum = ["new-arp-scan", "scan", "--vlan", "4095"];

        // Act
        let parsed_zero = CliRoot::try_parse_from(zero);
        let parsed_maximum = CliRoot::try_parse_from(maximum);

        // Assert
        match parsed_zero
            .expect("VID 0 should parse")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.vlan_identifier,
                    Some(0),
                    "null VID 0 should be accepted"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
        match parsed_maximum
            .expect("VID 4095 should parse")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.vlan_identifier,
                    Some(4095),
                    "12-bit maximum VID should be accepted"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_vlan_identifier_exceeds_twelve_bits() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--vlan", "4096"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "VLAN identifier 4096 is outside the IEEE 802.1Q 12-bit field, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_vlan_pcp_dei_and_padding() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--vlan",
            "10",
            "--pcp",
            "5",
            "--dei",
            "--padding",
            "deadbeef",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        match parsed
            .expect("parsing should succeed")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.vlan_identifier, Some(10));
                assert_eq!(scan.vlan_priority_code_point, Some(5));
                assert!(scan.vlan_drop_eligible_indicator);
                assert_eq!(
                    scan.ethernet_padding
                        .as_ref()
                        .map(crate::application_command::EthernetPaddingOctets::as_slice),
                    Some([0xDE, 0xAD, 0xBE, 0xEF].as_slice())
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_pcp_or_dei_is_set_without_vlan() {
        // Arrange
        let pcp = ["new-arp-scan", "scan", "--pcp", "1"];
        let dei = ["new-arp-scan", "scan", "--dei"];

        // Act
        let pcp_outcome = CliRoot::try_parse_from(pcp);
        let dei_outcome = CliRoot::try_parse_from(dei);

        // Assert
        assert!(
            pcp_outcome.is_err(),
            "--pcp requires --vlan, got: {pcp_outcome:?}"
        );
        assert!(
            dei_outcome.is_err(),
            "--dei requires --vlan, got: {dei_outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_padding_is_not_even_hex() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--padding", "0xdead"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "0x-prefixed --padding should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_arpspa_unspecified_as_rfc_5227_probe() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--arpspa",
            "0.0.0.0",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.sender_protocol_address,
                    Some(ArpSenderProtocolAddress::Explicit(Ipv4Addr::UNSPECIFIED)),
                    "--arpspa 0.0.0.0 should be an RFC 5227 Probe"
                );
                assert!(!scan.llc_snap, "omitted --llc should stay false");
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_arpspa_dest_and_explicit_ipv4() {
        // Arrange
        let dest = ["new-arp-scan", "scan", "--arpspa", "dest"];
        let dest_upper = ["new-arp-scan", "scan", "--arpspa", "DEST"];
        let explicit = ["new-arp-scan", "scan", "--arpspa", "192.168.1.9"];

        // Act
        let parsed_dest = CliRoot::try_parse_from(dest);
        let parsed_upper = CliRoot::try_parse_from(dest_upper);
        let parsed_explicit = CliRoot::try_parse_from(explicit);

        // Assert
        match parsed_dest
            .expect("dest should parse")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.sender_protocol_address,
                    Some(ArpSenderProtocolAddress::DestinationTarget)
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
        match parsed_upper
            .expect("DEST should parse")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.sender_protocol_address,
                    Some(ArpSenderProtocolAddress::DestinationTarget)
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
        match parsed_explicit
            .expect("dotted-quad should parse")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.sender_protocol_address,
                    Some(ArpSenderProtocolAddress::Explicit(Ipv4Addr::new(
                        192, 168, 1, 9
                    )))
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn omitted_arpspa_is_none() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert!(
                    scan.sender_protocol_address.is_none(),
                    "omitted --arpspa should yield None so the interface IPv4 is used"
                );
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_arpspa_token_is_neither_ipv4_nor_dest() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--arpspa", "destination"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "unknown --arpspa tokens should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_scan_subcommand_receives_duplicate_arpspa_flags() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--arpspa",
            "0.0.0.0",
            "--arpspa",
            "dest",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "duplicate --arpspa flags should be rejected to avoid ambiguous operator intent, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_llc_flag() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0", "--llc"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert!(scan.llc_snap, "--llc should enable RFC 1042 SNAP transmit");
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn omitted_llc_flag_is_false() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        let subcommand = parsed.subcommand.expect("subcommand should be present");
        match subcommand {
            super::CliSubcommand::Scan(scan) => {
                assert!(!scan.llc_snap, "omitted --llc should yield false");
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn rendered_help_includes_arpspa_and_llc_examples() {
        // Arrange
        let mut command = CliRoot::command();

        // Act
        let help = command.render_help().to_string();

        // Assert
        assert!(
            help.contains("--arpspa") && help.contains("--llc"),
            "root help examples should document RFC 5227 Probe and RFC 1042 SNAP, got: {help}"
        );
    }

    #[test]
    fn renders_scan_subcommand_long_help_including_arpspa_and_llc() {
        // Arrange
        let mut root_command = CliRoot::command();
        let scan_command = root_command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should exist for operator help");

        // Act
        let help = scan_command.render_long_help().to_string();

        // Assert
        assert!(
            help.contains("--arpspa") && help.contains("--llc") && help.contains("--vlan"),
            "scan long help should name VLAN, arpspa, and llc flags, got:\n{help}"
        );
        assert!(
            help.contains("--pcp") && help.contains("--dei") && help.contains("--padding"),
            "scan long help should name IEEE 802.1Q PCP/DEI and --padding, got:\n{help}"
        );
        assert!(
            help.contains("--destaddr")
                && help.contains("--srcaddr")
                && help.contains("--arpsha")
                && help.contains("--arptha")
                && help.contains("--arphrd")
                && help.contains("--arppro")
                && help.contains("--arphln")
                && help.contains("--arppln")
                && help.contains("--arpop"),
            "scan long help should name Ethernet and remaining RFC 826 field overrides, got:\n{help}"
        );
        let lower = help.to_lowercase();
        assert!(
            lower.contains("5227") || lower.contains("probe") || lower.contains("dest"),
            "scan long help should describe RFC 5227 Probe / dest SPA, got:\n{help}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_destaddr_srcaddr_and_arp_field_overrides() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--destaddr",
            "00:11:22:33:44:55",
            "--srcaddr",
            "0a-0b-0c-0d-0e-0f",
            "--arpsha",
            "aa:bb:cc:dd:ee:ff",
            "--arptha",
            "01:02:03:04:05:06",
            "--arphrd",
            "6",
            "--arppro",
            "0x0800",
            "--arphln",
            "6",
            "--arppln",
            "4",
            "--arpop",
            "1",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        match parsed.subcommand.expect("subcommand should be present") {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(
                    scan.ethernet_destination,
                    Some(MacAddress::from_octets([
                        0x00, 0x11, 0x22, 0x33, 0x44, 0x55
                    ]))
                );
                assert_eq!(
                    scan.ethernet_source,
                    Some(MacAddress::from_octets([
                        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    ]))
                );
                assert_eq!(
                    scan.arp_sender_hardware,
                    Some(MacAddress::from_octets([
                        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
                    ]))
                );
                assert_eq!(
                    scan.arp_target_hardware,
                    Some(MacAddress::from_octets([
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06
                    ]))
                );
                assert_eq!(scan.arp_hardware_type, 6);
                assert_eq!(scan.arp_protocol_type, 0x0800);
                assert_eq!(scan.arp_hardware_length, 6);
                assert_eq!(scan.arp_protocol_length, 4);
                assert_eq!(scan.arp_operation, 1);
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn omitted_destaddr_and_arp_field_overrides_use_rfc_826_defaults() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--interface", "eth0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        match parsed
            .expect("parsing should succeed")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert!(scan.ethernet_destination.is_none());
                assert!(scan.ethernet_source.is_none());
                assert!(scan.arp_sender_hardware.is_none());
                assert!(scan.arp_target_hardware.is_none());
                assert_eq!(scan.arp_hardware_type, 1);
                assert_eq!(scan.arp_protocol_type, 0x0800);
                assert_eq!(scan.arp_hardware_length, 6);
                assert_eq!(scan.arp_protocol_length, 4);
                assert_eq!(scan.arp_operation, 1);
                assert!(scan.vlan_priority_code_point.is_none());
                assert!(!scan.vlan_drop_eligible_indicator);
                assert!(scan.ethernet_padding.is_none());
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_destaddr_is_not_a_mac_address() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--destaddr", "not-a-mac"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "invalid --destaddr should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_destaddr_mixes_colon_and_hyphen_separators() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--destaddr", "00:11-22:33:44:55"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "mixed MAC separators should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_pcp_exceeds_three_bits() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--vlan", "1", "--pcp", "8"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(outcome.is_err(), "PCP 8 is outside 0..=7, got: {outcome:?}");
    }

    #[test]
    fn accepts_pcp_zero_with_vlan_and_without_dei() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--vlan", "1", "--pcp", "0"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        match parsed
            .expect("PCP 0 is a legal 3-bit value")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.vlan_identifier, Some(1));
                assert_eq!(scan.vlan_priority_code_point, Some(0));
                assert!(!scan.vlan_drop_eligible_indicator);
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn parses_scan_subcommand_with_vlan_and_llc_together() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--vlan", "10", "--llc"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        match parsed
            .expect("VLAN plus SNAP should parse")
            .subcommand
            .expect("subcommand should be present")
        {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.vlan_identifier, Some(10));
                assert!(scan.llc_snap);
            }
            super::CliSubcommand::Interfaces => {
                panic!("expected scan subcommand, got interfaces");
            }
        }
    }

    #[test]
    fn returns_error_when_arphrd_exceeds_sixteen_bits() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--arphrd", "0x10000"];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "ar$hrd 0x10000 exceeds u16, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_padding_is_empty() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--padding", ""];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert!(
            outcome.is_err(),
            "empty --padding should fail parsing, got: {outcome:?}"
        );
    }

    #[test]
    fn parses_scan_subcommand_with_service_vlan_pcp_and_dei() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--interface",
            "eth0",
            "--vlan",
            "10",
            "--svlan",
            "100",
            "--spcp",
            "5",
            "--sdei",
        ];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        match parsed.subcommand.expect("subcommand should be present") {
            super::CliSubcommand::Scan(scan) => {
                assert_eq!(scan.vlan_identifier, Some(10));
                assert_eq!(scan.service_vlan_identifier, Some(100));
                assert_eq!(scan.service_vlan_priority_code_point, Some(5));
                assert!(scan.service_vlan_drop_eligible_indicator);
            }
            super::CliSubcommand::Interfaces => panic!("expected scan subcommand, got interfaces"),
        }
    }

    #[test]
    fn omitted_service_vlan_flags_stay_none_and_false() {
        // Arrange
        let arguments = ["new-arp-scan", "scan", "--vlan", "10"];

        // Act
        let parsed = CliRoot::try_parse_from(arguments);

        // Assert
        let parsed = parsed.expect("parsing should succeed");
        match parsed.subcommand.expect("subcommand should be present") {
            super::CliSubcommand::Scan(scan) => {
                assert!(
                    scan.service_vlan_identifier.is_none(),
                    "omitted --svlan should yield None"
                );
                assert!(scan.service_vlan_priority_code_point.is_none());
                assert!(
                    !scan.service_vlan_drop_eligible_indicator,
                    "omitted --sdei should stay false"
                );
            }
            super::CliSubcommand::Interfaces => panic!("expected scan subcommand, got interfaces"),
        }
    }

    #[test]
    fn accepts_service_vlan_identifier_zero_and_4095_and_rejects_4096() {
        // Arrange
        let zero = ["new-arp-scan", "scan", "--vlan", "1", "--svlan", "0"];
        let maximum = ["new-arp-scan", "scan", "--vlan", "1", "--svlan", "4095"];
        let too_large = ["new-arp-scan", "scan", "--vlan", "1", "--svlan", "4096"];

        // Act
        let zero_outcome = CliRoot::try_parse_from(zero);
        let maximum_outcome = CliRoot::try_parse_from(maximum);
        let too_large_outcome = CliRoot::try_parse_from(too_large);

        // Assert
        for (outcome, expected) in [(zero_outcome, 0u16), (maximum_outcome, 4095)] {
            let parsed = outcome.expect("in-range service VID should parse");
            match parsed.subcommand.expect("subcommand should be present") {
                super::CliSubcommand::Scan(scan) => {
                    assert_eq!(scan.service_vlan_identifier, Some(expected));
                }
                super::CliSubcommand::Interfaces => panic!("expected scan subcommand"),
            }
        }
        assert_eq!(
            too_large_outcome
                .expect_err("4096 is outside the 12-bit VID field")
                .kind(),
            clap::error::ErrorKind::ValueValidation,
            "--svlan 4096 should fail range validation"
        );
    }

    #[test]
    fn returns_usage_error_when_service_vlan_flags_are_missing_their_prerequisites() {
        // Arrange: --svlan needs --vlan to wrap; --spcp and --sdei need --svlan to fill.
        let cases: [(&str, Vec<&str>); 4] = [
            (
                "--svlan without --vlan",
                vec!["new-arp-scan", "scan", "--svlan", "100"],
            ),
            (
                "--spcp without --svlan",
                vec!["new-arp-scan", "scan", "--vlan", "10", "--spcp", "5"],
            ),
            (
                "--sdei without --svlan",
                vec!["new-arp-scan", "scan", "--vlan", "10", "--sdei"],
            ),
            (
                "--spcp with neither --svlan nor --vlan",
                vec!["new-arp-scan", "scan", "--spcp", "5"],
            ),
        ];

        // Act
        let outcomes: Vec<(&str, _)> = cases
            .into_iter()
            .map(|(name, arguments)| (name, CliRoot::try_parse_from(arguments)))
            .collect();

        // Assert
        for (name, outcome) in outcomes {
            let error = outcome.expect_err("missing prerequisite should be a usage error");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{name} should be a missing-required-argument usage error"
            );
            assert_eq!(
                error.exit_code(),
                2,
                "{name} should map to the clap usage exit code"
            );
        }
    }

    #[test]
    fn returns_error_when_service_priority_code_point_exceeds_three_bits() {
        // Arrange
        let arguments = [
            "new-arp-scan",
            "scan",
            "--vlan",
            "1",
            "--svlan",
            "100",
            "--spcp",
            "8",
        ];

        // Act
        let outcome = CliRoot::try_parse_from(arguments);

        // Assert
        assert_eq!(
            outcome
                .expect_err("PCP 8 is outside the 3-bit field")
                .kind(),
            clap::error::ErrorKind::ValueValidation,
            "--spcp 8 should fail range validation"
        );
    }

    #[test]
    fn renders_scan_long_help_including_the_service_vlan_flags() {
        // Arrange
        let mut command = CliRoot::command();

        // Act
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand should exist")
            .render_long_help()
            .to_string();

        // Assert
        assert!(
            help.contains("--svlan") && help.contains("--spcp") && help.contains("--sdei"),
            "scan long help should name the IEEE 802.1ad service tag flags, got:\n{help}"
        );
    }
}
