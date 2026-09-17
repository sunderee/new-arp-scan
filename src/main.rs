//! Binary entry point for the new ARP scan tool.

use std::time::Duration;

use clap::CommandFactory;
use clap::Parser;

use new_arp_scan::Ieee8021qPriorityCodePoint;
use new_arp_scan::Ieee8021qVlanIdentifier;
use new_arp_scan::application_command::{
    ApplicationCommand, ArpSenderProtocolAddress, EthernetPaddingOctets, ScanWireOptions,
};
use new_arp_scan::cli::{CliRoot, CliSubcommand, ScanArguments};
use new_arp_scan::mac_vendor_registry::MacVendorRegistry;

fn main() {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if arguments.len() <= 1 {
        let mut command = CliRoot::command();
        if command.print_help().is_err() {
            std::process::exit(1);
        }
        return;
    }

    match CliRoot::try_parse_from(arguments.as_slice()) {
        Ok(parsed) => match parsed.subcommand {
            Some(CliSubcommand::Scan(scan)) => {
                let mac_vendor_registry =
                    match load_mac_vendor_registry(scan.mac_vendor_file.as_deref()) {
                        Ok(registry) => registry,
                        Err(error) => {
                            eprintln!("{error}");
                            std::process::exit(1);
                        }
                    };
                let wire = scan_wire_options_from_arguments(&scan);
                match new_arp_scan::run(ApplicationCommand::Scan {
                    interface_name: scan.interface_name,
                    target_ipv4_address: scan.host_ipv4_address,
                    timeout: Duration::from_millis(scan.timeout_milliseconds),
                    pacing: Duration::from_millis(scan.pacing_milliseconds),
                    attempts: std::num::NonZeroU64::new(scan.attempts).expect(
                        "clap should reject zero attempts before reaching the application run path",
                    ),
                    wire,
                }) {
                    Ok(outcome) => {
                        let mut standard_output = std::io::stdout().lock();
                        let mut standard_error = std::io::stderr().lock();
                        outcome
                            .write_operator_streams_with_mac_vendor_registry(
                                &mut standard_output,
                                &mut standard_error,
                                mac_vendor_registry.as_ref(),
                            )
                            .expect(
                                "writing operator output to standard streams should succeed for a CLI binary",
                            );
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                }
            }
            Some(CliSubcommand::Interfaces) => {
                match new_arp_scan::run(ApplicationCommand::UsableInterfacesList) {
                    Ok(outcome) => {
                        let mut standard_output = std::io::stdout().lock();
                        let mut standard_error = std::io::stderr().lock();
                        outcome
                            .write_operator_streams(&mut standard_output, &mut standard_error)
                            .expect(
                                "writing operator output to standard streams should succeed for a CLI binary",
                            );
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                let mut command = CliRoot::command();
                command
                    .print_help()
                    .expect("printing help should succeed for a CLI binary");
            }
        },
        Err(error) => error.exit(),
    }
}

fn scan_wire_options_from_arguments(scan: &ScanArguments) -> ScanWireOptions {
    ScanWireOptions {
        vlan_identifier: scan.vlan_identifier.map(|vlan_identifier| {
            Ieee8021qVlanIdentifier::new(vlan_identifier).expect(
                "clap should reject VLAN identifiers above 4095 before reaching the application run path",
            )
        }),
        vlan_priority_code_point: scan.vlan_priority_code_point.map_or(
            Ieee8021qPriorityCodePoint::ZERO,
            |priority_code_point| {
                Ieee8021qPriorityCodePoint::new(priority_code_point).expect(
                    "clap should reject Priority Code Points above 7 before reaching the application run path",
                )
            },
        ),
        vlan_drop_eligible_indicator: scan.vlan_drop_eligible_indicator,
        service_vlan_identifier: scan.service_vlan_identifier.map(|service_vlan_identifier| {
            Ieee8021qVlanIdentifier::new(service_vlan_identifier).expect(
                "clap should reject service VLAN identifiers above 4095 before reaching the application run path",
            )
        }),
        service_vlan_priority_code_point: scan.service_vlan_priority_code_point.map_or(
            Ieee8021qPriorityCodePoint::ZERO,
            |priority_code_point| {
                Ieee8021qPriorityCodePoint::new(priority_code_point).expect(
                    "clap should reject service Priority Code Points above 7 before reaching the application run path",
                )
            },
        ),
        service_vlan_drop_eligible_indicator: scan.service_vlan_drop_eligible_indicator,
        sender_protocol_address: scan
            .sender_protocol_address
            .unwrap_or(ArpSenderProtocolAddress::Interface),
        llc_snap: scan.llc_snap,
        ethernet_destination: scan.ethernet_destination,
        ethernet_source: scan.ethernet_source,
        arp_hardware_type: scan.arp_hardware_type,
        arp_protocol_type: scan.arp_protocol_type,
        arp_hardware_length: scan.arp_hardware_length,
        arp_protocol_length: scan.arp_protocol_length,
        arp_operation: scan.arp_operation,
        arp_sender_hardware: scan.arp_sender_hardware,
        arp_target_hardware: scan.arp_target_hardware,
        padding: scan
            .ethernet_padding
            .clone()
            .map_or_else(Vec::new, EthernetPaddingOctets::into_vec),
    }
}

#[cfg(feature = "bundled-mac-vendors")]
const BUNDLED_MAC_VENDOR_TEXT: &str = include_str!(env!("NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE"));

fn load_mac_vendor_registry(
    explicit_path: Option<&std::path::Path>,
) -> Result<Option<MacVendorRegistry>, String> {
    match explicit_path {
        Some(path) => MacVendorRegistry::load_from_path(path)
            .map(Some)
            .map_err(|error| format!("failed to load MAC vendor file {}: {error}", path.display())),
        None => match MacVendorRegistry::load_default_file_if_present() {
            Ok(Some(registry)) => Ok(Some(registry)),
            Ok(None) => {
                #[cfg(feature = "bundled-mac-vendors")]
                {
                    MacVendorRegistry::parse_ieee_oui_text(BUNDLED_MAC_VENDOR_TEXT)
                        .map(Some)
                        .map_err(|error| {
                            format!("failed to parse bundled MAC vendor registry: {error}")
                        })
                }
                #[cfg(not(feature = "bundled-mac-vendors"))]
                {
                    Ok(None)
                }
            }
            Err(error) => Err(format!(
                "failed to load default MAC vendor file ieee-oui.txt: {error}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::load_mac_vendor_registry;
    use new_arp_scan::mac_address::MacAddress;
    use new_arp_scan::mac_vendor_registry::DEFAULT_MAC_VENDOR_FILE_NAME;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    static CWD_LOCK: Mutex<()> = Mutex::new(());
    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    struct IsolatedCwd {
        previous: PathBuf,
        directory: PathBuf,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for IsolatedCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.previous);
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn isolate_empty_cwd() -> IsolatedCwd {
        let lock = CWD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = std::env::current_dir().expect("current directory should be readable");
        let stamp = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "new-arp-scan-mac-vendor-cwd-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("isolated cwd");
        std::env::set_current_dir(&directory).expect("chdir into isolated cwd");
        IsolatedCwd {
            previous,
            directory,
            _lock: lock,
        }
    }

    #[test]
    fn mac_address_display_matches_lowercase_colon_format() {
        // Arrange
        let address = MacAddress::from_octets([0x00u8, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);

        // Act
        let formatted = address.to_string();

        // Assert
        assert_eq!(
            formatted, "00:1a:2b:3c:4d:5e",
            "output should be stable lowercase colon-separated Ethernet notation"
        );
    }

    #[test]
    fn load_mac_vendor_registry_reads_explicit_file() {
        // Arrange
        let directory = std::env::temp_dir();
        let path = directory.join("new-arp-scan-mac-vendor-fixture.txt");
        let mut file = std::fs::File::create(&path).expect("temp mapping file should create");
        file.write_all(b"001122\tFixture Vendor\n")
            .expect("temp mapping file should write");
        drop(file);

        // Act
        let registry = load_mac_vendor_registry(Some(&path)).expect("explicit file should load");

        // Assert
        let registry = registry.expect("explicit path should yield Some");
        let address = MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1]);
        assert_eq!(registry.vendor_name_for(address), Some("Fixture Vendor"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_mac_vendor_registry_reports_missing_explicit_file() {
        // Arrange
        let path = std::path::Path::new("/no/such/new-arp-scan-ieee-oui.txt");

        // Act
        let outcome = load_mac_vendor_registry(Some(path));

        // Assert
        let error = outcome.expect_err("missing explicit file should fail");
        assert!(
            error.contains("failed to load MAC vendor file"),
            "error should name the load failure, got: {error}"
        );
    }

    #[test]
    fn explicit_path_overrides_cwd_and_bundled_text() {
        // Arrange
        let _cwd = isolate_empty_cwd();
        fs::write(DEFAULT_MAC_VENDOR_FILE_NAME, "AABBCC\tCwd Vendor\n").expect("cwd mapping file");
        let explicit = std::env::temp_dir().join(format!(
            "new-arp-scan-explicit-mac-vendor-{}.txt",
            std::process::id()
        ));
        fs::write(&explicit, "001122\tExplicit Vendor\n").expect("explicit mapping file");

        // Act
        let registry =
            load_mac_vendor_registry(Some(&explicit)).expect("explicit file should load");

        // Assert
        let registry = registry.expect("explicit path should yield Some");
        let explicit_address = MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1]);
        let cwd_address = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1]);
        assert_eq!(
            registry.vendor_name_for(explicit_address),
            Some("Explicit Vendor")
        );
        assert_eq!(
            registry.vendor_name_for(cwd_address),
            None,
            "explicit file must not merge cwd mappings"
        );
        let _ = fs::remove_file(&explicit);
    }

    #[test]
    fn cwd_ieee_oui_is_used_when_no_explicit_path_is_given() {
        // Arrange
        let _cwd = isolate_empty_cwd();
        fs::write(DEFAULT_MAC_VENDOR_FILE_NAME, "AABBCC\tCwd Vendor\n").expect("cwd mapping file");

        // Act
        let registry = load_mac_vendor_registry(None).expect("cwd file should load");

        // Assert
        let registry = registry.expect("cwd file should yield Some");
        let address = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1]);
        assert_eq!(registry.vendor_name_for(address), Some("Cwd Vendor"));
    }

    #[cfg(not(feature = "bundled-mac-vendors"))]
    #[test]
    fn unbundled_build_returns_none_when_cwd_file_is_absent() {
        // Arrange
        let _cwd = isolate_empty_cwd();

        // Act
        let registry = load_mac_vendor_registry(None).expect("missing default file is ok");

        // Assert
        assert!(
            registry.is_none(),
            "default unbundled builds must not invent a registry"
        );
    }

    #[cfg(feature = "bundled-mac-vendors")]
    #[test]
    fn bundled_fixture_is_used_when_cwd_file_is_absent() {
        // Arrange
        let _cwd = isolate_empty_cwd();
        let matched = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x00, 0x01, 0x22]);
        let unknown = MacAddress::from_octets([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);

        // Act
        let registry = load_mac_vendor_registry(None).expect("bundled registry should parse");

        // Assert
        let registry = registry.expect("bundled feature should yield Some");
        assert_eq!(registry.vendor_name_for(matched), Some("Fixture MA-S"));
        assert_eq!(
            registry.vendor_name_for(unknown),
            None,
            "unmatched prefixes stay unknown so scan output can print (Unknown)"
        );
    }

    #[test]
    fn invalid_cwd_ieee_oui_fails_closed_without_falling_back_to_bundled() {
        // Arrange
        let _cwd = isolate_empty_cwd();
        fs::write(DEFAULT_MAC_VENDOR_FILE_NAME, "not a mapping line\n")
            .expect("invalid cwd mapping file");

        // Act
        let outcome = load_mac_vendor_registry(None);

        // Assert
        let error = outcome.expect_err("a present but invalid cwd file must fail");
        assert!(
            error.contains("failed to load default MAC vendor file ieee-oui.txt"),
            "operators should see the cwd load failure rather than a silent bundled fallback, got: {error}"
        );
    }

    #[test]
    fn invalid_explicit_file_fails_without_using_cwd() {
        // Arrange
        let _cwd = isolate_empty_cwd();
        fs::write(DEFAULT_MAC_VENDOR_FILE_NAME, "AABBCC\tCwd Vendor\n").expect("cwd mapping file");
        let explicit = std::env::temp_dir().join(format!(
            "new-arp-scan-invalid-explicit-mac-vendor-{}.txt",
            std::process::id()
        ));
        fs::write(&explicit, "not a mapping line\n").expect("invalid explicit mapping file");

        // Act
        let outcome = load_mac_vendor_registry(Some(&explicit));

        // Assert
        let error = outcome.expect_err("invalid explicit file must fail");
        assert!(
            error.contains("failed to load MAC vendor file"),
            "explicit parse failures must not fall back to cwd, got: {error}"
        );
        let _ = fs::remove_file(&explicit);
    }

    #[test]
    fn distinct_explicit_paths_do_not_share_mappings() {
        // Arrange
        let first = std::env::temp_dir().join(format!(
            "new-arp-scan-explicit-a-{}.txt",
            std::process::id()
        ));
        let second = std::env::temp_dir().join(format!(
            "new-arp-scan-explicit-b-{}.txt",
            std::process::id()
        ));
        fs::write(&first, "001122\tFirst Vendor\n").expect("first explicit file");
        fs::write(&second, "AABBCC\tSecond Vendor\n").expect("second explicit file");

        // Act
        let first_registry = load_mac_vendor_registry(Some(&first))
            .expect("first file should load")
            .expect("first path should yield Some");
        let second_registry = load_mac_vendor_registry(Some(&second))
            .expect("second file should load")
            .expect("second path should yield Some");

        // Assert
        let first_address = MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1]);
        let second_address = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1]);
        assert_eq!(
            first_registry.vendor_name_for(first_address),
            Some("First Vendor")
        );
        assert_eq!(first_registry.vendor_name_for(second_address), None);
        assert_eq!(
            second_registry.vendor_name_for(second_address),
            Some("Second Vendor")
        );
        assert_eq!(second_registry.vendor_name_for(first_address), None);
        let _ = fs::remove_file(&first);
        let _ = fs::remove_file(&second);
    }

    #[cfg(feature = "bundled-mac-vendors")]
    #[test]
    fn cwd_mapping_does_not_merge_bundled_prefixes() {
        // Arrange
        let _cwd = isolate_empty_cwd();
        fs::write(DEFAULT_MAC_VENDOR_FILE_NAME, "AABBCC\tCwd Vendor\n").expect("cwd mapping file");
        let cwd_address = MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1]);
        let bundled_address = MacAddress::from_octets([0xF4, 0xA4, 0x75, 0x00, 0x01, 0x22]);

        // Act
        let registry = load_mac_vendor_registry(None)
            .expect("cwd file should load")
            .expect("cwd file should yield Some");

        // Assert
        assert_eq!(registry.vendor_name_for(cwd_address), Some("Cwd Vendor"));
        assert_eq!(
            registry.vendor_name_for(bundled_address),
            None,
            "a present cwd file must replace bundled mappings, not merge with them"
        );
    }
}
