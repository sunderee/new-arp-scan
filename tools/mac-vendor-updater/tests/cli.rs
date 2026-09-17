//! Hermetic CLI and fixture conversion tests. None of these contact IEEE.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use mac_vendor_updater::UpdateRequest;
use mac_vendor_updater::UpdaterError;
use mac_vendor_updater::convert_ieee_registry_csvs;
use mac_vendor_updater::run_update;
use new_arp_scan::MacAddress;
use new_arp_scan::MacVendorRegistry;

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn unique_dir() -> PathBuf {
    let stamp = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "mac-vendor-updater-int-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("temp directory");
    path
}

fn updater_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mac-vendor-updater"))
}

fn csv_text(relative: &str) -> String {
    fs::read_to_string(fixtures_dir().join(relative)).expect("read fixture CSV")
}

#[test]
fn valid_fixtures_convert_byte_stably_and_parse() {
    // Arrange
    let mal = csv_text("valid/oui.csv");
    let mam = csv_text("valid/mam.csv");
    let mas = csv_text("valid/oui36.csv");
    let iab = csv_text("valid/iab.csv");
    let inputs = [
        mac_vendor_updater::RegistryCsvInput {
            registry: mac_vendor_updater::IeeeMacRegistry::MaL,
            csv_text: &mal,
        },
        mac_vendor_updater::RegistryCsvInput {
            registry: mac_vendor_updater::IeeeMacRegistry::MaM,
            csv_text: &mam,
        },
        mac_vendor_updater::RegistryCsvInput {
            registry: mac_vendor_updater::IeeeMacRegistry::MaS,
            csv_text: &mas,
        },
        mac_vendor_updater::RegistryCsvInput {
            registry: mac_vendor_updater::IeeeMacRegistry::Iab,
            csv_text: &iab,
        },
    ];

    // Act
    let first = convert_ieee_registry_csvs(&inputs, "2026-09-17T12:00:00Z").expect("first");
    let second = convert_ieee_registry_csvs(&inputs, "2026-09-17T12:00:00Z").expect("second");
    let registry =
        MacVendorRegistry::parse_ieee_oui_text(&first.text).expect("generated text must parse");

    // Assert
    assert_eq!(first.text, second.text);
    assert_eq!(first.counts[0].source_rows, 6);
    assert_eq!(first.counts[0].emitted, 5);
    assert_eq!(first.counts[0].duplicates_removed, 1);
    assert_eq!(
        registry.vendor_name_for(MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1])),
        Some("Second")
    );
    assert_eq!(
        registry.vendor_name_for(MacAddress::from_octets([
            0xF4, 0xA4, 0x75, 0x00, 0x01, 0x22
        ])),
        Some("Fixture MA-S")
    );
}

#[test]
fn cli_from_dir_writes_output_without_network() {
    // Arrange
    let dir = unique_dir();
    let output = dir.join("ieee-oui.txt");

    // Act
    let result = Command::new(updater_binary())
        .args([
            "--from-dir",
            fixtures_dir().join("valid").to_str().expect("utf8 path"),
            "--output",
            output.to_str().expect("utf8 output"),
            "--retrieved-at",
            "2026-09-17T12:00:00Z",
        ])
        .output()
        .expect("spawn updater");

    // Assert
    assert!(
        result.status.success(),
        "offline updater should succeed, stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = fs::read_to_string(&output).expect("read CLI output");
    assert!(text.contains("F4A475\tIntel Corporate\n"));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("duplicates removed"),
        "stderr should report provenance counts, got: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_help_exits_successfully() {
    // Arrange
    // Act
    let result = Command::new(updater_binary())
        .arg("--help")
        .output()
        .expect("spawn help");

    // Assert
    assert_eq!(result.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("mac-vendor-updater") && stdout.contains("IAB"));
}

#[test]
fn cli_short_help_exits_successfully() {
    // Arrange
    // Act
    let result = Command::new(updater_binary())
        .arg("-h")
        .output()
        .expect("spawn short help");

    // Assert
    assert_eq!(result.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains("--from-dir") && stdout.contains("IAB"),
        "-h should print the same operator help, got: {stdout}"
    );
}

#[test]
fn cli_unknown_argument_exits_one() {
    // Arrange
    // Act
    let result = Command::new(updater_binary())
        .arg("--cidr")
        .output()
        .expect("spawn unknown argument");

    // Assert
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("unknown argument") && stderr.contains("--cidr"),
        "unknown flags must fail closed on stderr, got: {stderr}"
    );
}

#[test]
fn cli_from_dir_without_value_exits_one() {
    // Arrange
    // Act
    let result = Command::new(updater_binary())
        .arg("--from-dir")
        .output()
        .expect("spawn missing from-dir value");

    // Assert
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("--from-dir requires a value"),
        "missing flag values must fail closed, got: {stderr}"
    );
}

#[test]
fn malformed_fixtures_do_not_clobber_existing_output() {
    // Arrange
    let dir = unique_dir();
    let output = dir.join("ieee-oui.txt");
    fs::write(&output, "keep-me\n").expect("seed output");

    // Act
    let outcome = run_update(&UpdateRequest {
        output_path: output.clone(),
        from_dir: Some(fixtures_dir().join("malformed")),
        retrieved_at_utc: Some("2026-09-17T12:00:00Z".to_string()),
    });

    // Assert
    assert!(
        matches!(outcome, Err(UpdaterError::Convert(_))),
        "malformed assignment must fail, got: {outcome:?}"
    );
    assert_eq!(
        fs::read_to_string(&output).expect("read output"),
        "keep-me\n"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cli_with_fake_curl_on_path_fails_without_touching_output() {
    // Arrange
    use std::os::unix::fs::PermissionsExt;

    let dir = unique_dir();
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).expect("bin dir");
    let curl = bin.join("curl");
    fs::write(&curl, "#!/bin/sh\necho fake-curl-fail >&2\nexit 22\n").expect("fake curl");
    let mut permissions = fs::metadata(&curl).expect("curl metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&curl, permissions).expect("chmod curl");
    let output = dir.join("ieee-oui.txt");
    fs::write(&output, "keep-me\n").expect("seed output");

    let path = format!("{}:/usr/bin:/bin", bin.display());

    // Act
    let result = Command::new(updater_binary())
        .args(["--output", output.to_str().expect("utf8 output")])
        .env("PATH", &path)
        .output()
        .expect("spawn updater with fake curl");

    // Assert
    assert!(!result.status.success(), "fake curl must fail the updater");
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("curl failed") || stderr.contains("exit 22"),
        "stderr should report curl failure, got: {stderr}"
    );
    assert_eq!(
        fs::read_to_string(&output).expect("read output"),
        "keep-me\n"
    );
    let _ = fs::remove_dir_all(&dir);
}
