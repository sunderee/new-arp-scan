//! Deterministic conversion of official IEEE CSVs into `ieee-oui.txt` text.

use std::collections::HashMap;
use std::fmt::Write as _;

use csv::ReaderBuilder;
use csv::StringRecord;

use crate::error::ConvertError;
use crate::registry::IeeeMacRegistry;

const EXPECTED_HEADERS: [&str; 4] = [
    "Registry",
    "Assignment",
    "Organization Name",
    "Organization Address",
];

/// Official IEEE CSV text for one registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryCsvInput<'a> {
    /// Registry this CSV is supposed to describe.
    pub registry: IeeeMacRegistry,
    /// Entire CSV document, including the header row.
    pub csv_text: &'a str,
}

/// How many rows a registry contributed after conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryCounts {
    /// Registry these counts describe.
    pub registry: IeeeMacRegistry,
    /// Unique prefixes emitted (last duplicate assignment wins).
    pub emitted: usize,
    /// Data rows accepted from the CSV before deduplication.
    pub source_rows: usize,
    /// Duplicate assignments dropped because a later row reused the prefix.
    pub duplicates_removed: usize,
}

/// Converted `ieee-oui.txt` text plus per-registry counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedIeeeOui {
    /// Mapping file text accepted by [`new_arp_scan::MacVendorRegistry`].
    pub text: String,
    /// Counts in [`IeeeMacRegistry::ALL`] order.
    pub counts: Vec<RegistryCounts>,
}

/// Converts official MA-L, MA-M, MA-S, and IAB CSVs into `ieee-oui.txt` text.
///
/// Inputs must include every registry in [`IeeeMacRegistry::ALL`]. Duplicate assignments keep the
/// last source row; prefixes are emitted in first-seen order with that last vendor name.
///
/// # Errors
///
/// Returns [`ConvertError`] when a header, row, assignment width, registry label, vendor name,
/// or CSV record is invalid. The converter does not skip malformed rows.
pub fn convert_ieee_registry_csvs(
    inputs: &[RegistryCsvInput<'_>],
    retrieved_at_utc: &str,
) -> Result<ConvertedIeeeOui, ConvertError> {
    let mut sections = Vec::with_capacity(IeeeMacRegistry::ALL.len());
    for expected in IeeeMacRegistry::ALL {
        let input = inputs
            .iter()
            .copied()
            .find(|input| input.registry == expected)
            .ok_or(ConvertError::EmptyRegistry { registry: expected })?;
        sections.push(convert_one_registry(input)?);
    }
    Ok(ConvertedIeeeOui {
        text: render_ieee_oui_text(retrieved_at_utc, &sections),
        counts: sections.iter().map(|section| section.counts).collect(),
    })
}

struct RegistrySection {
    counts: RegistryCounts,
    mappings: Vec<(String, String)>,
}

fn convert_one_registry(input: RegistryCsvInput<'_>) -> Result<RegistrySection, ConvertError> {
    let csv_text = strip_utf8_bom(input.csv_text);
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(csv_text.as_bytes());

    let headers = reader
        .headers()
        .map_err(|error| csv_error(Some(input.registry), &error))?;
    validate_headers(headers)?;

    let mut first_seen_order = Vec::new();
    let mut last_vendor_by_prefix = HashMap::new();
    let mut source_rows = 0_usize;

    for record in reader.records() {
        let record = record.map_err(|error| csv_error(Some(input.registry), &error))?;
        let line_number = record
            .position()
            .map_or(0, |position| position.line().saturating_add(1));
        if record.len() != EXPECTED_HEADERS.len() {
            return Err(ConvertError::WrongFieldCount {
                registry: input.registry,
                line_number,
                field_count: record.len(),
            });
        }
        let registry_field = record_field(&record, 0, input.registry, line_number)?;
        if registry_field != input.registry.csv_registry_label() {
            return Err(ConvertError::RegistryMismatch {
                expected: input.registry,
                found: registry_field.to_string(),
                line_number,
            });
        }
        let assignment_field = record_field(&record, 1, input.registry, line_number)?;
        let prefix = normalize_assignment(assignment_field, input.registry).ok_or_else(|| {
            ConvertError::InvalidAssignment {
                registry: input.registry,
                assignment: assignment_field.trim().to_string(),
                line_number,
            }
        })?;
        let vendor_field = record_field(&record, 2, input.registry, line_number)?;
        let vendor = vendor_field.trim();
        if vendor.is_empty() {
            return Err(ConvertError::EmptyVendor {
                registry: input.registry,
                assignment: prefix,
                line_number,
            });
        }
        source_rows = source_rows.checked_add(1).expect(
            "INVARIANT: source row count cannot overflow usize on a host that held the CSV",
        );
        if last_vendor_by_prefix
            .insert(prefix.clone(), vendor.to_string())
            .is_none()
        {
            first_seen_order.push(prefix);
        }
    }

    if source_rows == 0 {
        return Err(ConvertError::EmptyRegistry {
            registry: input.registry,
        });
    }

    let mappings: Vec<(String, String)> = first_seen_order
        .into_iter()
        .map(|prefix| {
            let vendor = last_vendor_by_prefix.remove(&prefix).expect(
                "INVARIANT: every first-seen prefix was inserted into last_vendor_by_prefix",
            );
            (prefix, vendor)
        })
        .collect();
    let emitted = mappings.len();
    let duplicates_removed = source_rows
        .checked_sub(emitted)
        .expect("INVARIANT: unique prefixes cannot exceed accepted source rows");

    Ok(RegistrySection {
        counts: RegistryCounts {
            registry: input.registry,
            emitted,
            source_rows,
            duplicates_removed,
        },
        mappings,
    })
}

fn record_field(
    record: &csv::StringRecord,
    index: usize,
    registry: IeeeMacRegistry,
    line_number: u64,
) -> Result<&str, ConvertError> {
    record.get(index).ok_or(ConvertError::WrongFieldCount {
        registry,
        line_number,
        field_count: record.len(),
    })
}

fn validate_headers(headers: &StringRecord) -> Result<(), ConvertError> {
    if headers.len() != EXPECTED_HEADERS.len() {
        return Err(ConvertError::InvalidHeader {
            found: headers.iter().collect::<Vec<_>>().join(","),
        });
    }
    for (index, expected) in EXPECTED_HEADERS.iter().enumerate() {
        let found = headers
            .get(index)
            .ok_or_else(|| ConvertError::InvalidHeader {
                found: headers.iter().collect::<Vec<_>>().join(","),
            })?;
        if found != *expected {
            return Err(ConvertError::InvalidHeader {
                found: headers.iter().collect::<Vec<_>>().join(","),
            });
        }
    }
    Ok(())
}

fn normalize_assignment(raw: &str, registry: IeeeMacRegistry) -> Option<String> {
    let stripped: String = raw
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | '.' | ' ' | '\t'))
        .collect();
    let expected = registry.assignment_hex_digit_count();
    if stripped.len() != expected {
        return None;
    }
    if !stripped.bytes().all(|octet| octet.is_ascii_hexdigit()) {
        return None;
    }
    Some(stripped.to_ascii_uppercase())
}

fn strip_utf8_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn csv_error(registry: Option<IeeeMacRegistry>, error: &csv::Error) -> ConvertError {
    ConvertError::Csv {
        registry,
        line_number: error.position().map(csv::Position::line),
        message: error.to_string(),
    }
}

fn render_ieee_oui_text(retrieved_at_utc: &str, sections: &[RegistrySection]) -> String {
    let mut text = String::new();
    write_line(
        &mut text,
        format_args!(
            "\
# ieee-oui.txt -- IEEE Ethernet OUI-Vendor mapping file for new-arp-scan
#
# Generated by mac-vendor-updater. Do not edit this file.
# Extra local mappings belong in a separate file passed to --mac-vendor-file.
#
# Retrieved (UTC): {retrieved_at_utc}
#
# Sources:"
        ),
    );
    for registry in IeeeMacRegistry::ALL {
        write_line(
            &mut text,
            format_args!(
                "#   {}: {}",
                registry.csv_registry_label(),
                registry.csv_url()
            ),
        );
    }
    write_line(
        &mut text,
        format_args!(
            "\
#
# Each line is <hex-prefix><TAB><vendor>. Blank lines and # comments are ignored.
# Duplicate assignments keep the last source row.
#
# Entry counts (emitted unique prefixes; last duplicate assignment wins):"
        ),
    );
    for section in sections {
        let counts = section.counts;
        write_line(
            &mut text,
            format_args!(
                "#   {}: {} emitted ({} {}, {} {} removed)",
                counts.registry.csv_registry_label(),
                counts.emitted,
                counts.source_rows,
                count_noun(counts.source_rows, "source row", "source rows"),
                counts.duplicates_removed,
                count_noun(counts.duplicates_removed, "duplicate", "duplicates")
            ),
        );
    }
    write_line(&mut text, format_args!(""));

    for section in sections {
        let label = section.counts.registry.csv_registry_label();
        write_line(
            &mut text,
            format_args!("#\n# Start of IEEE {label} registry data\n#"),
        );
        for (prefix, vendor) in &section.mappings {
            write_line(&mut text, format_args!("{prefix}\t{vendor}"));
        }
        write_line(
            &mut text,
            format_args!(
                "#\n# End of IEEE {label} registry data. {} emitted, {} {}, {} {} removed.\n#",
                section.counts.emitted,
                section.counts.source_rows,
                count_noun(section.counts.source_rows, "source row", "source rows"),
                section.counts.duplicates_removed,
                count_noun(section.counts.duplicates_removed, "duplicate", "duplicates")
            ),
        );
    }
    text
}

fn write_line(text: &mut String, args: std::fmt::Arguments<'_>) {
    text.write_fmt(args)
        .expect("INVARIANT: writing to String cannot fail");
    text.push('\n');
}

fn count_noun(count: usize, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::{
        ConvertError, RegistryCsvInput, convert_ieee_registry_csvs, normalize_assignment,
        render_ieee_oui_text,
    };
    use crate::registry::IeeeMacRegistry;
    use new_arp_scan::{MacAddress, MacVendorRegistry};
    use std::fmt::Write as _;

    const RETRIEVED_AT: &str = "2026-09-17T12:00:00Z";

    fn input(registry: IeeeMacRegistry, csv_text: &str) -> RegistryCsvInput<'_> {
        RegistryCsvInput { registry, csv_text }
    }

    fn four_registry_inputs<'a>(
        mal: &'a str,
        mam: &'a str,
        mas: &'a str,
        iab: &'a str,
    ) -> [RegistryCsvInput<'a>; 4] {
        [
            input(IeeeMacRegistry::MaL, mal),
            input(IeeeMacRegistry::MaM, mam),
            input(IeeeMacRegistry::MaS, mas),
            input(IeeeMacRegistry::Iab, iab),
        ]
    }

    fn standard_companion_csvs() -> (String, String, String) {
        let mam = "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,F4A4750,Fixture MA-M,Addr\r\n".to_string();
        let mas = "Registry,Assignment,Organization Name,Organization Address\r\nMA-S,F4A475000,Fixture MA-S,Addr\r\n".to_string();
        let iab = "Registry,Assignment,Organization Name,Organization Address\r\nIAB,40D8550D7,Avant Technologies,Addr\r\n".to_string();
        (mam, mas, iab)
    }

    #[test]
    fn converts_quoted_utf8_whitespace_private_and_duplicate_rows() {
        // Arrange
        let mal = "\
Registry,Assignment,Organization Name,Organization Address\r
MA-L,F4A475,Intel Corporate,Santa Clara\r
MA-L,AA:BB:CC,Separated Prefix,Addr\r
MA-L,AA.BB.00,Dotted Prefix,Addr\r
MA-L,aa-bb-11,Lowercase Separated,Addr\r
MA-L,001122,First,Addr\r
MA-L,001122,Second,Addr\r
MA-L,00FFEE,\"Vendor, with comma\",Addr\r
MA-L,00DDEE,Private,\r
MA-L,00CCDD,IEEE Registration Authority,Piscataway\r
MA-L,00BBAA,\"Shenzhen YOUHUA Technology Co., Ltd\t\",Addr\r
MA-L,00AA99,\"He said \"\"Hello\"\"\",Addr\r
MA-L,00AA88,Møller Elektronik,Århus\r
";
        let (mam, mas, iab) = standard_companion_csvs();
        let inputs = four_registry_inputs(mal, &mam, &mas, &iab);

        // Act
        let converted =
            convert_ieee_registry_csvs(&inputs, RETRIEVED_AT).expect("fixture CSVs should convert");
        let registry = MacVendorRegistry::parse_ieee_oui_text(&converted.text)
            .expect("generated text must parse");

        // Assert
        assert!(
            converted
                .text
                .contains("Retrieved (UTC): 2026-09-17T12:00:00Z")
                && converted.text.contains(IeeeMacRegistry::Iab.csv_url()),
            "provenance header should include timestamp and IAB URL, got:\n{}",
            converted.text
        );
        assert_eq!(converted.counts[0].source_rows, 12);
        assert_eq!(converted.counts[0].emitted, 11);
        assert_eq!(converted.counts[0].duplicates_removed, 1);
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0x11, 0x22, 0, 0, 1])),
            Some("Second"),
            "last duplicate assignment must win"
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0xFF, 0xEE, 0, 0, 1])),
            Some("Vendor, with comma")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0xDD, 0xEE, 0, 0, 1])),
            Some("Private")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0xCC, 0xDD, 0, 0, 1])),
            Some("IEEE Registration Authority")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0xBB, 0xAA, 0, 0, 1])),
            Some("Shenzhen YOUHUA Technology Co., Ltd")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1])),
            Some("Separated Prefix")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0xAA, 0xBB, 0x00, 0, 0, 1])),
            Some("Dotted Prefix")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0xAA, 0xBB, 0x11, 0, 0, 1])),
            Some("Lowercase Separated")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0xAA, 0x99, 0, 0, 1])),
            Some("He said \"Hello\"")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0xAA, 0x88, 0, 0, 1])),
            Some("Møller Elektronik")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([
                0xF4, 0xA4, 0x75, 0x00, 0x01, 0x22
            ])),
            Some("Fixture MA-S"),
            "MA-S must win over overlapping MA-M/MA-L"
        );
        assert!(
            converted.text.contains("001122\tSecond\n")
                && !converted.text.contains("001122\tFirst\n"),
            "deduped output should emit the last vendor once, got:\n{}",
            converted.text
        );
        let intel_offset = converted
            .text
            .find("F4A475\tIntel Corporate\n")
            .expect("MA-L Intel row");
        let duplicate_offset = converted
            .text
            .find("001122\tSecond\n")
            .expect("deduped MA-L row");
        assert!(
            intel_offset < duplicate_offset,
            "duplicate prefixes must keep first-seen emit order, got:\n{}",
            converted.text
        );
        assert!(
            converted
                .text
                .contains("#   MA-L: 11 emitted (12 source rows, 1 duplicate removed)"),
            "singular 'duplicate' for a count of one, got:\n{}",
            converted.text
        );
    }

    #[test]
    fn conversion_is_byte_stable_for_fixed_inputs_and_timestamp() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,Example,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();
        let inputs = four_registry_inputs(mal, &mam, &mas, &iab);

        // Act
        let first = convert_ieee_registry_csvs(&inputs, RETRIEVED_AT).expect("first convert");
        let second = convert_ieee_registry_csvs(&inputs, RETRIEVED_AT).expect("second convert");

        // Assert
        assert_eq!(first.text, second.text);
        assert!(first.text.contains("AABBCC\tExample\n"));
        assert!(
            first
                .text
                .contains("#   MA-L: 1 emitted (1 source row, 0 duplicates removed)")
        );
    }

    #[test]
    fn overlapping_ma_s_and_iab_keep_the_later_source_row() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,Example,Addr\r\n";
        let mam = "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,F4A4750,Fixture MA-M,Addr\r\n";
        let mas = "Registry,Assignment,Organization Name,Organization Address\r\nMA-S,40D8550D7,From MA-S,Addr\r\n";
        let iab = "Registry,Assignment,Organization Name,Organization Address\r\nIAB,40D8550D7,From IAB,Addr\r\n";

        // Act
        let converted =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, mam, mas, iab), RETRIEVED_AT)
                .expect("overlapping 36-bit prefixes should convert");
        let registry = MacVendorRegistry::parse_ieee_oui_text(&converted.text)
            .expect("generated text must parse");

        // Assert
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([
                0x40, 0xD8, 0x55, 0x0D, 0x70, 0x01
            ])),
            Some("From IAB"),
            "IAB is emitted last, so the mapping parser's last-row-wins keeps IAB"
        );
    }

    #[test]
    fn rejects_wrong_header() {
        // Arrange
        let mal = "Registry,Assignment,Name,Address\r\nMA-L,AABBCC,Example,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();
        let inputs = four_registry_inputs(mal, &mam, &mas, &iab);

        // Act
        let outcome = convert_ieee_registry_csvs(&inputs, RETRIEVED_AT);

        // Assert
        assert!(
            matches!(outcome, Err(ConvertError::InvalidHeader { .. })),
            "wrong header should fail loudly, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_wrong_registry_label() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,AABBCC,Example,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();
        let inputs = four_registry_inputs(mal, &mam, &mas, &iab);

        // Act
        let outcome = convert_ieee_registry_csvs(&inputs, RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::RegistryMismatch {
                    expected: IeeeMacRegistry::MaL,
                    line_number: 2,
                    ..
                })
            ),
            "MA-M row in the MA-L file should fail, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_assignment_that_would_require_truncation() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCCDD,TooLong,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();
        let inputs = four_registry_inputs(mal, &mam, &mas, &iab);

        // Act
        let outcome = convert_ieee_registry_csvs(&inputs, RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaL,
                    line_number: 2,
                    ..
                })
            ),
            "over-long assignments must not be truncated, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_short_and_non_hex_assignments() {
        // Arrange
        let short = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABB,Short,Addr\r\n";
        let not_hex = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,GGHHII,Bad,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let short_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(short, &mam, &mas, &iab),
            RETRIEVED_AT,
        );
        let not_hex_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(not_hex, &mam, &mas, &iab),
            RETRIEVED_AT,
        );

        // Assert
        assert!(
            matches!(short_outcome, Err(ConvertError::InvalidAssignment { .. })),
            "short assignment should fail, got: {short_outcome:?}"
        );
        assert!(
            matches!(not_hex_outcome, Err(ConvertError::InvalidAssignment { .. })),
            "non-hex assignment should fail, got: {not_hex_outcome:?}"
        );
    }

    #[test]
    fn rejects_empty_vendor_and_empty_registry() {
        // Arrange
        let empty_vendor = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,   ,Addr\r\n";
        let header_only = "Registry,Assignment,Organization Name,Organization Address\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let empty_vendor_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(empty_vendor, &mam, &mas, &iab),
            RETRIEVED_AT,
        );
        let empty_registry_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(header_only, &mam, &mas, &iab),
            RETRIEVED_AT,
        );

        // Assert
        assert!(
            matches!(
                empty_vendor_outcome,
                Err(ConvertError::EmptyVendor {
                    registry: IeeeMacRegistry::MaL,
                    ..
                })
            ),
            "blank vendor should fail, got: {empty_vendor_outcome:?}"
        );
        assert!(
            matches!(
                empty_registry_outcome,
                Err(ConvertError::EmptyRegistry {
                    registry: IeeeMacRegistry::MaL
                })
            ),
            "header-only CSV should fail, got: {empty_registry_outcome:?}"
        );
    }

    #[test]
    fn rejects_wrong_field_count() {
        // Arrange
        let short = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,OnlyThree\r\n";
        let extra = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,Five,Addr,Extra\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let short_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(short, &mam, &mas, &iab),
            RETRIEVED_AT,
        );
        let extra_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(extra, &mam, &mas, &iab),
            RETRIEVED_AT,
        );

        // Assert
        assert!(
            matches!(
                short_outcome,
                Err(ConvertError::WrongFieldCount {
                    registry: IeeeMacRegistry::MaL,
                    field_count: 3,
                    ..
                })
            ),
            "short records should fail, got: {short_outcome:?}"
        );
        assert!(
            matches!(
                extra_outcome,
                Err(ConvertError::WrongFieldCount {
                    registry: IeeeMacRegistry::MaL,
                    field_count: 5,
                    ..
                })
            ),
            "extra columns should fail, got: {extra_outcome:?}"
        );
    }

    #[test]
    fn strips_utf8_bom_and_accepts_lf_only_newlines() {
        // Arrange
        let mal = "\u{feff}Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Bom Vendor,Addr\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let converted =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT)
                .expect("BOM + LF CSV should convert");
        let registry = MacVendorRegistry::parse_ieee_oui_text(&converted.text)
            .expect("generated text must parse");

        // Assert
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1])),
            Some("Bom Vendor")
        );
    }

    #[test]
    fn scale_fixture_preserves_every_unique_prefix() {
        // Arrange
        let mut mal =
            String::from("Registry,Assignment,Organization Name,Organization Address\r\n");
        for index in 0..300_u16 {
            let prefix = format!("{index:06X}");
            write!(mal, "MA-L,{prefix},Vendor {index},Addr\r\n")
                .expect("INVARIANT: writing to String cannot fail");
        }
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let converted =
            convert_ieee_registry_csvs(&four_registry_inputs(&mal, &mam, &mas, &iab), RETRIEVED_AT)
                .expect("300-row MA-L fixture should convert");
        let registry = MacVendorRegistry::parse_ieee_oui_text(&converted.text)
            .expect("generated text must parse");

        // Assert
        assert_eq!(converted.counts[0].emitted, 300);
        assert_eq!(converted.counts[0].duplicates_removed, 0);
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0x00, 0x00, 1, 2, 3])),
            Some("Vendor 0")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0x00, 0x01, 0x2B, 1, 2, 3])),
            Some("Vendor 299")
        );
    }

    #[test]
    fn normalize_assignment_does_not_drop_trailing_hex_to_fit_width() {
        // Arrange
        // Act
        let too_long = normalize_assignment("AABBCCDD", IeeeMacRegistry::MaL);
        let separated = normalize_assignment("AA-BB-CC", IeeeMacRegistry::MaL);

        // Assert
        assert_eq!(too_long, None);
        assert_eq!(separated.as_deref(), Some("AABBCC"));
    }

    #[test]
    fn missing_registry_input_is_empty_registry() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,Example,Addr\r\n";
        let mam = "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,F4A4750,Fixture MA-M,Addr\r\n";
        let mas = "Registry,Assignment,Organization Name,Organization Address\r\nMA-S,F4A475000,Fixture MA-S,Addr\r\n";

        // Act
        let outcome = convert_ieee_registry_csvs(
            &[
                input(IeeeMacRegistry::MaL, mal),
                input(IeeeMacRegistry::MaM, mam),
                input(IeeeMacRegistry::MaS, mas),
            ],
            RETRIEVED_AT,
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::EmptyRegistry {
                    registry: IeeeMacRegistry::Iab
                })
            ),
            "omitting IAB should fail rather than skip, got: {outcome:?}"
        );
    }

    #[test]
    fn render_includes_sources_even_without_sections() {
        // Arrange
        // Act
        let text = render_ieee_oui_text(RETRIEVED_AT, &[]);

        // Assert
        assert!(text.contains("Sources:") && text.contains(RETRIEVED_AT));
        assert!(text.contains(IeeeMacRegistry::MaL.csv_url()));
    }

    #[test]
    fn later_malformed_row_fails_the_whole_conversion() {
        // Arrange
        let mal = "\
Registry,Assignment,Organization Name,Organization Address\r
MA-L,AABBCC,Good,Addr\r
MA-L,NOTHEX,Bad,Addr\r
";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let outcome =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaL,
                    ..
                })
            ),
            "a later bad row must fail the run, not skip, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_unclosed_quotes_as_a_short_record() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,\"unclosed,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let outcome =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::WrongFieldCount {
                    registry: IeeeMacRegistry::MaL,
                    field_count: 3,
                    ..
                })
            ),
            "an unclosed quote must fail closed; csv+flexible yields a 3-field record, got: {outcome:?}"
        );
    }

    #[test]
    fn quote_in_assignment_is_not_treated_as_a_separator() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AA\"BBCC,Name,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let outcome =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaL,
                    ref assignment,
                    ..
                }) if assignment == "AA\"BBCC"
            ),
            "quotes are not IEEE assignment separators, got: {outcome:?}"
        );
    }

    #[test]
    fn rejects_empty_file_and_header_with_wrong_column_count() {
        // Arrange
        let empty = "";
        let extra_header = "Registry,Assignment,Organization Name,Organization Address,Extra\r\nMA-L,AABBCC,Example,Addr,X\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let empty_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(empty, &mam, &mas, &iab),
            RETRIEVED_AT,
        );
        let extra_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(extra_header, &mam, &mas, &iab),
            RETRIEVED_AT,
        );

        // Assert
        assert!(
            matches!(empty_outcome, Err(ConvertError::InvalidHeader { .. })),
            "empty CSV must fail the header check, got: {empty_outcome:?}"
        );
        assert!(
            matches!(extra_outcome, Err(ConvertError::InvalidHeader { .. })),
            "extra header columns must fail, got: {extra_outcome:?}"
        );
    }

    #[test]
    fn preserves_inner_vendor_whitespace_and_rejects_empty_assignment() {
        // Arrange
        let inner = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,  Foo  Bar  ,Addr\r\n";
        let empty_assignment =
            "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,,NoAssign,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let converted = convert_ieee_registry_csvs(
            &four_registry_inputs(inner, &mam, &mas, &iab),
            RETRIEVED_AT,
        )
        .expect("inner whitespace vendor should convert");
        let registry = MacVendorRegistry::parse_ieee_oui_text(&converted.text)
            .expect("generated text must parse");
        let empty_assignment_outcome = convert_ieee_registry_csvs(
            &four_registry_inputs(empty_assignment, &mam, &mas, &iab),
            RETRIEVED_AT,
        );

        // Assert
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([0xAA, 0xBB, 0xCC, 0, 0, 1])),
            Some("Foo  Bar")
        );
        assert!(
            matches!(
                empty_assignment_outcome,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaL,
                    ref assignment,
                    ..
                }) if assignment.is_empty()
            ),
            "empty Assignment must fail, got: {empty_assignment_outcome:?}"
        );
    }

    #[test]
    fn assignment_widths_are_exact_for_ma_m_ma_s_and_iab() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,Example,Addr\r\n";
        let mam_short = "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,F4A475,TooShort,Addr\r\n";
        let mam_ok = "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,F4A4750,Medium,Addr\r\n";
        let mas = "Registry,Assignment,Organization Name,Organization Address\r\nMA-S,F4A475000,Small,Addr\r\n";
        let iab_long = "Registry,Assignment,Organization Name,Organization Address\r\nIAB,40D8550D70,TooLong,Addr\r\n";
        let iab_ok = "Registry,Assignment,Organization Name,Organization Address\r\nIAB,40D8550D7,IabVendor,Addr\r\n";

        // Act
        let short_mam = convert_ieee_registry_csvs(
            &four_registry_inputs(mal, mam_short, mas, iab_ok),
            RETRIEVED_AT,
        );
        let long_iab = convert_ieee_registry_csvs(
            &four_registry_inputs(mal, mam_ok, mas, iab_long),
            RETRIEVED_AT,
        );
        let ok = convert_ieee_registry_csvs(
            &four_registry_inputs(mal, mam_ok, mas, iab_ok),
            RETRIEVED_AT,
        )
        .expect("exact widths should convert");
        let registry =
            MacVendorRegistry::parse_ieee_oui_text(&ok.text).expect("generated text must parse");

        // Assert
        assert!(
            matches!(
                short_mam,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaM,
                    ..
                })
            ),
            "MA-M must not accept a 6-digit assignment, got: {short_mam:?}"
        );
        assert!(
            matches!(
                long_iab,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::Iab,
                    ..
                })
            ),
            "IAB must not accept a 10-digit assignment, got: {long_iab:?}"
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([
                0xF4, 0xA4, 0x75, 0x0F, 0x00, 0x01
            ])),
            Some("Medium")
        );
        assert_eq!(
            registry.vendor_name_for(MacAddress::from_octets([
                0x40, 0xD8, 0x55, 0x0D, 0x70, 0x01
            ])),
            Some("IabVendor")
        );
    }

    #[test]
    fn invalid_assignment_error_keeps_the_raw_field_not_a_truncated_prefix() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AA-BB-CC-DD,TooLong,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let outcome =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaL,
                    ref assignment,
                    ..
                }) if assignment == "AA-BB-CC-DD"
            ),
            "operators should see the raw assignment, not a silently truncated AABBCC, got: {outcome:?}"
        );
    }

    #[test]
    fn assignment_that_is_only_separators_is_invalid() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,:-.,EmptyHex,Addr\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let outcome =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(ConvertError::InvalidAssignment {
                    registry: IeeeMacRegistry::MaL,
                    ref assignment,
                    ..
                }) if assignment == ":-."
            ),
            "separator-only Assignment must fail with the raw field, got: {outcome:?}"
        );
    }

    #[test]
    fn header_with_too_few_columns_is_invalid() {
        // Arrange
        let mal = "Registry,Assignment,Organization Name\r\nMA-L,AABBCC,Example\r\n";
        let (mam, mas, iab) = standard_companion_csvs();

        // Act
        let outcome =
            convert_ieee_registry_csvs(&four_registry_inputs(mal, &mam, &mas, &iab), RETRIEVED_AT);

        // Assert
        assert!(
            matches!(outcome, Err(ConvertError::InvalidHeader { .. })),
            "a three-column header must fail, got: {outcome:?}"
        );
    }
}
