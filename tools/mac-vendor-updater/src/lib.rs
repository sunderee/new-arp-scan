//! Isolated IEEE MAC registry updater for `new-arp-scan`.
//!
//! Downloads are performed with system `curl`. Conversion lives in this crate so `csv` never
//! enters the privileged scan binary.

mod convert;
mod error;
mod fetch;
mod registry;
mod write;

pub use convert::ConvertedIeeeOui;
pub use convert::RegistryCounts;
pub use convert::RegistryCsvInput;
pub use convert::convert_ieee_registry_csvs;
pub use error::ConvertError;
pub use error::UpdaterError;
pub use fetch::fetch_official_csvs;
pub use fetch::utc_timestamp_from_date;
pub use registry::IeeeMacRegistry;
pub use write::replace_file_atomically;

use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use new_arp_scan::MacVendorRegistry;

/// Inputs for one updater run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRequest {
    /// Destination `ieee-oui.txt` path.
    pub output_path: PathBuf,
    /// When `Some`, read the four official CSV file names from this directory instead of curling.
    pub from_dir: Option<PathBuf>,
    /// Injected UTC timestamp. When `None`, `date -u` is invoked.
    pub retrieved_at_utc: Option<String>,
}

/// Converts the four IEEE CSVs and atomically replaces `output_path`.
///
/// # Errors
///
/// Returns [`UpdaterError`] when fetch, conversion, parse validation, or the atomic write fails.
/// An existing destination is left untouched until the generated text parses successfully.
pub fn run_update(request: &UpdateRequest) -> Result<ConvertedIeeeOui, UpdaterError> {
    let csv_dir = if let Some(directory) = &request.from_dir {
        directory.clone()
    } else {
        let parent = request
            .output_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let fetch_dir = parent.join(".mac-vendor-updater-csv");
        fetch_official_csvs(&fetch_dir)?;
        fetch_dir
    };

    let mut csv_texts = Vec::with_capacity(IeeeMacRegistry::ALL.len());
    for registry in IeeeMacRegistry::ALL {
        let path = csv_dir.join(registry.csv_file_name());
        let text = fs::read_to_string(&path).map_err(|source| UpdaterError::ReadCsv {
            path: path.clone(),
            message: source.to_string(),
        })?;
        csv_texts.push(text);
    }
    let inputs: Vec<RegistryCsvInput<'_>> = IeeeMacRegistry::ALL
        .iter()
        .zip(csv_texts.iter())
        .map(|(registry, text)| RegistryCsvInput {
            registry: *registry,
            csv_text: text,
        })
        .collect();

    let retrieved_at = if let Some(value) = &request.retrieved_at_utc {
        value.clone()
    } else {
        utc_timestamp_from_date()?
    };

    let converted = convert_ieee_registry_csvs(&inputs, &retrieved_at)?;
    MacVendorRegistry::parse_ieee_oui_text(&converted.text)
        .map_err(|source| UpdaterError::GeneratedTextRejected { source })?;
    replace_file_atomically(&request.output_path, &converted.text)?;
    Ok(converted)
}

/// Writes a human-readable conversion summary to `out`.
///
/// # Errors
///
/// Returns [`std::io::Error`] when writing the summary fails.
pub fn write_summary(converted: &ConvertedIeeeOui, mut out: impl Write) -> std::io::Result<()> {
    writeln!(
        out,
        "mac-vendor-updater: wrote {} bytes",
        converted.text.len()
    )?;
    for counts in &converted.counts {
        writeln!(
            out,
            "  {}: {} emitted ({} source rows, {} duplicates removed)",
            counts.registry.csv_registry_label(),
            counts.emitted,
            counts.source_rows,
            counts.duplicates_removed
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{UpdateRequest, run_update, write_summary};
    use crate::convert::ConvertedIeeeOui;
    use crate::convert::RegistryCounts;
    use crate::error::UpdaterError;
    use crate::registry::IeeeMacRegistry;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let stamp = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mac-vendor-updater-lib-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    fn write_four_csvs(dir: &Path, mal_body: &str) {
        fs::write(
            dir.join("oui.csv"),
            format!("Registry,Assignment,Organization Name,Organization Address\r\n{mal_body}"),
        )
        .expect("write MA-L");
        fs::write(
            dir.join("mam.csv"),
            "Registry,Assignment,Organization Name,Organization Address\r\nMA-M,F4A4750,Fixture MA-M,Addr\r\n",
        )
        .expect("write MA-M");
        fs::write(
            dir.join("oui36.csv"),
            "Registry,Assignment,Organization Name,Organization Address\r\nMA-S,F4A475000,Fixture MA-S,Addr\r\n",
        )
        .expect("write MA-S");
        fs::write(
            dir.join("iab.csv"),
            "Registry,Assignment,Organization Name,Organization Address\r\nIAB,40D8550D7,Avant Technologies,Addr\r\n",
        )
        .expect("write IAB");
    }

    #[test]
    fn from_dir_writes_validated_text_and_does_not_fetch() {
        // Arrange
        let dir = unique_dir();
        write_four_csvs(&dir, "MA-L,AABBCC,Example Corp,Addr\r\n");
        let output = dir.join("ieee-oui.txt");

        // Act
        let converted = run_update(&UpdateRequest {
            output_path: output.clone(),
            from_dir: Some(dir.clone()),
            retrieved_at_utc: Some("2026-09-17T12:00:00Z".to_string()),
        })
        .expect("offline update");

        // Assert
        let text = fs::read_to_string(&output).expect("read generated file");
        assert_eq!(converted.text, text);
        assert!(text.contains("AABBCC\tExample Corp\n"));
        assert_eq!(converted.counts[0].emitted, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_csv_leaves_existing_output_untouched() {
        // Arrange
        let dir = unique_dir();
        write_four_csvs(&dir, "MA-L,NOTHEX,Broken,Addr\r\n");
        let output = dir.join("ieee-oui.txt");
        fs::write(&output, "keep-me\n").expect("seed existing output");

        // Act
        let outcome = run_update(&UpdateRequest {
            output_path: output.clone(),
            from_dir: Some(dir.clone()),
            retrieved_at_utc: Some("2026-09-17T12:00:00Z".to_string()),
        });

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::Convert(_))),
            "malformed CSV must fail conversion, got: {outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(&output).expect("read existing output"),
            "keep-me\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_csv_in_from_dir_is_read_error_and_does_not_clobber() {
        // Arrange
        let dir = unique_dir();
        write_four_csvs(&dir, "MA-L,AABBCC,Example,Addr\r\n");
        fs::remove_file(dir.join("iab.csv")).expect("remove IAB");
        let output = dir.join("ieee-oui.txt");
        fs::write(&output, "keep-me\n").expect("seed existing output");

        // Act
        let outcome = run_update(&UpdateRequest {
            output_path: output.clone(),
            from_dir: Some(dir.clone()),
            retrieved_at_utc: Some("2026-09-17T12:00:00Z".to_string()),
        });

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::ReadCsv { .. })),
            "missing CSV should be a read error, got: {outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(&output).expect("read existing output"),
            "keep-me\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_failure_after_conversion_leaves_existing_output_untouched() {
        // Arrange
        let dir = unique_dir();
        write_four_csvs(&dir, "MA-L,AABBCC,Example,Addr\r\n");
        let output = dir.join("ieee-oui.txt");
        fs::create_dir(&output).expect("destination is a directory");
        fs::write(output.join("marker"), "keep").expect("marker");

        // Act
        let outcome = run_update(&UpdateRequest {
            output_path: output.clone(),
            from_dir: Some(dir.clone()),
            retrieved_at_utc: Some("2026-09-17T12:00:00Z".to_string()),
        });

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::Write { .. })),
            "directory destination must fail the write, got: {outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(output.join("marker")).expect("marker should survive"),
            "keep"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_summary_reports_counts() {
        // Arrange
        let converted = ConvertedIeeeOui {
            text: "unused".to_string(),
            counts: vec![RegistryCounts {
                registry: IeeeMacRegistry::MaL,
                emitted: 2,
                source_rows: 3,
                duplicates_removed: 1,
            }],
        };
        let mut buffer = Vec::new();

        // Act
        write_summary(&converted, &mut buffer).expect("write summary");

        // Assert
        let summary = String::from_utf8(buffer).expect("utf8 summary");
        assert!(
            summary.contains("2 emitted (3 source rows, 1 duplicates removed)"),
            "summary should report counts, got: {summary}"
        );
    }

    #[test]
    fn non_utf8_csv_is_a_read_error_and_does_not_clobber() {
        // Arrange
        let dir = unique_dir();
        write_four_csvs(&dir, "MA-L,AABBCC,Example,Addr\r\n");
        fs::write(dir.join("oui.csv"), [0xff, 0xfe, 0x00, 0x00]).expect("invalid UTF-8 CSV");
        let output = dir.join("ieee-oui.txt");
        fs::write(&output, "keep-me\n").expect("seed existing output");

        // Act
        let outcome = run_update(&UpdateRequest {
            output_path: output.clone(),
            from_dir: Some(dir.clone()),
            retrieved_at_utc: Some("2026-09-17T12:00:00Z".to_string()),
        });

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::ReadCsv { .. })),
            "invalid UTF-8 must fail before conversion, got: {outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(&output).expect("read existing output"),
            "keep-me\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_summary_surfaces_writer_errors() {
        // Arrange
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken pipe"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let converted = ConvertedIeeeOui {
            text: "unused".to_string(),
            counts: vec![RegistryCounts {
                registry: IeeeMacRegistry::MaL,
                emitted: 1,
                source_rows: 1,
                duplicates_removed: 0,
            }],
        };

        // Act
        let outcome = write_summary(&converted, FailingWriter);

        // Assert
        assert!(
            outcome.is_err(),
            "a broken summary writer must fail, got: {outcome:?}"
        );
    }
}
