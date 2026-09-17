//! Typed failures for IEEE CSV conversion, fetch, and atomic writes.

use std::path::PathBuf;

use new_arp_scan::MacVendorRegistryParseError;

use crate::registry::IeeeMacRegistry;

/// Why IEEE registry CSVs could not be converted into `ieee-oui.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertError {
    /// The CSV header row was missing or did not match the official four columns.
    InvalidHeader {
        /// Header fields joined by commas, or a short explanation when headers are missing.
        found: String,
    },
    /// A data row did not have exactly four fields.
    WrongFieldCount {
        /// Registry being converted.
        registry: IeeeMacRegistry,
        /// 1-based CSV line number.
        line_number: u64,
        /// Number of fields observed.
        field_count: usize,
    },
    /// The `Registry` column did not match the file being converted.
    RegistryMismatch {
        /// Registry being converted.
        expected: IeeeMacRegistry,
        /// Value from the `Registry` column.
        found: String,
        /// 1-based CSV line number.
        line_number: u64,
    },
    /// `Assignment` was not exactly the registry's hex width after stripping separators.
    InvalidAssignment {
        /// Registry being converted.
        registry: IeeeMacRegistry,
        /// Trimmed `Assignment` field as it appeared in the CSV (separators not stripped).
        assignment: String,
        /// 1-based CSV line number.
        line_number: u64,
    },
    /// Organization name was empty after trimming outer whitespace.
    EmptyVendor {
        /// Registry being converted.
        registry: IeeeMacRegistry,
        /// Normalized assignment that had no vendor name.
        assignment: String,
        /// 1-based CSV line number.
        line_number: u64,
    },
    /// A registry CSV contained a header but no assignment rows.
    EmptyRegistry {
        /// Registry that had no data rows.
        registry: IeeeMacRegistry,
    },
    /// The `csv` crate rejected the input (quoting, UTF-8, or record shape).
    Csv {
        /// Registry being converted, when known.
        registry: Option<IeeeMacRegistry>,
        /// 1-based CSV line number when the parser reported one.
        line_number: Option<u64>,
        /// Display of the underlying `csv::Error`.
        message: String,
    },
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConvertError::InvalidHeader { found } => {
                write!(
                    formatter,
                    "IEEE CSV header is invalid (expected Registry,Assignment,Organization Name,Organization Address); found {found}"
                )
            }
            ConvertError::WrongFieldCount {
                registry,
                line_number,
                field_count,
            } => write!(
                formatter,
                "{registry} CSV line {line_number} has {field_count} fields; expected 4"
            ),
            ConvertError::RegistryMismatch {
                expected,
                found,
                line_number,
            } => write!(
                formatter,
                "{expected} CSV line {line_number} has Registry `{found}`"
            ),
            ConvertError::InvalidAssignment {
                registry,
                assignment,
                line_number,
            } => write!(
                formatter,
                "{registry} CSV line {line_number} has invalid assignment `{assignment}` (expected {} hexadecimal digits after stripping separators)",
                registry.assignment_hex_digit_count()
            ),
            ConvertError::EmptyVendor {
                registry,
                assignment,
                line_number,
            } => write!(
                formatter,
                "{registry} CSV line {line_number} has empty organization name for assignment `{assignment}`"
            ),
            ConvertError::EmptyRegistry { registry } => {
                write!(formatter, "{registry} CSV contains no assignment rows")
            }
            ConvertError::Csv {
                registry,
                line_number,
                message,
            } => match (registry, line_number) {
                (Some(registry), Some(line_number)) => {
                    write!(formatter, "{registry} CSV line {line_number}: {message}")
                }
                (Some(registry), None) => write!(formatter, "{registry} CSV: {message}"),
                (None, Some(line_number)) => {
                    write!(formatter, "IEEE CSV line {line_number}: {message}")
                }
                (None, None) => write!(formatter, "IEEE CSV: {message}"),
            },
        }
    }
}

impl std::error::Error for ConvertError {}

/// Failures from the updater binary: fetch, conversion, validation, or write.
#[derive(Debug)]
pub enum UpdaterError {
    /// CSV conversion failed; the previous output file must stay untouched.
    Convert(ConvertError),
    /// Generated text was rejected by [`new_arp_scan::MacVendorRegistry`].
    GeneratedTextRejected {
        /// Parser error from the existing `ieee-oui.txt` loader.
        source: MacVendorRegistryParseError,
    },
    /// Reading a `--from-dir` CSV failed.
    ReadCsv {
        /// Path that could not be read as UTF-8 text.
        path: PathBuf,
        /// Underlying I/O or UTF-8 error display.
        message: String,
    },
    /// `curl` was not found on `PATH`.
    CurlMissing,
    /// `curl` ran but did not download the listing.
    CurlFailed {
        /// URL that was requested.
        url: String,
        /// Process exit status, when known.
        status: Option<i32>,
        /// Standard error from `curl`.
        stderr: String,
    },
    /// The `date -u` command used for the provenance timestamp failed.
    RetrievedAtTimestampUnavailable {
        /// Explanation for operators.
        message: String,
    },
    /// Writing or renaming the output file failed. The previous file is left in place when rename
    /// never ran.
    Write {
        /// Intended destination path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A CLI argument was missing or unknown.
    Usage {
        /// Operator-facing usage explanation.
        message: String,
    },
}

impl std::fmt::Display for UpdaterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdaterError::Convert(error) => write!(formatter, "{error}"),
            UpdaterError::GeneratedTextRejected { source } => {
                write!(
                    formatter,
                    "generated ieee-oui.txt was rejected by MacVendorRegistry: {source}"
                )
            }
            UpdaterError::ReadCsv { path, message } => {
                write!(
                    formatter,
                    "failed to read IEEE CSV {}: {message}",
                    path.display()
                )
            }
            UpdaterError::CurlMissing => {
                write!(
                    formatter,
                    "curl was not found on PATH; install curl to fetch IEEE listings"
                )
            }
            UpdaterError::CurlFailed {
                url,
                status,
                stderr,
            } => match status {
                Some(status) => write!(
                    formatter,
                    "curl failed for {url} (exit {status}): {}",
                    stderr.trim()
                ),
                None => write!(formatter, "curl failed for {url}: {}", stderr.trim()),
            },
            UpdaterError::RetrievedAtTimestampUnavailable { message } => {
                write!(
                    formatter,
                    "could not determine UTC retrieval timestamp: {message}"
                )
            }
            UpdaterError::Write { path, source } => {
                write!(formatter, "failed to write {}: {source}", path.display())
            }
            UpdaterError::Usage { message } => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for UpdaterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UpdaterError::Convert(error) => Some(error),
            UpdaterError::GeneratedTextRejected { source } => Some(source),
            UpdaterError::Write { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ConvertError> for UpdaterError {
    fn from(error: ConvertError) -> Self {
        Self::Convert(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{ConvertError, UpdaterError};
    use crate::registry::IeeeMacRegistry;

    #[test]
    fn convert_error_display_names_registry_and_line() {
        // Arrange
        let error = ConvertError::InvalidAssignment {
            registry: IeeeMacRegistry::MaL,
            assignment: "GGHHII".to_string(),
            line_number: 4,
        };

        // Act
        let displayed = error.to_string();

        // Assert
        assert!(
            displayed.contains("MA-L") && displayed.contains('4') && displayed.contains("GGHHII"),
            "display should name registry, line, and assignment, got: {displayed}"
        );
    }

    #[test]
    fn updater_error_display_includes_curl_url() {
        // Arrange
        let error = UpdaterError::CurlFailed {
            url: "https://standards-oui.ieee.org/oui/oui.csv".to_string(),
            status: Some(22),
            stderr: "HTTP 403".to_string(),
        };

        // Act
        let displayed = error.to_string();

        // Assert
        assert!(
            displayed.contains("standards-oui.ieee.org") && displayed.contains("22"),
            "curl failure should name the URL and exit status, got: {displayed}"
        );
    }

    #[test]
    fn convert_error_display_covers_header_vendor_and_csv_variants() {
        // Arrange
        let header = ConvertError::InvalidHeader {
            found: "A,B".to_string(),
        };
        let empty = ConvertError::EmptyRegistry {
            registry: IeeeMacRegistry::MaS,
        };
        let csv = ConvertError::Csv {
            registry: Some(IeeeMacRegistry::Iab),
            line_number: Some(3),
            message: "quote".to_string(),
        };

        // Act
        // Assert
        assert!(header.to_string().contains("IEEE CSV header is invalid"));
        assert!(empty.to_string().contains("MA-S"));
        let csv_display = csv.to_string();
        assert!(
            csv_display.contains("IAB") && csv_display.contains('3'),
            "CSV errors should name registry and line, got: {csv_display}"
        );
    }

    #[test]
    fn curl_missing_and_usage_display_are_operator_facing() {
        // Arrange
        let missing = UpdaterError::CurlMissing;
        let usage = UpdaterError::Usage {
            message: "--output requires a value".to_string(),
        };

        // Act
        // Assert
        assert!(missing.to_string().contains("curl was not found"));
        assert_eq!(usage.to_string(), "--output requires a value");
    }

    #[test]
    fn remaining_updater_error_displays_name_paths_and_causes() {
        // Arrange
        use std::error::Error;

        let convert = UpdaterError::Convert(ConvertError::EmptyVendor {
            registry: IeeeMacRegistry::MaM,
            assignment: "F4A4750".to_string(),
            line_number: 9,
        });
        let rejected = UpdaterError::GeneratedTextRejected {
            source: new_arp_scan::MacVendorRegistryParseError::LineMissingTab { line_number: 4 },
        };
        let read = UpdaterError::ReadCsv {
            path: std::path::PathBuf::from("iab.csv"),
            message: "No such file or directory".to_string(),
        };
        let timestamp = UpdaterError::RetrievedAtTimestampUnavailable {
            message: "date printed an empty timestamp".to_string(),
        };
        let write = UpdaterError::Write {
            path: std::path::PathBuf::from("ieee-oui.txt"),
            source: std::io::Error::other("disk full"),
        };
        let curl_no_status = UpdaterError::CurlFailed {
            url: "https://standards-oui.ieee.org/iab/iab.csv".to_string(),
            status: None,
            stderr: "spawn failed".to_string(),
        };
        let csv_no_line = ConvertError::Csv {
            registry: Some(IeeeMacRegistry::MaL),
            line_number: None,
            message: "utf-8".to_string(),
        };
        let csv_bare = ConvertError::Csv {
            registry: None,
            line_number: None,
            message: "empty".to_string(),
        };
        let csv_line_only = ConvertError::Csv {
            registry: None,
            line_number: Some(8),
            message: "quote".to_string(),
        };
        let fields = ConvertError::WrongFieldCount {
            registry: IeeeMacRegistry::Iab,
            line_number: 3,
            field_count: 2,
        };

        // Act
        // Assert
        assert!(convert.to_string().contains("MA-M") && convert.source().is_some());
        assert!(rejected.to_string().contains("MacVendorRegistry"));
        assert!(read.to_string().contains("iab.csv"));
        assert!(timestamp.to_string().contains("UTC retrieval timestamp"));
        assert!(write.to_string().contains("ieee-oui.txt"));
        assert!(curl_no_status.to_string().contains("iab.csv"));
        assert!(csv_no_line.to_string().contains("MA-L CSV:"));
        assert!(csv_bare.to_string().contains("IEEE CSV:"));
        assert!(csv_line_only.to_string().contains("line 8"));
        assert!(fields.to_string().contains("IAB") && fields.to_string().contains("2 fields"));
        let mismatch = ConvertError::RegistryMismatch {
            expected: IeeeMacRegistry::MaL,
            found: "MA-M".to_string(),
            line_number: 2,
        };
        let mismatch_display = mismatch.to_string();
        assert!(
            mismatch_display.contains("MA-L")
                && mismatch_display.contains("MA-M")
                && mismatch_display.contains("line 2"),
            "registry mismatch should name expected, found, and line, got: {mismatch_display}"
        );
        assert!(write.source().is_some());
        assert!(rejected.source().is_some());
    }
}
