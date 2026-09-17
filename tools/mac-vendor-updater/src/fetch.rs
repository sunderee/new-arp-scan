//! Fetch IEEE CSVs with system `curl` and capture a UTC timestamp with `date`.

use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use std::process::Output;

use crate::error::UpdaterError;
use crate::registry::IeeeMacRegistry;

const CURL_USER_AGENT: &str =
    "new-arp-scan-mac-vendor-updater/0.2 (+https://github.com/Bizjak-Tech-OU/new-arp-scan)";

/// Downloads the four official IEEE CSV files into `destination_dir`.
///
/// # Errors
///
/// Returns [`UpdaterError::CurlMissing`] when `curl` is not on `PATH`,
/// [`UpdaterError::CurlFailed`] when a download fails, and [`UpdaterError::Write`] when the
/// destination directory cannot be created.
pub fn fetch_official_csvs(destination_dir: &Path) -> Result<(), UpdaterError> {
    fetch_official_csvs_with_curl(destination_dir, Path::new("curl"))
}

/// Returns a UTC timestamp from `date -u +%Y-%m-%dT%H:%M:%SZ`.
///
/// # Errors
///
/// Returns [`UpdaterError::RetrievedAtTimestampUnavailable`] when `date` is missing or does not
/// print a timestamp.
pub fn utc_timestamp_from_date() -> Result<String, UpdaterError> {
    utc_timestamp_from_program(Path::new("date"), ["-u", "+%Y-%m-%dT%H:%M:%SZ"])
}

pub(crate) fn fetch_official_csvs_with_curl(
    destination_dir: &Path,
    curl_program: &Path,
) -> Result<(), UpdaterError> {
    std::fs::create_dir_all(destination_dir).map_err(|source| UpdaterError::Write {
        path: destination_dir.to_path_buf(),
        source,
    })?;
    for registry in IeeeMacRegistry::ALL {
        let output_path = destination_dir.join(registry.csv_file_name());
        run_curl(curl_program, registry.csv_url(), &output_path)?;
    }
    Ok(())
}

pub(crate) fn utc_timestamp_from_program<I, S>(
    program: &Path,
    args: I,
) -> Result<String, UpdaterError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_command(program, args, CommandKind::Date)?;
    let timestamp = String::from_utf8(output.stdout).map_err(|error| {
        UpdaterError::RetrievedAtTimestampUnavailable {
            message: error.to_string(),
        }
    })?;
    let timestamp = timestamp.trim();
    if timestamp.is_empty() {
        return Err(UpdaterError::RetrievedAtTimestampUnavailable {
            message: "date printed an empty timestamp".to_string(),
        });
    }
    Ok(timestamp.to_string())
}

fn run_curl(curl_program: &Path, url: &str, output_path: &Path) -> Result<(), UpdaterError> {
    let output_display = output_path.display().to_string();
    run_command(
        curl_program,
        [
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--user-agent",
            CURL_USER_AGENT,
            "--output",
            output_display.as_str(),
            url,
        ],
        CommandKind::Curl { url },
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
enum CommandKind<'a> {
    Curl { url: &'a str },
    Date,
}

fn run_command<I, S>(program: &Path, args: I, kind: CommandKind<'_>) -> Result<Output, UpdaterError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(args);
    let output = command.output().map_err(|error| match kind {
        CommandKind::Curl { .. } if error.kind() == ErrorKind::NotFound => {
            UpdaterError::CurlMissing
        }
        CommandKind::Curl { url } => UpdaterError::CurlFailed {
            url: url.to_string(),
            status: None,
            stderr: error.to_string(),
        },
        CommandKind::Date => UpdaterError::RetrievedAtTimestampUnavailable {
            message: error.to_string(),
        },
    })?;
    if output.status.success() {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    match kind {
        CommandKind::Curl { url } => Err(UpdaterError::CurlFailed {
            url: url.to_string(),
            status: output.status.code(),
            stderr: stderr.into_owned(),
        }),
        CommandKind::Date => Err(UpdaterError::RetrievedAtTimestampUnavailable {
            message: format!("exit status {}; stderr: {}", output.status, stderr.trim()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CURL_USER_AGENT, fetch_official_csvs_with_curl, utc_timestamp_from_date,
        utc_timestamp_from_program,
    };
    use crate::error::UpdaterError;
    use crate::registry::IeeeMacRegistry;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let stamp = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mac-vendor-updater-fetch-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body).expect("write fake program");
        let mut permissions = fs::metadata(path)
            .expect("metadata for fake program")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod fake program");
    }

    #[test]
    fn missing_curl_program_is_curl_missing() {
        // Arrange
        let dir = unique_dir();

        // Act
        let outcome = fetch_official_csvs_with_curl(
            &dir.join("csv"),
            Path::new("/no/such/new-arp-scan-curl"),
        );

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::CurlMissing)),
            "missing curl must be CurlMissing, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn fake_curl_nonzero_exit_is_curl_failed() {
        // Arrange
        let dir = unique_dir();
        let curl = dir.join("curl");
        write_executable(&curl, "#!/bin/sh\necho denied >&2\nexit 22\n");

        // Act
        let outcome = fetch_official_csvs_with_curl(&dir.join("csv"), &curl);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::CurlFailed {
                    status: Some(22),
                    ..
                })
            ),
            "fake curl exit 22 must not contact IEEE, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn fake_curl_writes_each_registry_file_without_network() {
        // Arrange
        let dir = unique_dir();
        let data = dir.join("data");
        fs::create_dir_all(&data).expect("data dir");
        for registry in IeeeMacRegistry::ALL {
            fs::write(
                data.join(registry.csv_file_name()),
                format!("fixture-{}", registry.csv_file_name()),
            )
            .expect("sidecar CSV");
        }
        let curl = dir.join("curl");
        write_executable(
            &curl,
            &format!(
                "#!/bin/sh\n\
echo \"$@\" > \"{}/curl-args.txt\"\n\
out=\"\"\n\
prev=\"\"\n\
for arg in \"$@\"; do\n\
  if [ \"$prev\" = \"--output\" ]; then out=\"$arg\"; fi\n\
  prev=\"$arg\"\n\
done\n\
cp \"{}\"/\"$(basename \"$out\")\" \"$out\"\n",
                dir.display(),
                data.display()
            ),
        );
        let dest = dir.join("csv");

        // Act
        fetch_official_csvs_with_curl(&dest, &curl).expect("fake curl should copy sidecars");

        // Assert
        let args = fs::read_to_string(dir.join("curl-args.txt")).expect("curl argv log");
        assert!(
            args.contains("--fail")
                && args.contains("--proto")
                && args.contains("=https")
                && args.contains("--user-agent")
                && args.contains("new-arp-scan-mac-vendor-updater"),
            "curl must be invoked with HTTPS-only flags and this updater's user agent, got: {args:?}"
        );
        for registry in IeeeMacRegistry::ALL {
            let written =
                fs::read_to_string(dest.join(registry.csv_file_name())).expect("read fetched CSV");
            assert_eq!(written, format!("fixture-{}", registry.csv_file_name()));
        }
        assert!(
            CURL_USER_AGENT.contains("new-arp-scan-mac-vendor-updater"),
            "user agent should identify this updater"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn non_executable_curl_is_curl_failed_not_missing() {
        // Arrange
        let dir = unique_dir();
        let curl = dir.join("curl");
        fs::write(&curl, "#!/bin/sh\nexit 0\n").expect("write non-executable curl");

        // Act
        let outcome = fetch_official_csvs_with_curl(&dir.join("csv"), &curl);

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::CurlFailed { status: None, .. })),
            "an unusable curl binary must not be reported as missing, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_destination_that_is_a_file_is_a_write_error() {
        // Arrange
        let dir = unique_dir();
        let dest = dir.join("csv");
        fs::write(&dest, "not-a-directory").expect("seed file where a directory is required");

        // Act
        let outcome = fetch_official_csvs_with_curl(&dest, Path::new("/no/such/new-arp-scan-curl"));

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::Write { .. })),
            "create_dir_all over a file must fail before curl, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn date_nonzero_exit_is_timestamp_unavailable() {
        // Arrange
        let dir = unique_dir();
        let date = dir.join("date");
        write_executable(&date, "#!/bin/sh\necho date failed >&2\nexit 1\n");

        // Act
        let outcome = utc_timestamp_from_program(&date, ["-u"]);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::RetrievedAtTimestampUnavailable { .. })
            ),
            "date exit 1 must fail closed, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn date_trims_surrounding_whitespace() {
        // Arrange
        let dir = unique_dir();
        let date = dir.join("date");
        write_executable(&date, "#!/bin/sh\nprintf '  2026-09-17T12:00:00Z \\n'\n");

        // Act
        let timestamp = utc_timestamp_from_program(&date, ["-u"]).expect("trimmed timestamp");

        // Assert
        assert_eq!(timestamp, "2026-09-17T12:00:00Z");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn system_date_minus_u_produces_a_utc_iso8601_timestamp() {
        // Arrange
        // Production `make update-mac-vendors` invokes `/bin/date` (BSD on macOS, GNU on Linux)
        // with `-u +%Y-%m-%dT%H:%M:%SZ`. Fake date scripts cannot catch a format incompatibility.

        // Act
        let timestamp = utc_timestamp_from_date()
            .expect("updater hosts need date -u +%Y-%m-%dT%H:%M:%SZ on PATH");

        // Assert
        let bytes = timestamp.as_bytes();
        assert_eq!(
            bytes.len(),
            20,
            "expected YYYY-MM-DDTHH:MM:SSZ from date -u, got {timestamp:?}"
        );
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b'T');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        assert_eq!(bytes[19], b'Z');
        assert!(
            timestamp.bytes().all(|octet| octet.is_ascii()),
            "timestamp must be ASCII, got {timestamp:?}"
        );
        for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
            assert!(
                bytes[index].is_ascii_digit(),
                "expected a digit at index {index} in {timestamp:?}"
            );
        }
    }

    #[test]
    fn missing_date_program_is_timestamp_unavailable() {
        // Arrange
        // Act
        let outcome = utc_timestamp_from_program(
            Path::new("/no/such/new-arp-scan-date"),
            ["-u", "+%Y-%m-%dT%H:%M:%SZ"],
        );

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::RetrievedAtTimestampUnavailable { .. })
            ),
            "missing date must fail closed, got: {outcome:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_date_output_is_timestamp_unavailable() {
        // Arrange
        let dir = unique_dir();
        let date = dir.join("date");
        write_executable(&date, "#!/bin/sh\nexit 0\n");

        // Act
        let outcome = utc_timestamp_from_program(&date, ["-u"]);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::RetrievedAtTimestampUnavailable { .. })
            ),
            "empty date stdout must fail, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_date_output_is_timestamp_unavailable() {
        // Arrange
        let dir = unique_dir();
        let payload = dir.join("invalid-utf8");
        fs::write(&payload, [0xff, 0xfe]).expect("write invalid UTF-8 payload");
        let date = dir.join("date");
        write_executable(&date, &format!("#!/bin/sh\ncat '{}'\n", payload.display()));

        // Act
        let outcome = utc_timestamp_from_program(&date, ["-u"]);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::RetrievedAtTimestampUnavailable { .. })
            ),
            "invalid UTF-8 from date must fail closed, got: {outcome:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
