//! CLI for the isolated IEEE MAC registry updater.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use mac_vendor_updater::UpdateRequest;
use mac_vendor_updater::UpdaterError;
use mac_vendor_updater::run_update;
use mac_vendor_updater::write_summary;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("{}", help_text());
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mac-vendor-updater: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), UpdaterError> {
    let request = parse_args(args)?;
    let converted = run_update(&request)?;
    write_summary(&converted, std::io::stderr()).map_err(|source| UpdaterError::Write {
        path: request.output_path,
        source,
    })?;
    Ok(())
}

fn parse_args(args: &[String]) -> Result<UpdateRequest, UpdaterError> {
    let mut output_path = PathBuf::from("ieee-oui.txt");
    let mut from_dir = None;
    let mut retrieved_at_utc = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                output_path = PathBuf::from(require_value(args, index, "--output")?);
                index += 2;
            }
            "--from-dir" => {
                from_dir = Some(PathBuf::from(require_value(args, index, "--from-dir")?));
                index += 2;
            }
            "--retrieved-at" => {
                retrieved_at_utc = Some(require_value(args, index, "--retrieved-at")?.to_string());
                index += 2;
            }
            unknown => {
                return Err(UpdaterError::Usage {
                    message: format!("unknown argument {unknown:?}\n{}", help_text()),
                });
            }
        }
    }
    Ok(UpdateRequest {
        output_path,
        from_dir,
        retrieved_at_utc,
    })
}

fn require_value<'a>(
    args: &'a [String],
    index: usize,
    flag: &str,
) -> Result<&'a str, UpdaterError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| UpdaterError::Usage {
            message: format!("{flag} requires a value"),
        })
}

fn help_text() -> &'static str {
    "\
Usage: mac-vendor-updater [--output PATH] [--from-dir DIR] [--retrieved-at TIMESTAMP]

Downloads IEEE MA-L, MA-M, MA-S, and IAB CSVs with curl, converts them to ieee-oui.txt,
and atomically replaces PATH (default: ./ieee-oui.txt). Scans never fetch these listings.

  --output PATH          Destination mapping file
  --from-dir DIR         Read oui.csv, mam.csv, oui36.csv, and iab.csv from DIR (no network)
  --retrieved-at STAMP   Inject this UTC timestamp into the provenance header
  -h, --help             Show this help"
}

#[cfg(test)]
mod tests {
    use super::{parse_args, run};
    use mac_vendor_updater::UpdaterError;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let stamp = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mac-vendor-updater-cli-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    fn write_four_csvs(dir: &std::path::Path) {
        fs::write(
            dir.join("oui.csv"),
            "Registry,Assignment,Organization Name,Organization Address\r\nMA-L,AABBCC,Example Corp,Addr\r\n",
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
    fn parse_args_defaults_to_cwd_ieee_oui() {
        // Arrange
        let args: [String; 0] = [];

        // Act
        let request = parse_args(&args).expect("defaults");

        // Assert
        assert_eq!(request.output_path, PathBuf::from("ieee-oui.txt"));
        assert_eq!(request.from_dir, None);
        assert_eq!(request.retrieved_at_utc, None);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        // Arrange
        let args = vec!["--cidr".to_string()];

        // Act
        let outcome = parse_args(&args);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::Usage { ref message }) if message.contains("unknown argument")
            ),
            "unknown flags must fail, got: {outcome:?}"
        );
    }

    #[test]
    fn parse_args_records_output_from_dir_and_retrieved_at() {
        // Arrange
        let args = vec![
            "--output".to_string(),
            "/tmp/ieee-oui.txt".to_string(),
            "--from-dir".to_string(),
            "/tmp/ieee-csv".to_string(),
            "--retrieved-at".to_string(),
            "2026-09-17T12:00:00Z".to_string(),
        ];

        // Act
        let request = parse_args(&args).expect("valid flags");

        // Assert
        assert_eq!(request.output_path, PathBuf::from("/tmp/ieee-oui.txt"));
        assert_eq!(request.from_dir, Some(PathBuf::from("/tmp/ieee-csv")));
        assert_eq!(
            request.retrieved_at_utc.as_deref(),
            Some("2026-09-17T12:00:00Z")
        );
    }

    #[test]
    fn parse_args_requires_values() {
        // Arrange
        let args = vec!["--output".to_string()];

        // Act
        let outcome = parse_args(&args);

        // Assert
        assert!(
            matches!(
                outcome,
                Err(UpdaterError::Usage { ref message }) if message == "--output requires a value"
            ),
            "missing values must fail, got: {outcome:?}"
        );
    }

    #[test]
    fn parse_args_requires_from_dir_and_retrieved_at_values() {
        // Arrange
        let from_dir = vec!["--from-dir".to_string()];
        let retrieved_at = vec!["--retrieved-at".to_string()];

        // Act
        let from_dir_outcome = parse_args(&from_dir);
        let retrieved_at_outcome = parse_args(&retrieved_at);

        // Assert
        assert!(
            matches!(
                from_dir_outcome,
                Err(UpdaterError::Usage { ref message }) if message == "--from-dir requires a value"
            ),
            "--from-dir without a value must fail, got: {from_dir_outcome:?}"
        );
        assert!(
            matches!(
                retrieved_at_outcome,
                Err(UpdaterError::Usage { ref message }) if message == "--retrieved-at requires a value"
            ),
            "--retrieved-at without a value must fail, got: {retrieved_at_outcome:?}"
        );
    }

    #[test]
    fn run_from_dir_writes_output() {
        // Arrange
        let dir = unique_dir();
        write_four_csvs(&dir);
        let output = dir.join("out.txt");
        let args = vec![
            "--from-dir".to_string(),
            dir.to_string_lossy().into_owned(),
            "--output".to_string(),
            output.to_string_lossy().into_owned(),
            "--retrieved-at".to_string(),
            "2026-09-17T12:00:00Z".to_string(),
        ];

        // Act
        run(&args).expect("offline CLI run");

        // Assert
        let text = fs::read_to_string(&output).expect("read CLI output");
        assert!(text.contains("AABBCC\tExample Corp\n"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn help_text_names_four_registries() {
        // Arrange
        // Act
        let help = super::help_text();

        // Assert
        assert!(
            help.contains("MA-L")
                && help.contains("MA-M")
                && help.contains("MA-S")
                && help.contains("IAB")
                && help.contains("--from-dir"),
            "help should name the four registries and offline flag, got: {help}"
        );
    }
}
