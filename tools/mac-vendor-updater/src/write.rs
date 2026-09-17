//! Atomic replacement of `ieee-oui.txt` after the generated text has already been validated.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::process;

use crate::error::UpdaterError;

/// Writes `text` to `output_path` by creating a sibling temp file, syncing it, then renaming.
///
/// # Errors
///
/// Returns [`UpdaterError::Write`] when creating, writing, syncing, or renaming fails. The
/// destination is only replaced after the temp file is fully written and synced.
pub fn replace_file_atomically(output_path: &Path, text: &str) -> Result<(), UpdaterError> {
    let file_name = output_path.file_name().ok_or_else(|| UpdaterError::Write {
        path: output_path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output path must include a file name",
        ),
    })?;
    let directory = match output_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let temp_path = directory.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        process::id()
    ));

    if let Err(source) = write_temp_file(&temp_path, text) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(UpdaterError::Write {
            path: output_path.to_path_buf(),
            source,
        });
    }

    if let Err(source) = std::fs::rename(&temp_path, output_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(UpdaterError::Write {
            path: output_path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

fn write_temp_file(temp_path: &Path, text: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(temp_path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::replace_file_atomically;
    use crate::error::UpdaterError;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let stamp = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mac-vendor-updater-write-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    #[test]
    fn replaces_existing_file_after_successful_write() {
        // Arrange
        let dir = unique_dir();
        let output = dir.join("ieee-oui.txt");
        fs::write(&output, "old\n").expect("seed existing file");

        // Act
        replace_file_atomically(&output, "new\n").expect("atomic replace");

        // Assert
        assert_eq!(fs::read_to_string(&output).expect("read output"), "new\n");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(
            leftovers.len(),
            1,
            "temp file should be renamed away: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn creates_file_when_destination_is_missing() {
        // Arrange
        let dir = unique_dir();
        let output = dir.join("ieee-oui.txt");

        // Act
        replace_file_atomically(&output, "created\n").expect("atomic create");

        // Assert
        assert_eq!(
            fs::read_to_string(&output).expect("read output"),
            "created\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_onto_directory_leaves_the_directory_in_place() {
        // Arrange
        let dir = unique_dir();
        let output = dir.join("ieee-oui.txt");
        fs::create_dir(&output).expect("destination is a directory");
        fs::write(output.join("marker"), "keep").expect("marker inside destination directory");

        // Act
        let outcome = replace_file_atomically(&output, "new\n");

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::Write { .. })),
            "renaming a file onto a directory must fail, got: {outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(output.join("marker")).expect("marker should survive"),
            "keep"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_name_is_a_write_error() {
        // Arrange
        let output = PathBuf::from("/");

        // Act
        let outcome = replace_file_atomically(&output, "new\n");

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::Write { .. })),
            "root path has no file name, got: {outcome:?}"
        );
    }

    #[test]
    fn missing_parent_directory_is_a_write_error() {
        // Arrange
        let dir = unique_dir();
        let output = dir.join("missing-parent").join("ieee-oui.txt");

        // Act
        let outcome = replace_file_atomically(&output, "new\n");

        // Assert
        assert!(
            matches!(outcome, Err(UpdaterError::Write { .. })),
            "atomic replace must not create missing parents, got: {outcome:?}"
        );
        assert!(
            !output.exists(),
            "a failed write must not create the destination"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
