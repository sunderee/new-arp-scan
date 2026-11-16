//! Integration tests for standard streams that reject writes (a closed pipe, `EPIPE`).
//!
//! Each child gets the write end of a pipe whose read end is already closed, so the first flush
//! fails without any timing dependence.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::PipeWriter;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

/// Exit status of a Rust process that panicked. A rejected write must never produce it.
const PANIC_EXIT_CODE: i32 = 101;

fn new_arp_scan_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_new-arp-scan"))
}

/// Returns the write end of a pipe whose read end is already closed.
fn closed_pipe_writer() -> std::io::Result<PipeWriter> {
    let (reader, writer) = std::io::pipe()?;
    drop(reader);
    Ok(writer)
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_with_closed_standard_output_exits_with_failure_and_does_not_panic() {
    // Arrange
    let mut command = new_arp_scan_command();
    command
        .stdout(closed_pipe_writer().expect("closed standard output pipe"))
        .stderr(Stdio::piped());

    // Act
    let output = command
        .output()
        .expect("spawning the binary without arguments should succeed");

    // Assert
    let stderr = stderr_text(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "help that cannot be written is an operational failure, stderr: {stderr}"
    );
    assert!(
        stderr.contains("failed to print help"),
        "stderr should name the rejected help write, got: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "a closed standard output must not panic, got: {stderr}"
    );
}

#[test]
fn interfaces_with_closed_standard_output_exits_with_failure_and_does_not_panic() {
    // Arrange
    let mut command = new_arp_scan_command();
    command
        .arg("interfaces")
        .stdout(closed_pipe_writer().expect("closed standard output pipe"))
        .stderr(Stdio::piped());

    // Act
    let output = command
        .output()
        .expect("spawning the interfaces subcommand should succeed");

    // Assert
    let stderr = stderr_text(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a listing that cannot be written is an operational failure, stderr: {stderr}"
    );
    assert!(
        stderr.contains("failed to write operator output"),
        "stderr should name the rejected operator output, got: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "a closed standard output must not panic, got: {stderr}"
    );
}

#[test]
fn help_with_both_standard_streams_closed_still_exits_with_failure_code() {
    // Arrange
    let mut command = new_arp_scan_command();
    command
        .stdout(closed_pipe_writer().expect("closed standard output pipe"))
        .stderr(closed_pipe_writer().expect("closed standard error pipe"));

    // Act
    let status = command
        .status()
        .expect("spawning the binary without arguments should succeed");

    // Assert
    assert_ne!(
        status.code(),
        Some(PANIC_EXIT_CODE),
        "an unreportable failure must not panic"
    );
    assert_eq!(
        status.code(),
        Some(1),
        "the failure report is best-effort; the exit status must still be 1"
    );
}

#[test]
fn interfaces_with_both_standard_streams_closed_still_exits_with_failure_code() {
    // Arrange
    let mut command = new_arp_scan_command();
    command
        .arg("interfaces")
        .stdout(closed_pipe_writer().expect("closed standard output pipe"))
        .stderr(closed_pipe_writer().expect("closed standard error pipe"));

    // Act
    let status = command
        .status()
        .expect("spawning the interfaces subcommand should succeed");

    // Assert
    assert_eq!(
        status.code(),
        Some(1),
        "the failure report is best-effort; the exit status must still be 1"
    );
}

#[test]
fn help_with_open_standard_output_still_exits_successfully() {
    // Arrange
    let mut command = new_arp_scan_command();

    // Act
    let output = command
        .output()
        .expect("spawning the binary without arguments should succeed");

    // Assert
    assert_eq!(
        output.status.code(),
        Some(0),
        "help on a writable standard output keeps exit status 0, stderr: {}",
        stderr_text(&output)
    );
    assert_eq!(
        stderr_text(&output),
        "",
        "successful help writes nothing to standard error"
    );
}
