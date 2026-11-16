//! Validates Linux network interface names before issuing syscalls.

#![allow(
    unsafe_code,
    reason = "libc FFI for interface-name ioctl buffers; see DECISIONS.md 2026-11-15"
)]

use crate::error::AppError;

/// Matches Linux `IFNAMSIZ` from `linux/if.h`.
pub const INTERFACE_NAME_BUFFER_SIZE: usize = 16;

/// Maximum number of non-null bytes in an interface name (excluding the terminator).
pub const INTERFACE_NAME_MAXIMUM_BYTES: usize = INTERFACE_NAME_BUFFER_SIZE - 1;

/// Returns [`AppError::InvalidInterfaceName`] when `interface_name` cannot be used with Linux
/// packet socket APIs.
///
/// # Errors
///
/// Returns [`AppError::InvalidInterfaceName`] when the name is empty, too long, contains a
/// slash, or contains an interior NUL byte.
pub fn validate_interface_name_for_linux_packet_socket(
    interface_name: &str,
) -> Result<(), AppError> {
    if interface_name.is_empty() {
        return Err(AppError::InvalidInterfaceName {
            message: "interface name must not be empty".to_string(),
        });
    }

    if interface_name.len() > INTERFACE_NAME_MAXIMUM_BYTES {
        return Err(AppError::InvalidInterfaceName {
            message: format!(
                "interface name must be at most {INTERFACE_NAME_MAXIMUM_BYTES} bytes, got {}",
                interface_name.len()
            ),
        });
    }

    if interface_name.contains('/') {
        return Err(AppError::InvalidInterfaceName {
            message: "interface name must not contain '/'".to_string(),
        });
    }

    if interface_name.as_bytes().contains(&0) {
        return Err(AppError::InvalidInterfaceName {
            message: "interface name must not contain a NUL byte".to_string(),
        });
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Copies `interface_name` into [`libc::ifreq::ifr_name`] for `ioctl(2)` requests.
///
/// Callers must invoke [`validate_interface_name_for_linux_packet_socket`] first when the name
/// comes from untrusted input.
///
/// # Errors
///
/// Returns [`AppError::InvalidInterfaceName`] when the name is too long for `IFNAMSIZ`.
///
/// # Panics
///
/// This function does not panic.
pub(crate) fn copy_interface_name_to_ifreq(
    interface_name: &str,
    request: &mut libc::ifreq,
) -> Result<(), AppError> {
    let bytes = interface_name.as_bytes();
    if bytes.len() >= INTERFACE_NAME_BUFFER_SIZE {
        return Err(AppError::InvalidInterfaceName {
            message: format!(
                "interface name must be shorter than {INTERFACE_NAME_BUFFER_SIZE} bytes"
            ),
        });
    }

    request.ifr_name = [0; INTERFACE_NAME_BUFFER_SIZE];
    unsafe {
        // SAFETY: `bytes.len()` is strictly less than `INTERFACE_NAME_BUFFER_SIZE`, so the copy
        // fits inside `ifr_name`. Viewing the destination as bytes preserves the kernel ABI layout
        // whether `libc` exposes the field as signed or unsigned characters.
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            request.ifr_name.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::INTERFACE_NAME_MAXIMUM_BYTES;
    use super::validate_interface_name_for_linux_packet_socket;
    use crate::error::AppError;

    #[test]
    fn returns_error_when_interface_name_is_empty() {
        // Arrange
        let interface_name = "";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "empty name should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_name_exceeds_maximum_length() {
        // Arrange
        let interface_name = "a".repeat(INTERFACE_NAME_MAXIMUM_BYTES + 1);

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(&interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "oversized name should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_name_contains_slash() {
        // Arrange
        let interface_name = "eth0/1";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "slash should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn returns_error_when_interface_name_contains_nul_byte() {
        // Arrange
        let interface_name = "eth\0";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "NUL should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn accepts_valid_interface_name() {
        // Arrange
        let interface_name = "eth0";

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(interface_name);

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "valid interface name should be accepted, got: {outcome:?}"
        );
    }

    #[test]
    fn accepts_interface_name_at_maximum_byte_length() {
        // Arrange
        let interface_name = "a".repeat(INTERFACE_NAME_MAXIMUM_BYTES);

        // Act
        let outcome = validate_interface_name_for_linux_packet_socket(&interface_name);

        // Assert
        assert!(
            matches!(outcome, Ok(())),
            "IFNAMSIZ-1 byte names are valid on Linux, got: {outcome:?}"
        );
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod copy_interface_name_to_ifreq_linux_tests {
    use super::INTERFACE_NAME_BUFFER_SIZE;
    use super::copy_interface_name_to_ifreq;
    use crate::error::AppError;
    use std::mem::zeroed;

    #[test]
    fn returns_error_when_byte_length_reaches_ifreq_name_buffer_size() {
        // Arrange
        let mut request: libc::ifreq = unsafe { zeroed() };
        let interface_name = "a".repeat(INTERFACE_NAME_BUFFER_SIZE);

        // Act
        let outcome = copy_interface_name_to_ifreq(&interface_name, &mut request);

        // Assert
        assert!(
            matches!(outcome, Err(AppError::InvalidInterfaceName { .. })),
            "names that cannot fit with a trailing NUL in ifr_name should be rejected, got: {outcome:?}"
        );
    }

    #[test]
    fn copies_short_name_into_leading_bytes_of_ifr_name() {
        // Arrange
        let mut request: libc::ifreq = unsafe { zeroed() };

        // Act
        copy_interface_name_to_ifreq("ab", &mut request)
            .expect("two-byte name should copy into ifreq");

        // Assert
        let request_name_bytes = unsafe {
            // SAFETY: `ifr_name` is a fixed-size byte buffer in the Linux `ifreq` ABI.
            std::slice::from_raw_parts(
                request.ifr_name.as_ptr().cast::<u8>(),
                request.ifr_name.len(),
            )
        };
        assert_eq!(request_name_bytes[0], b'a');
        assert_eq!(request_name_bytes[1], b'b');
        assert_eq!(
            request_name_bytes[2], 0,
            "copy should not write past the final interface name byte; remainder stays zero-filled"
        );
    }
}
