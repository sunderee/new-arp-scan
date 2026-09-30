//! Application-wide error types.

/// Represents failures surfaced by the library and binary.
#[derive(Debug)]
pub enum AppError {
    /// An underlying input/output operation failed.
    Io(std::io::Error),
    /// The host operating system does not support Linux packet sockets.
    UnsupportedPlatform {
        /// Value of `std::env::consts::OS` for the current process.
        operating_system: String,
    },
    /// The interface name violates basic Linux naming rules.
    InvalidInterfaceName {
        /// Human-readable explanation for operators.
        message: String,
    },
    /// The kernel could not resolve the interface name to an interface index.
    InterfaceLookupFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Reading interface flags through `ioctl` failed.
    InterfaceFlagsQueryFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// The interface is not suitable for ARP scanning with a raw packet socket.
    InterfaceRejectedForScanning {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Human-readable reason (for example loopback, administratively down, or `NOARP`).
        reason: String,
    },
    /// Creating the raw `AF_PACKET` socket failed.
    RawSocketOpenFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Opening a raw packet socket was denied because the process lacks `CAP_NET_RAW`.
    RawSocketCapabilityRequired {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Opening a macOS Berkeley Packet Filter device was denied for lack of privilege.
    BpfDeviceAccessRequired {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Binding the raw `AF_PACKET` socket to the interface failed.
    SocketBindFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Reading the interface IPv4 address through `ioctl` failed.
    InterfaceIpv4AddressQueryFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Reading the interface IPv4 netmask through `ioctl` failed.
    InterfaceIpv4NetmaskQueryFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Reading the interface hardware address through `ioctl` failed.
    InterfaceHardwareAddressQueryFailed {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// The interface hardware address is not Ethernet or is otherwise unsupported.
    InterfaceHardwareAddressUnsupported {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Human-readable explanation for operators.
        reason: String,
    },
    /// The socket address family for an interface IPv4 address was not `AF_INET`.
    InterfaceIpv4AddressInvalidFamily {
        /// Address family value returned by the kernel.
        address_family: libc::sa_family_t,
    },
    /// The socket address family for an interface IPv4 netmask was not `AF_INET`.
    InterfaceIpv4NetmaskInvalidFamily {
        /// Interface name supplied by the caller.
        interface_name: String,
        /// Address family value returned by the kernel.
        address_family: libc::sa_family_t,
    },
    /// The IPv4 netmask is not a valid contiguous classless inter-domain routing mask.
    Ipv4NetmaskInvalid {
        /// Netmask that was rejected.
        netmask: String,
    },
    /// The IPv4 subnet cannot be scanned with the current rules (for example `/31` or `/32`).
    Ipv4SubnetUnsupported {
        /// Human-readable explanation for operators.
        message: String,
    },
    /// The IPv4 classless inter-domain routing string could not be parsed.
    Ipv4CidrStringInvalid {
        /// Original input supplied by the caller (trimmed of leading and trailing ASCII whitespace only).
        source: String,
        /// Human-readable explanation for operators.
        message: String,
    },
    /// Waiting for packet socket readiness with `poll(2)` failed.
    PollWaitFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Receiving a raw Ethernet frame failed.
    RawPacketReceiveFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Enumerating local interfaces with `if_nameindex(3)` failed.
    InterfaceEnumerationFailed {
        /// Underlying operating system error (typically `errno`).
        source: std::io::Error,
    },
    /// Automatic interface selection found no usable interface.
    AutomaticInterfaceSelectionNoneFound,
    /// Automatic interface selection found more than one usable interface.
    AutomaticInterfaceSelectionAmbiguous {
        /// Names of interfaces that were all considered usable.
        interface_names: Vec<String>,
    },
    /// The IPv4 address supplied for single-target scanning is not allowed on the interface subnet.
    SingleScanTargetRejected {
        /// Target address that was rejected.
        target_ipv4_address: std::net::Ipv4Addr,
        /// Interface name used for discovery context.
        interface_name: String,
        /// Human-readable explanation for operators.
        reason: String,
    },
    /// Custom `--padding` (plus ARP and optional LLC/SNAP) exceeds the IEEE 802.3 1500-octet MAC
    /// client data maximum.
    Ieee8023MacClientDataExceedsMaximum {
        /// Combined LLC/SNAP (when used), ARP PDU, and custom padding length.
        octet_count: usize,
        /// IEEE 802.3 maximum MAC client data length (1500).
        maximum: u16,
    },
    /// An IEEE 802.1Q service tag (`--svlan`) was requested without the customer tag (`--vlan`)
    /// that IEEE 802.1ad provider bridging requires it to wrap.
    ServiceVlanTagRequiresCustomerVlanTag {
        /// Service VLAN identifier that had no customer tag to wrap.
        service_vlan_identifier: u16,
    },
    /// `--bandwidth` was zero. Suffix overflow is rejected by the command-line parser before this
    /// variant is constructed.
    InterTargetBandwidthRejected,
    /// An explicit inter-target interval was zero.
    InterTargetIntervalRejected,
    /// A retry backoff factor was non-finite or less than one.
    RetryBackoffFactorRejected,
    /// A checked scan duration or monotonic deadline does not fit in its representation.
    ScanTimingExceedsLimit {
        /// Which computed span overflowed.
        limit: ScanTimingLimit,
    },
    /// A passive monitor listen window was zero. The monitor does not treat zero as an immediate
    /// return the way a scan receive timeout can.
    MonitorTimeoutRejected,
}

/// A scan-timing span that could not be represented without overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanTimingLimit {
    /// The interval derived from `--bandwidth` and the on-wire frame size does not fit in
    /// [`std::time::Duration`].
    BandwidthInterval,
    /// The strict inter-send interval plus inter-round `--pacing-ms` does not fit in
    /// [`std::time::Duration`].
    InterRoundGap,
    /// `timeout * backoff^round` for a planned retry round does not fit in [`std::time::Duration`].
    RetryReceiveWindow,
    /// Adding a duration to the monotonic clock would overflow [`std::time::Instant`] or the test
    /// clock.
    MonotonicDeadline,
}

fn try_write_early_app_error_variants(
    application_error: &AppError,
    formatter: &mut std::fmt::Formatter<'_>,
) -> Option<std::fmt::Result> {
    Some(match application_error {
        AppError::Io(error) => write!(formatter, "input/output error: {error}"),
        AppError::UnsupportedPlatform { operating_system } => write!(
            formatter,
            "this command requires Linux packet sockets; host operating system is {operating_system}"
        ),
        AppError::InvalidInterfaceName { message } => {
            write!(formatter, "invalid interface name: {message}")
        }
        AppError::InterfaceLookupFailed {
            interface_name,
            source,
        } => write!(
            formatter,
            "failed to look up interface index for `{interface_name}`: {source}"
        ),
        AppError::InterfaceFlagsQueryFailed {
            interface_name,
            source,
        } => write!(
            formatter,
            "failed to read interface flags for `{interface_name}`: {source}"
        ),
        AppError::InterfaceRejectedForScanning {
            interface_name,
            reason,
        } => write!(
            formatter,
            "interface `{interface_name}` is not suitable for ARP scanning: {reason}"
        ),
        AppError::RawSocketOpenFailed { source } => {
            write!(formatter, "failed to open raw packet socket: {source}")
        }
        AppError::RawSocketCapabilityRequired { source } => write!(
            formatter,
            "opening a raw packet socket requires the Linux capability CAP_NET_RAW (or equivalent privileges); permission denied: {source}"
        ),
        AppError::BpfDeviceAccessRequired { source } => write!(
            formatter,
            "opening a Berkeley Packet Filter device requires root or BPF access (try running with sudo); permission denied: {source}"
        ),
        AppError::SocketBindFailed { source } => {
            write!(formatter, "failed to bind raw packet socket: {source}")
        }
        AppError::InterfaceEnumerationFailed { source } => write!(
            formatter,
            "failed to enumerate network interfaces: {source}"
        ),
        AppError::AutomaticInterfaceSelectionNoneFound => write!(
            formatter,
            "no usable network interface was found for automatic selection; specify one explicitly with --interface <NAME>"
        ),
        AppError::AutomaticInterfaceSelectionAmbiguous { interface_names } => write!(
            formatter,
            "multiple usable network interfaces were found for automatic selection: {}; specify one explicitly with --interface <NAME>",
            interface_names.join(", ")
        ),
        _ => return None,
    })
}

fn write_rate_limit_app_error(
    application_error: &AppError,
    formatter: &mut std::fmt::Formatter<'_>,
) -> Option<std::fmt::Result> {
    Some(match application_error {
        AppError::InterTargetBandwidthRejected => {
            write!(
                formatter,
                "inter-target bandwidth must be greater than zero"
            )
        }
        AppError::InterTargetIntervalRejected => {
            write!(formatter, "inter-target interval must be greater than zero")
        }
        AppError::RetryBackoffFactorRejected => write!(
            formatter,
            "retry backoff factor must be finite and at least 1"
        ),
        AppError::ScanTimingExceedsLimit { limit } => {
            write!(formatter, "{}", scan_timing_limit_display_message(*limit))
        }
        _ => return None,
    })
}

fn write_late_app_error_variants(
    application_error: &AppError,
    formatter: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    if let Some(result) = write_rate_limit_app_error(application_error, formatter) {
        return result;
    }
    match application_error {
        AppError::InterfaceIpv4AddressQueryFailed {
            interface_name,
            source,
        } => write!(
            formatter,
            "failed to read IPv4 address for `{interface_name}`: {source}"
        ),
        AppError::InterfaceIpv4NetmaskQueryFailed {
            interface_name,
            source,
        } => write!(
            formatter,
            "failed to read IPv4 netmask for `{interface_name}`: {source}"
        ),
        AppError::InterfaceHardwareAddressQueryFailed {
            interface_name,
            source,
        } => write!(
            formatter,
            "failed to read hardware address for `{interface_name}`: {source}"
        ),
        AppError::InterfaceHardwareAddressUnsupported {
            interface_name,
            reason,
        } => write!(
            formatter,
            "hardware address for `{interface_name}` is not supported for ARP scanning: {reason}"
        ),
        AppError::InterfaceIpv4AddressInvalidFamily { address_family } => write!(
            formatter,
            "interface IPv4 address query returned an unexpected address family: {address_family}"
        ),
        AppError::InterfaceIpv4NetmaskInvalidFamily {
            interface_name,
            address_family,
        } => write!(
            formatter,
            "interface IPv4 netmask query for `{interface_name}` returned an unexpected address family: {address_family}"
        ),
        AppError::Ipv4NetmaskInvalid { netmask } => {
            write!(
                formatter,
                "IPv4 netmask `{netmask}` is not a valid contiguous netmask"
            )
        }
        AppError::Ipv4SubnetUnsupported { message } => {
            write!(
                formatter,
                "IPv4 subnet is not supported for scanning: {message}"
            )
        }
        AppError::Ipv4CidrStringInvalid { source, message } => write!(
            formatter,
            "invalid IPv4 classless inter-domain routing notation `{source}`: {message}"
        ),
        AppError::PollWaitFailed { source } => {
            write!(
                formatter,
                "failed while waiting for raw packet socket readiness: {source}"
            )
        }
        AppError::RawPacketReceiveFailed { source } => {
            write!(formatter, "failed to receive raw Ethernet frame: {source}")
        }
        AppError::SingleScanTargetRejected {
            target_ipv4_address,
            interface_name,
            reason,
        } => write!(
            formatter,
            "single-target scan rejected {target_ipv4_address} on interface `{interface_name}`: {reason}"
        ),
        AppError::Ieee8023MacClientDataExceedsMaximum {
            octet_count,
            maximum,
        } => write!(
            formatter,
            "IEEE 802.3 MAC client data is {octet_count} octets; maximum is {maximum} (reduce --padding, especially with --llc)"
        ),
        AppError::ServiceVlanTagRequiresCustomerVlanTag {
            service_vlan_identifier,
        } => write!(
            formatter,
            "IEEE 802.1Q service VLAN {service_vlan_identifier} needs a customer VLAN to wrap: set --vlan as well as --svlan"
        ),
        AppError::MonitorTimeoutRejected => {
            write!(formatter, "monitor timeout must be greater than zero")
        }
        _ => write!(
            formatter,
            "unexpected application error variant during display formatting"
        ),
    }
}

fn scan_timing_limit_display_message(limit: ScanTimingLimit) -> &'static str {
    match limit {
        ScanTimingLimit::BandwidthInterval => {
            "outbound send interval derived from --bandwidth does not fit in a duration"
        }
        ScanTimingLimit::InterRoundGap => {
            "inter-round gap of the send interval plus --pacing-ms does not fit in a duration"
        }
        ScanTimingLimit::RetryReceiveWindow => "retry receive window does not fit in a duration",
        ScanTimingLimit::MonotonicDeadline => "scan deadline does not fit in the monotonic clock",
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(outcome) = try_write_early_app_error_variants(self, formatter) {
            return outcome;
        }
        write_late_app_error_variants(self, formatter)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(error) => Some(error),
            AppError::InterfaceLookupFailed { source, .. }
            | AppError::InterfaceFlagsQueryFailed { source, .. }
            | AppError::RawSocketOpenFailed { source }
            | AppError::RawSocketCapabilityRequired { source }
            | AppError::BpfDeviceAccessRequired { source }
            | AppError::SocketBindFailed { source }
            | AppError::InterfaceIpv4AddressQueryFailed { source, .. }
            | AppError::InterfaceIpv4NetmaskQueryFailed { source, .. }
            | AppError::InterfaceHardwareAddressQueryFailed { source, .. }
            | AppError::PollWaitFailed { source }
            | AppError::RawPacketReceiveFailed { source }
            | AppError::InterfaceEnumerationFailed { source } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        AppError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use std::error::Error as _;

    #[test]
    fn display_includes_message_for_io_error() {
        // Arrange
        let inner = std::io::Error::other("fixture message");
        let application_error = AppError::Io(inner);

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("fixture message"),
            "display should include inner message, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_io_error() {
        // Arrange
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let application_error = AppError::Io(inner);

        // Act
        let source = application_error
            .source()
            .expect("Io variant should expose io::Error as source");

        // Assert
        let source_display = source.to_string();
        assert!(
            source_display.contains("denied"),
            "source should be the inner error, got: {source_display}"
        );
    }

    #[test]
    fn display_handles_empty_io_message_without_panicking() {
        // Arrange
        let inner = std::io::Error::other("");
        let application_error = AppError::Io(inner);

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("input/output error"),
            "display should still describe the variant, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_operating_system_for_unsupported_platform() {
        // Arrange
        let application_error = AppError::UnsupportedPlatform {
            operating_system: "fixture-os".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("fixture-os"),
            "display should include operating system, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_unsupported_platform() {
        // Arrange
        let application_error = AppError::UnsupportedPlatform {
            operating_system: "fixture-os".to_string(),
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "unsupported platform should not chain a source error"
        );
    }

    #[test]
    fn display_includes_message_for_invalid_interface_name() {
        // Arrange
        let application_error = AppError::InvalidInterfaceName {
            message: "too long".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("too long"),
            "display should include message, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_lookup_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceLookupFailed {
            interface_name: "missing0".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("missing0"),
            "display should include interface name, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_lookup_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceLookupFailed {
            interface_name: "missing0".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("lookup failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_flags_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(22);
        let application_error = AppError::InterfaceFlagsQueryFailed {
            interface_name: "eth0".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("eth0"),
            "display should include interface name, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_flags_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(22);
        let application_error = AppError::InterfaceFlagsQueryFailed {
            interface_name: "eth0".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("flags query failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_reason_for_interface_rejected_for_scanning() {
        // Arrange
        let application_error = AppError::InterfaceRejectedForScanning {
            interface_name: "lo".to_string(),
            reason: "loopback interface".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("loopback"),
            "display should include reason, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_interface_rejected_for_scanning() {
        // Arrange
        let application_error = AppError::InterfaceRejectedForScanning {
            interface_name: "lo".to_string(),
            reason: "loopback interface".to_string(),
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "interface rejection should not chain a source error"
        );
    }

    #[test]
    fn display_includes_context_for_raw_socket_open_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(1);
        let application_error = AppError::RawSocketOpenFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("raw packet socket"),
            "display should describe failure, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_raw_socket_open_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(1);
        let application_error = AppError::RawSocketOpenFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("raw socket failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_mentions_capability_for_raw_socket_capability_required() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(13);
        let application_error = AppError::RawSocketCapabilityRequired { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("CAP_NET_RAW"),
            "display should mention CAP_NET_RAW, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_raw_socket_capability_required() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(13);
        let application_error = AppError::RawSocketCapabilityRequired { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("capability denial should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_mentions_sudo_and_bpf_for_bpf_device_access_required() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(13);
        let application_error = AppError::BpfDeviceAccessRequired { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("Berkeley Packet Filter")
                && displayed.to_ascii_lowercase().contains("sudo"),
            "display should mention the BPF device and suggest sudo, got: {displayed}"
        );
    }

    #[test]
    fn display_for_bpf_device_access_required_does_not_leak_device_paths() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(13);
        let application_error = AppError::BpfDeviceAccessRequired { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            !displayed.contains("/dev/bpf"),
            "operator message should not leak a device path, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_bpf_device_access_required() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(13);
        let application_error = AppError::BpfDeviceAccessRequired { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("BPF access denial should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_context_for_socket_bind_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(99);
        let application_error = AppError::SocketBindFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("bind"),
            "display should describe bind failure, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_socket_bind_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(99);
        let application_error = AppError::SocketBindFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("bind failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_ipv4_address_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceIpv4AddressQueryFailed {
            interface_name: "eth9".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("eth9"),
            "display should include interface name, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_ipv4_address_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceIpv4AddressQueryFailed {
            interface_name: "eth9".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("IPv4 address query failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_ipv4_netmask_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(22);
        let application_error = AppError::InterfaceIpv4NetmaskQueryFailed {
            interface_name: "eth9".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("eth9"),
            "display should include interface name, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_reason_for_interface_hardware_address_unsupported() {
        // Arrange
        let application_error = AppError::InterfaceHardwareAddressUnsupported {
            interface_name: "eth0".to_string(),
            reason: "not Ethernet".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("not Ethernet"),
            "display should include reason, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_netmask_for_ipv4_netmask_invalid() {
        // Arrange
        let application_error = AppError::Ipv4NetmaskInvalid {
            netmask: "255.0.255.0".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("255.0.255.0"),
            "display should include netmask, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_message_for_ipv4_subnet_unsupported() {
        // Arrange
        let application_error = AppError::Ipv4SubnetUnsupported {
            message: "no usable hosts".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("no usable hosts"),
            "display should include message, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_source_and_message_for_ipv4_cidr_string_invalid() {
        // Arrange
        let application_error = AppError::Ipv4CidrStringInvalid {
            source: "10/8".to_string(),
            message: "fixture message".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("10/8") && displayed.contains("fixture message"),
            "display should include source and message, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_ipv4_cidr_string_invalid() {
        // Arrange
        let application_error = AppError::Ipv4CidrStringInvalid {
            source: "bad".to_string(),
            message: "bad format".to_string(),
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "CIDR parse errors should not chain a source error"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_poll_wait_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(4);
        let application_error = AppError::PollWaitFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("poll failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_raw_packet_receive_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(5);
        let application_error = AppError::RawPacketReceiveFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("receive failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_interface_name_for_interface_hardware_address_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceHardwareAddressQueryFailed {
            interface_name: "wlan0".to_string(),
            source: inner,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("wlan0") && displayed.contains("hardware address"),
            "display should name the interface and mention hardware address, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_hardware_address_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(19);
        let application_error = AppError::InterfaceHardwareAddressQueryFailed {
            interface_name: "wlan0".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("hardware address query failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_ipv4_netmask_query_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(99);
        let application_error = AppError::InterfaceIpv4NetmaskQueryFailed {
            interface_name: "eth2".to_string(),
            source: inner,
        };

        // Act
        let source = application_error
            .source()
            .expect("netmask query failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_includes_address_family_for_interface_ipv4_address_invalid_family() {
        // Arrange
        let application_error = AppError::InterfaceIpv4AddressInvalidFamily {
            address_family: 123,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("123"),
            "display should surface the unexpected family value, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_interface_and_family_for_netmask_invalid_family() {
        // Arrange
        let application_error = AppError::InterfaceIpv4NetmaskInvalidFamily {
            interface_name: "eth3".to_string(),
            address_family: 7,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("eth3") && displayed.contains('7'),
            "display should include interface and family, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_context_for_poll_wait_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(4);
        let application_error = AppError::PollWaitFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("readiness"),
            "display should describe poll/readiness failure, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_context_for_raw_packet_receive_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(5);
        let application_error = AppError::RawPacketReceiveFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("receive") && displayed.contains("Ethernet"),
            "display should describe receive failure, got: {displayed}"
        );
    }

    #[test]
    fn display_includes_context_for_interface_enumeration_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(12);
        let application_error = AppError::InterfaceEnumerationFailed { source: inner };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("enumerate") && displayed.contains("interface"),
            "display should describe enumeration failure, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_underlying_error_for_interface_enumeration_failed() {
        // Arrange
        let inner = std::io::Error::from_raw_os_error(12);
        let application_error = AppError::InterfaceEnumerationFailed { source: inner };

        // Act
        let source = application_error
            .source()
            .expect("enumeration failure should expose source");

        // Assert
        assert!(
            !source.to_string().is_empty(),
            "source should be non-empty, got: {source}"
        );
    }

    #[test]
    fn display_mentions_explicit_interface_flag_for_automatic_selection_none_found() {
        // Arrange
        let application_error = AppError::AutomaticInterfaceSelectionNoneFound;

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("--interface"),
            "display should tell the operator how to proceed, got: {displayed}"
        );
    }

    #[test]
    fn display_lists_interface_names_for_automatic_selection_ambiguous() {
        // Arrange
        let application_error = AppError::AutomaticInterfaceSelectionAmbiguous {
            interface_names: vec!["eth0".to_string(), "wlan0".to_string()],
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("eth0") && displayed.contains("wlan0"),
            "display should list ambiguous interface names, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_automatic_interface_selection_none_found() {
        // Arrange
        let application_error = AppError::AutomaticInterfaceSelectionNoneFound;

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "automatic selection errors should not chain a source error"
        );
    }

    #[test]
    fn source_returns_none_for_automatic_interface_selection_ambiguous() {
        // Arrange
        let application_error = AppError::AutomaticInterfaceSelectionAmbiguous {
            interface_names: vec!["eth0".to_string(), "wlan0".to_string()],
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "ambiguous automatic selection should not chain a source error"
        );
    }

    #[test]
    fn display_includes_target_interface_and_reason_for_single_scan_target_rejected() {
        // Arrange
        use std::net::Ipv4Addr;

        let application_error = AppError::SingleScanTargetRejected {
            target_ipv4_address: Ipv4Addr::new(192, 168, 1, 0),
            interface_name: "enp0s1".to_string(),
            reason: "not a strictly interior host on the interface subnet".to_string(),
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("192.168.1.0")
                && displayed.contains("enp0s1")
                && displayed.contains("strictly interior"),
            "display should name target, interface, and reason, got: {displayed}"
        );
    }

    #[test]
    fn source_returns_none_for_single_scan_target_rejected() {
        // Arrange
        use std::net::Ipv4Addr;

        let application_error = AppError::SingleScanTargetRejected {
            target_ipv4_address: Ipv4Addr::new(10, 0, 0, 0),
            interface_name: "eth1".to_string(),
            reason: "fixture".to_string(),
        };

        // Act
        let source = application_error.source();

        // Assert
        assert!(
            source.is_none(),
            "single scan target rejection should not chain a source error"
        );
    }

    #[test]
    fn display_includes_octet_counts_for_ieee_8023_mac_client_data_exceeds_maximum() {
        // Arrange
        let application_error = AppError::Ieee8023MacClientDataExceedsMaximum {
            octet_count: 1501,
            maximum: 1500,
        };

        // Act
        let displayed = application_error.to_string();

        // Assert
        assert!(
            displayed.contains("1501")
                && displayed.contains("1500")
                && displayed.contains("padding"),
            "display should name the oversize payload and --padding, got: {displayed}"
        );
    }

    #[test]
    fn display_names_rejected_inter_target_rate_inputs() {
        // Arrange
        let bandwidth = AppError::InterTargetBandwidthRejected;
        let interval = AppError::InterTargetIntervalRejected;
        let backoff = AppError::RetryBackoffFactorRejected;

        // Act
        let bandwidth_display = bandwidth.to_string();
        let interval_display = interval.to_string();
        let backoff_display = backoff.to_string();

        // Assert
        assert!(
            bandwidth_display.contains("bandwidth") && bandwidth_display.contains("zero"),
            "zero bandwidth should be named, got: {bandwidth_display}"
        );
        assert!(
            interval_display.contains("interval") && interval_display.contains("zero"),
            "zero interval should be named, got: {interval_display}"
        );
        assert!(
            backoff_display.contains("backoff") && backoff_display.contains('1'),
            "invalid backoff should be named, got: {backoff_display}"
        );
        assert!(bandwidth.source().is_none());
    }

    #[test]
    fn display_rejects_zero_monitor_timeout_without_a_source() {
        // Arrange
        let application_error = AppError::MonitorTimeoutRejected;

        // Act
        let displayed = application_error.to_string();
        let source = std::error::Error::source(&application_error);

        // Assert
        assert!(
            displayed.contains("monitor timeout") && displayed.contains("zero"),
            "zero monitor timeout should be named, got: {displayed}"
        );
        assert!(
            source.is_none(),
            "monitor timeout rejection has no underlying error, got: {source:?}"
        );
    }

    #[test]
    fn display_names_each_scan_timing_overflow() {
        // Arrange
        let limits = [
            super::ScanTimingLimit::BandwidthInterval,
            super::ScanTimingLimit::InterRoundGap,
            super::ScanTimingLimit::RetryReceiveWindow,
            super::ScanTimingLimit::MonotonicDeadline,
        ];

        // Act
        let displayed: Vec<String> = limits
            .into_iter()
            .map(|limit| AppError::ScanTimingExceedsLimit { limit }.to_string())
            .collect();

        // Assert
        assert!(
            displayed.iter().all(|message| !message.is_empty())
                && displayed[0].contains("bandwidth")
                && displayed[1].contains("pacing")
                && displayed[2].contains("retry")
                && displayed[3].contains("deadline"),
            "each timing overflow should name its span, got: {displayed:?}"
        );
    }
}
