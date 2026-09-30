//! Thin `libc` wrappers for Linux system calls used by raw packet scanning.
//!
//! All foreign-function-interface calls are concentrated here. Callers translate operating
//! system errors into [`crate::error::AppError`] at higher layers.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::linux_packet::ethernet_protocol_host_to_network_order;

/// `ioctl(2)` request for reading interface flags (`SIOCGIFFLAGS`).
pub const SIOCGIFFLAGS_REQUEST: libc::Ioctl = 0x8913;

/// `ioctl(2)` request for reading an interface IPv4 address (`SIOCGIFADDR`).
pub const SIOCGIFADDR_REQUEST: libc::Ioctl = 0x8915;

/// `ioctl(2)` request for reading an interface IPv4 netmask (`SIOCGIFNETMASK`).
pub const SIOCGIFNETMASK_REQUEST: libc::Ioctl = 0x891b;

/// `ioctl(2)` request for reading an interface hardware address (`SIOCGIFHWADDR`).
pub const SIOCGIFHWADDR_REQUEST: libc::Ioctl = 0x8927;

fn sockaddr_link_layer_length() -> std::io::Result<libc::socklen_t> {
    libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sockaddr_ll length does not fit socklen_t",
        )
    })
}

/// Opens an `AF_INET` datagram socket for interface `ioctl` operations.
///
/// # Errors
///
/// Returns the last operating system error when `socket(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn open_inet_datagram_socket() -> std::io::Result<OwnedFd> {
    // SAFETY: `socket(2)` with `AF_INET`/`SOCK_DGRAM` is the standard approach for issuing
    // interface `ioctl`s (see `netdevice(7)`).
    let file_descriptor =
        unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };

    if file_descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `file_descriptor` is a freshly created valid socket file descriptor returned by
    // `socket(2)`.
    Ok(unsafe { OwnedFd::from_raw_fd(file_descriptor) })
}

/// Invokes `ioctl(2)` with a mutable [`libc::ifreq`] buffer.
///
/// # Errors
///
/// Returns the last operating system error when `ioctl(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn ioctl_ifreq(
    socket: &OwnedFd,
    request_code: libc::Ioctl,
    request: &mut libc::ifreq,
) -> std::io::Result<()> {
    // SAFETY: `socket` is a valid datagram socket file descriptor and `request` is a valid
    // `ifreq` pointer for the given `request_code` (see `ioctl(2)` and `netdevice(7)`).
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            request_code,
            std::ptr::from_mut(request).cast::<libc::c_void>(),
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Resolves `interface_name` to an interface index via `if_nametoindex(3)`.
///
/// # Errors
///
/// Returns the last operating system error when the name is not found or resolution fails.
///
/// # Panics
///
/// This function does not panic.
pub fn interface_index_from_name(interface_name: &std::ffi::CStr) -> std::io::Result<libc::c_uint> {
    // SAFETY: `interface_name` is a valid NUL-terminated C string pointer accepted by
    // `if_nametoindex(3)`.
    let index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(index)
}

struct IfNameIndexArrayGuard(*mut libc::if_nameindex);

impl Drop for IfNameIndexArrayGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by `if_nameindex(3)` and must be released with
            // `if_freenameindex(3)`.
            unsafe {
                libc::if_freenameindex(self.0);
            }
        }
    }
}

/// Returns interface names and indexes from `if_nameindex(3)`.
///
/// Entries are sorted by interface index ascending. Names that are not valid UTF-8 are skipped.
///
/// # Errors
///
/// Returns the last operating system error when `if_nameindex(3)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn list_interface_name_and_index_pairs() -> std::io::Result<Vec<(String, libc::c_uint)>> {
    // SAFETY: `if_nameindex(3)` returns either `NULL` or a pointer to a `NULL`-terminated array
    // of `struct if_nameindex` (see `if_nameindex(3)`).
    let head = unsafe { libc::if_nameindex() };
    if head.is_null() {
        return Err(std::io::Error::last_os_error());
    }

    let _guard = IfNameIndexArrayGuard(head);
    let mut pairs = Vec::new();
    let mut offset = 0usize;

    loop {
        // SAFETY: `head` points at a valid array until the terminator entry is observed.
        let entry = unsafe { *head.add(offset) };
        if entry.if_index == 0 && entry.if_name.is_null() {
            break;
        }

        // SAFETY: active entries have a non-null `if_name` per `if_nameindex(3)`.
        let name_pointer = entry.if_name;
        if !name_pointer.is_null() {
            // SAFETY: `name_pointer` references a NUL-terminated interface name string.
            let name_slice = unsafe { std::ffi::CStr::from_ptr(name_pointer) };
            if let Ok(name) = name_slice.to_str() {
                pairs.push((name.to_string(), entry.if_index));
            }
        }

        offset = offset.saturating_add(1);
    }

    pairs.sort_by_key(|pair| pair.1);
    Ok(pairs)
}

/// Opens a raw `AF_PACKET` / `SOCK_RAW` socket for the given Ethernet protocol (for example
/// [`crate::linux_packet::ETHERNET_PROTOCOL_ARP`] in host byte order; the kernel expects
/// `protocol` in network byte order per `packet(7)`).
///
/// # Errors
///
/// Returns the last operating system error when `socket(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn open_packet_raw_socket(ethernet_protocol_host_order: u16) -> std::io::Result<OwnedFd> {
    let protocol = libc::c_int::from(ethernet_protocol_host_to_network_order(
        ethernet_protocol_host_order,
    ));

    // SAFETY: `socket(2)` with `AF_PACKET`/`SOCK_RAW` is the documented Linux mechanism for raw
    // link-layer access (see `packet(7)`).
    let file_descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            protocol,
        )
    };

    if file_descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `file_descriptor` is a freshly created valid socket file descriptor returned by
    // `socket(2)`.
    Ok(unsafe { OwnedFd::from_raw_fd(file_descriptor) })
}

/// Binds a packet socket to a [`libc::sockaddr_ll`] address.
///
/// # Errors
///
/// Returns the last operating system error when `bind(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn bind_sockaddr_link_layer(
    socket: &OwnedFd,
    address: &libc::sockaddr_ll,
) -> std::io::Result<()> {
    let address_length = sockaddr_link_layer_length()?;

    // SAFETY: `address` matches `struct sockaddr_ll` and `bind(2)` expects a `sockaddr` pointer
    // with the correct length for this address family (see `packet(7)`).
    let bind_result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            std::ptr::from_ref::<libc::sockaddr_ll>(address).cast::<libc::sockaddr>(),
            address_length,
        )
    };

    if bind_result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Sends a datagram on a packet socket using `sendto(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `sendto(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn send_to_link_layer(
    socket: &OwnedFd,
    message: &[u8],
    destination: &libc::sockaddr_ll,
) -> std::io::Result<usize> {
    let destination_length = sockaddr_link_layer_length()?;

    // SAFETY: `message` is a valid byte slice and `destination` points to a valid `sockaddr_ll`
    // for the packet socket (see `sendto(2)` and `packet(7)`).
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr().cast::<libc::c_void>(),
            message.len(),
            0,
            std::ptr::from_ref::<libc::sockaddr_ll>(destination).cast::<libc::sockaddr>(),
            destination_length,
        )
    };

    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }

    usize::try_from(sent)
        .map_err(|_| std::io::Error::other("sendto returned a negative byte count"))
}

/// Receives a datagram from a packet socket using `recvfrom(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `recvfrom(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn receive_from_link_layer(
    socket: &OwnedFd,
    buffer: &mut [u8],
    flags: libc::c_int,
    source_out: Option<&mut libc::sockaddr_ll>,
) -> std::io::Result<usize> {
    let mut address_length = sockaddr_link_layer_length()?;
    let (source_pointer, source_length_pointer) = match source_out {
        Some(out) => (
            std::ptr::from_mut(out).cast::<libc::sockaddr>(),
            std::ptr::from_mut(&mut address_length),
        ),
        None => (std::ptr::null_mut(), std::ptr::null_mut()),
    };

    // SAFETY: `buffer` is a valid writable slice; when `source_out` is `Some`, `out` is large
    // enough for `sockaddr_ll` and `address_length` is initialized to that size (see
    // `recvfrom(2)`).
    let received = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            flags,
            source_pointer,
            source_length_pointer,
        )
    };

    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }

    usize::try_from(received)
        .map_err(|_| std::io::Error::other("recvfrom returned a negative byte count"))
}

/// Waits for readiness on `socket` using `poll(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `poll(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn poll_socket_readiness(
    socket: &OwnedFd,
    events: i16,
    timeout_milliseconds: libc::c_int,
) -> std::io::Result<libc::c_int> {
    let mut poll_file_descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };

    // SAFETY: `poll_file_descriptor` points to one element for the duration of the call.
    let ready = unsafe {
        libc::poll(
            std::ptr::addr_of_mut!(poll_file_descriptor),
            1,
            timeout_milliseconds,
        )
    };

    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(ready)
}

/// One IPv4 address reported by `getifaddrs(3)` for a named interface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Returned by `list_interface_ipv4_addresses`.
pub struct InterfaceIpv4AddressRecord {
    /// Kernel interface name (`ifa_name`).
    pub interface_name: String,
    /// IPv4 address stored at `ifa_addr`.
    pub ipv4_address: std::net::Ipv4Addr,
}

/// Owns the `getifaddrs(3)` list head and releases it with `freeifaddrs(3)` on drop.
#[allow(dead_code)] // Owns the list inside `list_interface_ipv4_addresses`.
struct InterfaceAddressListGuard(*mut libc::ifaddrs);

impl Drop for InterfaceAddressListGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was returned by `getifaddrs(3)` and must be released with
            // `freeifaddrs(3)`.
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
}

/// Reads an IPv4 address from `sockaddr` when its family is `AF_INET`.
///
/// The four octets at `sin_addr.s_addr` are the address in wire order. `s_addr.to_be_bytes()` would
/// permute those octets on little-endian hosts.
#[allow(dead_code)] // Called while lowering `getifaddrs(3)` records.
fn ipv4_address_from_sockaddr(sockaddr: &libc::sockaddr) -> Option<std::net::Ipv4Addr> {
    if libc::c_int::from(sockaddr.sa_family) != libc::AF_INET {
        return None;
    }

    // SAFETY: `sockaddr` was validated as `AF_INET` and can be reinterpreted as `sockaddr_in`.
    let socket_address_internet = unsafe {
        std::ptr::from_ref(sockaddr)
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };
    // SAFETY: `s_addr` is a four-octet network-order address in the POSIX `in_addr` ABI.
    let octets: [u8; 4] = unsafe {
        std::ptr::from_ref(&socket_address_internet.sin_addr.s_addr)
            .cast::<[u8; 4]>()
            .read_unaligned()
    };
    Some(std::net::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

/// Collects every `AF_INET` address reported by `getifaddrs(3)`.
///
/// Entries without a usable UTF-8 name, without an address, or with a family other than `AF_INET`
/// are skipped. `SIOCGIFADDR` only returns one address per name; this list is what passive
/// monitoring uses to see secondary addresses on the same interface. Alias names such as `eth0:1`
/// remain separate `ifa_name` values and are not folded into `eth0`.
///
/// # Errors
///
/// Returns the last operating system error when `getifaddrs(3)` fails.
///
/// # Panics
///
/// This function does not panic.
#[allow(dead_code)] // Called by Linux monitor discovery in the following change.
pub fn list_interface_ipv4_addresses() -> std::io::Result<Vec<InterfaceIpv4AddressRecord>> {
    let mut list_head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs(3)` either writes a list head into `list_head` and returns 0, or returns
    // a non-zero value and leaves `list_head` untouched.
    let result = unsafe { libc::getifaddrs(std::ptr::addr_of_mut!(list_head)) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let _guard = InterfaceAddressListGuard(list_head);
    let mut records = Vec::new();
    let mut current = list_head;
    while !current.is_null() {
        // SAFETY: `current` points to a valid node until the terminating null pointer.
        let node = unsafe { &*current };
        if let Some(record) = interface_ipv4_address_record_from_ifaddrs(node) {
            records.push(record);
        }
        current = node.ifa_next;
    }

    Ok(records)
}

/// Lowers one `getifaddrs(3)` node into an [`InterfaceIpv4AddressRecord`].
///
/// Returns [`None`] for a missing name, a non-UTF-8 name, a missing address, or a non-`AF_INET`
/// address.
#[allow(dead_code)] // Called by `list_interface_ipv4_addresses`.
fn interface_ipv4_address_record_from_ifaddrs(
    node: &libc::ifaddrs,
) -> Option<InterfaceIpv4AddressRecord> {
    if node.ifa_name.is_null() || node.ifa_addr.is_null() {
        return None;
    }

    // SAFETY: `ifa_name` is a non-null NUL-terminated interface name string per `getifaddrs(3)`.
    let interface_name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }
        .to_str()
        .ok()?
        .to_string();
    // SAFETY: `ifa_addr` is non-null here and points to a valid `sockaddr`.
    let ipv4_address = ipv4_address_from_sockaddr(unsafe { &*node.ifa_addr })?;
    Some(InterfaceIpv4AddressRecord {
        interface_name,
        ipv4_address,
    })
}

#[cfg(test)]
mod tests {
    use super::interface_index_from_name;
    use super::open_inet_datagram_socket;
    use super::poll_socket_readiness;
    use std::ffi::CString;

    #[test]
    fn opens_inet_datagram_socket_successfully_on_linux() {
        // Arrange
        // Act
        let outcome = open_inet_datagram_socket();

        // Assert
        assert!(
            outcome.is_ok(),
            "opening an inet datagram socket should succeed on Linux, got: {outcome:?}"
        );
    }

    #[test]
    fn resolves_loopback_interface_index_on_linux() {
        // Arrange
        let name = CString::new("lo").expect("loopback interface name should be valid C string");

        // Act
        let outcome = interface_index_from_name(&name);

        // Assert
        assert!(
            outcome.is_ok(),
            "loopback interface index should resolve on Linux, got: {outcome:?}"
        );
        assert_ne!(
            outcome.expect("index resolution should succeed"),
            0,
            "loopback index should be non-zero"
        );
    }

    #[test]
    fn list_interface_name_and_index_pairs_includes_loopback_on_linux() {
        // Arrange
        // Act
        let outcome = super::list_interface_name_and_index_pairs();

        // Assert
        let pairs = outcome.expect("if_nameindex should succeed on Linux");
        assert!(
            pairs.iter().any(|(name, _)| name == "lo"),
            "expected loopback interface in if_nameindex results, got: {pairs:?}"
        );
    }

    #[test]
    fn interface_index_from_name_fails_for_nonexistent_interface() {
        // Arrange
        let name = CString::new("narp___nonexistent_iface___").expect("fixture name");

        // Act
        let outcome = interface_index_from_name(&name);

        // Assert
        assert!(
            outcome.is_err(),
            "bogus interface names should fail resolution, got: {outcome:?}"
        );
    }

    #[test]
    fn poll_on_inet_datagram_socket_reports_pollout_without_blocking_forever() {
        // Arrange
        let socket = open_inet_datagram_socket().expect("inet datagram socket should open");
        let timeout_milliseconds: libc::c_int = 100;

        // Act
        let outcome = poll_socket_readiness(&socket, libc::POLLOUT, timeout_milliseconds);

        // Assert
        let ready = outcome.expect("poll on open socket should succeed");
        assert_ne!(
            ready, 0,
            "POLLOUT should become ready quickly on an open datagram socket, got ready={ready}"
        );
    }

    #[test]
    fn reads_ipv4_octets_from_sockaddr_in_wire_order() {
        // Arrange
        let expected = std::net::Ipv4Addr::new(198, 51, 100, 24);
        let mut socket_address_internet: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET should fit sa_family_t");
        unsafe {
            std::ptr::addr_of_mut!(socket_address_internet.sin_addr.s_addr)
                .cast::<[u8; 4]>()
                .write(expected.octets());
        }
        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_in` for the lifetime of this test.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = super::ipv4_address_from_sockaddr(sockaddr_ref);

        // Assert
        assert_eq!(
            outcome,
            Some(expected),
            "s_addr memory should be read as wire-order octets"
        );
    }

    #[test]
    fn ipv4_address_from_sockaddr_rejects_non_inet_family() {
        // Arrange
        let mut socket_address_internet: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 should fit sa_family_t");
        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_in` for the lifetime of this test.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = super::ipv4_address_from_sockaddr(sockaddr_ref);

        // Assert
        assert_eq!(
            outcome, None,
            "AF_INET6 addresses are not IPv4 monitor identities"
        );
    }

    #[test]
    fn list_interface_ipv4_addresses_includes_loopback_localhost() {
        // Act
        let records = super::list_interface_ipv4_addresses()
            .expect("getifaddrs should succeed on Linux test hosts");

        // Assert
        assert!(
            records.iter().any(|record| {
                record.interface_name == "lo"
                    && record.ipv4_address == std::net::Ipv4Addr::LOCALHOST
            }),
            "loopback should report 127.0.0.1, got: {records:?}"
        );
        assert!(
            records
                .iter()
                .all(|record| !record.interface_name.is_empty()),
            "every retained record should have a name, got: {records:?}"
        );
    }
}
