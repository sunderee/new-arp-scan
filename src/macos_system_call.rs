//! Thin `libc` wrappers for the macOS system calls used by interface discovery.
//!
//! All foreign-function-interface calls for the macOS backend are concentrated here. The
//! `getifaddrs(3)` linked list is walked once and lowered into owned, safe
//! [`InterfaceAddressRecord`] values so that classification (in
//! [`crate::macos_interface_discovery`]) stays pure and hermetically testable. Callers translate
//! operating system errors into [`crate::error::AppError`] at higher layers.

#![allow(
    unsafe_code,
    reason = "libc FFI for the macOS packet backend; see DECISIONS.md 2026-11-15"
)]

use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};

/// One address entry reported by `getifaddrs(3)` for a named interface, lowered to safe values.
///
/// `getifaddrs(3)` returns several entries per interface (one per address family); discovery
/// aggregates the IPv4 and link-layer entries that share an [`Self::interface_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddressRecord {
    /// Interface name this entry belongs to (for example `en0`).
    pub interface_name: String,
    /// `ifa_flags` for the interface (`IFF_*`); identical across a single interface's entries.
    pub interface_flags: libc::c_uint,
    /// The address payload carried by this entry.
    pub payload: InterfaceAddressPayload,
}

/// The address-family-specific payload of an [`InterfaceAddressRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceAddressPayload {
    /// An `AF_INET` entry: the interface IPv4 address and, when present, its netmask.
    Ipv4 {
        /// IPv4 address assigned to the interface.
        address: Ipv4Addr,
        /// IPv4 netmask, when `getifaddrs(3)` reported one.
        netmask: Option<Ipv4Addr>,
    },
    /// An `AF_LINK` entry: the link-layer hardware type and Ethernet address when usable.
    LinkLayer {
        /// `sdl_type` (`IFT_*`) describing the link-layer medium.
        interface_type: u8,
        /// Six-octet Ethernet address when `sdl_alen == 6`; [`None`] otherwise.
        hardware_address: Option<[u8; 6]>,
    },
}

/// Reads an IPv4 address from a `sockaddr` whose family is `AF_INET`.
///
/// Returns [`None`] when the address family is not `AF_INET`.
fn read_ipv4_from_sockaddr(sockaddr: &libc::sockaddr) -> Option<Ipv4Addr> {
    if libc::c_int::from(sockaddr.sa_family) != libc::AF_INET {
        return None;
    }

    // SAFETY: `sockaddr` was validated as `AF_INET` and can be reinterpreted as `sockaddr_in`.
    let socket_address_internet = unsafe {
        std::ptr::from_ref(sockaddr)
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };

    // POSIX stores `in_addr.s_addr` in network byte order: the four bytes at `&s_addr` are the
    // IPv4 octets in order. Reading them as raw bytes avoids the endianness permutation that
    // `s_addr.to_be_bytes()` introduces on little-endian targets.
    let octets: [u8; 4] = unsafe {
        std::ptr::from_ref(&socket_address_internet.sin_addr.s_addr)
            .cast::<[u8; 4]>()
            .read_unaligned()
    };
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// Reads the hardware type and Ethernet address from an `AF_LINK` `sockaddr_dl`.
///
/// Returns the `sdl_type` and, when `sdl_alen == 6`, the six Ethernet octets located at
/// `sdl_data[sdl_nlen..]`.
fn read_link_layer_address_from_sockaddr_dl(sockaddr: &libc::sockaddr) -> (u8, Option<[u8; 6]>) {
    use std::mem::offset_of;

    // Read the `sockaddr_dl` header fields as individual bytes at their `offset_of` positions. This
    // keeps the access alignment-agnostic (the `sockaddr` may be only byte-aligned) and robust to
    // layout padding, instead of casting to a more-strictly-aligned `*const sockaddr_dl`.
    let base = std::ptr::from_ref(sockaddr).cast::<u8>();
    // SAFETY: callers pass a `sockaddr` backed by a `sockaddr_dl` (family `AF_LINK`); these
    // single-byte header fields lie within the structure.
    let interface_type = unsafe { base.add(offset_of!(libc::sockaddr_dl, sdl_type)).read() };
    let name_length = unsafe { base.add(offset_of!(libc::sockaddr_dl, sdl_nlen)).read() } as usize;
    let address_length =
        unsafe { base.add(offset_of!(libc::sockaddr_dl, sdl_alen)).read() } as usize;

    if address_length != 6 {
        return (interface_type, None);
    }

    // `sdl_data` is a variable-length trailing array holding the interface name (`sdl_nlen` bytes)
    // followed by the link-layer address (`sdl_alen` bytes). Read the address bytes from the start
    // of `sdl_data` by offset, because the kernel allocation extends beyond the fixed mirror field.
    let mut octets = [0u8; 6];
    // SAFETY: the backing `sockaddr_dl` allocation contains at least `sdl_nlen + sdl_alen` valid
    // bytes of `sdl_data` (guaranteed by `getifaddrs(3)` and by the test fixtures), so copying six
    // octets starting at offset `name_length` stays in bounds.
    unsafe {
        let data_base = base.add(offset_of!(libc::sockaddr_dl, sdl_data));
        std::ptr::copy_nonoverlapping(data_base.add(name_length), octets.as_mut_ptr(), 6);
    }
    (interface_type, Some(octets))
}

/// Owns the `getifaddrs(3)` list head and releases it with `freeifaddrs(3)` on drop.
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

/// Lowers one `getifaddrs(3)` node into an [`InterfaceAddressRecord`].
///
/// Returns [`None`] for entries without a usable UTF-8 name, without an address, or whose address
/// family is neither `AF_INET` nor `AF_LINK`.
fn build_interface_address_record(node: &libc::ifaddrs) -> Option<InterfaceAddressRecord> {
    if node.ifa_name.is_null() {
        return None;
    }
    // SAFETY: `ifa_name` is a non-null NUL-terminated interface name string per `getifaddrs(3)`.
    let interface_name = unsafe { CStr::from_ptr(node.ifa_name) }
        .to_str()
        .ok()?
        .to_string();

    if node.ifa_addr.is_null() {
        return None;
    }
    // SAFETY: `ifa_addr` is non-null here and points to a valid `sockaddr`.
    let address = unsafe { &*node.ifa_addr };
    let address_family = libc::c_int::from(address.sa_family);

    let payload = if address_family == libc::AF_INET {
        let ipv4_address = read_ipv4_from_sockaddr(address)?;
        let netmask = if node.ifa_netmask.is_null() {
            None
        } else {
            // SAFETY: `ifa_netmask` is non-null here and points to a valid `sockaddr`.
            read_ipv4_from_sockaddr(unsafe { &*node.ifa_netmask })
        };
        InterfaceAddressPayload::Ipv4 {
            address: ipv4_address,
            netmask,
        }
    } else if address_family == libc::AF_LINK {
        let (interface_type, hardware_address) = read_link_layer_address_from_sockaddr_dl(address);
        InterfaceAddressPayload::LinkLayer {
            interface_type,
            hardware_address,
        }
    } else {
        return None;
    };

    Some(InterfaceAddressRecord {
        interface_name,
        interface_flags: node.ifa_flags,
        payload,
    })
}

/// Collects the IPv4 and link-layer address records reported by `getifaddrs(3)`.
///
/// # Errors
///
/// Returns the last operating system error when `getifaddrs(3)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn collect_interface_address_records() -> std::io::Result<Vec<InterfaceAddressRecord>> {
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
        if let Some(record) = build_interface_address_record(node) {
            records.push(record);
        }
        current = node.ifa_next;
    }

    Ok(records)
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
pub fn interface_index_from_name(interface_name: &CStr) -> std::io::Result<libc::c_uint> {
    // SAFETY: `interface_name` is a valid NUL-terminated C string pointer accepted by
    // `if_nametoindex(3)`.
    let index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(index)
}

/// `ioctl(2)` direction flag for reading a value from the kernel (`IOC_OUT`).
const IOCTL_DIRECTION_OUT: libc::c_ulong = 0x4000_0000;
/// `ioctl(2)` direction flag for writing a value to the kernel (`IOC_IN`).
const IOCTL_DIRECTION_IN: libc::c_ulong = 0x8000_0000;
/// Mask limiting the encoded parameter length (`IOCPARM_MASK`).
const IOCTL_PARAMETER_MASK: libc::c_ulong = 0x1fff;
/// `ioctl(2)` group character for Berkeley Packet Filter requests (`'B'`).
const BPF_IOCTL_GROUP: u8 = b'B';

/// Encodes a BSD `ioctl(2)` request code the way the `_IOR`/`_IOW`/`_IO` macros in `sys/ioccom.h`
/// do, so the Berkeley Packet Filter request constants can be derived rather than hard-coded.
const fn encode_ioctl_request(
    direction: libc::c_ulong,
    group: u8,
    number: u8,
    parameter_length: usize,
) -> libc::c_ulong {
    direction
        | (((parameter_length as libc::c_ulong) & IOCTL_PARAMETER_MASK) << 16)
        | ((group as libc::c_ulong) << 8)
        | (number as libc::c_ulong)
}

/// `BIOCGBLEN`: read the kernel's Berkeley Packet Filter read-buffer length.
const BIOCGBLEN: libc::c_ulong = encode_ioctl_request(
    IOCTL_DIRECTION_OUT,
    BPF_IOCTL_GROUP,
    102,
    std::mem::size_of::<libc::c_uint>(),
);
/// `BIOCSETIF`: attach the Berkeley Packet Filter device to a named interface.
const BIOCSETIF: libc::c_ulong = encode_ioctl_request(
    IOCTL_DIRECTION_IN,
    BPF_IOCTL_GROUP,
    108,
    std::mem::size_of::<libc::ifreq>(),
);
/// `BIOCIMMEDIATE`: return reads immediately as packets arrive rather than buffering.
const BIOCIMMEDIATE: libc::c_ulong = encode_ioctl_request(
    IOCTL_DIRECTION_IN,
    BPF_IOCTL_GROUP,
    112,
    std::mem::size_of::<libc::c_uint>(),
);
/// `BIOCSHDRCMPLT`: send frames with the source address as written instead of overwriting it.
const BIOCSHDRCMPLT: libc::c_ulong = encode_ioctl_request(
    IOCTL_DIRECTION_IN,
    BPF_IOCTL_GROUP,
    117,
    std::mem::size_of::<libc::c_uint>(),
);

/// One classic Berkeley Packet Filter instruction (`struct bpf_insn` in `net/bpf.h`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfProgramInstruction {
    /// Operation code (`BPF_*`).
    pub code: u16,
    /// Branch offset taken when a comparison is true.
    pub jump_if_true: u8,
    /// Branch offset taken when a comparison is false.
    pub jump_if_false: u8,
    /// Generic operand (offset, constant, or return length).
    pub operand: u32,
}

/// A classic Berkeley Packet Filter program (`struct bpf_program` in `net/bpf.h`).
#[repr(C)]
struct BpfProgram {
    instruction_count: libc::c_uint,
    instructions: *mut BpfProgramInstruction,
}

/// `BIOCSETF`: install a classic Berkeley Packet Filter program on the device.
const BIOCSETF: libc::c_ulong = encode_ioctl_request(
    IOCTL_DIRECTION_IN,
    BPF_IOCTL_GROUP,
    103,
    std::mem::size_of::<BpfProgram>(),
);

/// Installs a classic Berkeley Packet Filter program (`BIOCSETF`) limiting which frames the device
/// delivers to reads.
///
/// # Errors
///
/// Returns the last operating system error when the `ioctl(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn set_bpf_filter(
    bpf_device: &OwnedFd,
    instructions: &[BpfProgramInstruction],
) -> std::io::Result<()> {
    let instruction_count = libc::c_uint::try_from(instructions.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Berkeley Packet Filter program is too long",
        )
    })?;
    let mut program = BpfProgram {
        instruction_count,
        instructions: instructions.as_ptr().cast_mut(),
    };

    // SAFETY: `BIOCSETF` reads a `bpf_program` pointing at `instruction_count` valid instructions;
    // `instructions` outlives the call and the kernel copies the program in.
    let result = unsafe {
        libc::ioctl(
            bpf_device.as_raw_fd(),
            BIOCSETF,
            std::ptr::from_mut(&mut program),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Controls whether the device also captures frames sent on the interface (`BIOCSSEESENT`).
///
/// Disabling this keeps the scanner from receiving the ARP requests it just broadcast.
///
/// # Errors
///
/// Returns the last operating system error when the `ioctl(2)` fails.
pub fn set_bpf_see_sent(bpf_device: &OwnedFd, enabled: bool) -> std::io::Result<()> {
    set_bpf_unsigned_option(bpf_device, libc::BIOCSSEESENT, libc::c_uint::from(enabled))
}

/// Opens the first available cloning Berkeley Packet Filter device (`/dev/bpfN`).
///
/// Skips devices that are busy (`EBUSY`) and returns the underlying error otherwise (for example
/// `EACCES` when the process lacks root, or `ENOENT` once the device range is exhausted).
///
/// # Errors
///
/// Returns the last operating system error when no Berkeley Packet Filter device can be opened.
///
/// # Panics
///
/// This function does not panic.
pub fn open_bpf_device() -> std::io::Result<OwnedFd> {
    let mut last_error = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no Berkeley Packet Filter device was available",
    );
    for minor_number in 0..256u32 {
        let device_path = format!("/dev/bpf{minor_number}");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device_path)
        {
            Ok(file) => return Ok(OwnedFd::from(file)),
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                last_error = error;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

/// Attaches an opened Berkeley Packet Filter device to the interface named in `request` (`BIOCSETIF`).
///
/// # Errors
///
/// Returns the last operating system error when the `ioctl(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn set_bpf_interface(bpf_device: &OwnedFd, request: &libc::ifreq) -> std::io::Result<()> {
    // SAFETY: `BIOCSETIF` reads a `struct ifreq` naming the interface to attach; `request` is a
    // valid `ifreq` and lives for the duration of the call.
    let result = unsafe {
        libc::ioctl(
            bpf_device.as_raw_fd(),
            BIOCSETIF,
            std::ptr::from_ref(request),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Sets an unsigned-integer Berkeley Packet Filter option (`BIOCIMMEDIATE`, `BIOCSHDRCMPLT`).
fn set_bpf_unsigned_option(
    bpf_device: &OwnedFd,
    request_code: libc::c_ulong,
    value: libc::c_uint,
) -> std::io::Result<()> {
    let mut option_value = value;
    // SAFETY: these BPF options read a single `c_uint`; `option_value` is a valid, writable
    // `c_uint` for the call.
    let result = unsafe {
        libc::ioctl(
            bpf_device.as_raw_fd(),
            request_code,
            std::ptr::from_mut(&mut option_value),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enables immediate read delivery on a Berkeley Packet Filter device (`BIOCIMMEDIATE`).
///
/// # Errors
///
/// Returns the last operating system error when the `ioctl(2)` fails.
pub fn set_bpf_immediate(bpf_device: &OwnedFd, enabled: bool) -> std::io::Result<()> {
    set_bpf_unsigned_option(bpf_device, BIOCIMMEDIATE, libc::c_uint::from(enabled))
}

/// Enables complete-header sending on a Berkeley Packet Filter device (`BIOCSHDRCMPLT`).
///
/// With this set, the kernel sends frames exactly as written instead of overwriting the source
/// hardware address, which preserves the source MAC the encoder placed in the frame.
///
/// # Errors
///
/// Returns the last operating system error when the `ioctl(2)` fails.
pub fn set_bpf_header_complete(bpf_device: &OwnedFd, enabled: bool) -> std::io::Result<()> {
    set_bpf_unsigned_option(bpf_device, BIOCSHDRCMPLT, libc::c_uint::from(enabled))
}

/// Reads the kernel read-buffer length for a Berkeley Packet Filter device (`BIOCGBLEN`).
///
/// Reads from the device must use a buffer of exactly this length.
///
/// # Errors
///
/// Returns the last operating system error when the `ioctl(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn get_bpf_buffer_length(bpf_device: &OwnedFd) -> std::io::Result<libc::c_uint> {
    let mut buffer_length: libc::c_uint = 0;
    // SAFETY: `BIOCGBLEN` writes a single `c_uint`; `buffer_length` is a valid, writable `c_uint`.
    let result = unsafe {
        libc::ioctl(
            bpf_device.as_raw_fd(),
            BIOCGBLEN,
            std::ptr::from_mut(&mut buffer_length),
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buffer_length)
}

/// Puts a file descriptor into non-blocking mode (`O_NONBLOCK`).
///
/// # Errors
///
/// Returns the last operating system error when `fcntl(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn set_file_descriptor_nonblocking(file_descriptor: &OwnedFd) -> std::io::Result<()> {
    // SAFETY: `F_GETFL` takes no further argument and returns the current status flags.
    let current_flags = unsafe { libc::fcntl(file_descriptor.as_raw_fd(), libc::F_GETFL) };
    if current_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `F_SETFL` takes the new status flags as its argument.
    let result = unsafe {
        libc::fcntl(
            file_descriptor.as_raw_fd(),
            libc::F_SETFL,
            current_flags | libc::O_NONBLOCK,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Writes one complete Ethernet frame to a Berkeley Packet Filter device with `write(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `write(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn write_link_layer_frame(bpf_device: &OwnedFd, frame: &[u8]) -> std::io::Result<usize> {
    // SAFETY: `frame` is a valid readable slice; `write(2)` reads `frame.len()` bytes from it.
    let sent = unsafe {
        libc::write(
            bpf_device.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    usize::try_from(sent).map_err(|_| std::io::Error::other("write returned a negative byte count"))
}

/// Reads buffered Berkeley Packet Filter records into `buffer` with `read(2)`.
///
/// One read can return several `bpf_hdr`-prefixed records; de-aggregation happens in the endpoint.
///
/// # Errors
///
/// Returns the last operating system error when `read(2)` fails (including `EAGAIN` in non-blocking
/// mode).
///
/// # Panics
///
/// This function does not panic.
pub fn read_link_layer_frames(bpf_device: &OwnedFd, buffer: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: `buffer` is a valid writable slice; `read(2)` writes at most `buffer.len()` bytes.
    let received = unsafe {
        libc::read(
            bpf_device.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
        )
    };
    if received < 0 {
        return Err(std::io::Error::last_os_error());
    }
    usize::try_from(received)
        .map_err(|_| std::io::Error::other("read returned a negative byte count"))
}

/// Waits for readiness on `file_descriptor` using `poll(2)`.
///
/// # Errors
///
/// Returns the last operating system error when `poll(2)` fails.
///
/// # Panics
///
/// This function does not panic.
pub fn poll_readiness(
    file_descriptor: &OwnedFd,
    events: libc::c_short,
    timeout_milliseconds: libc::c_int,
) -> std::io::Result<libc::c_int> {
    let mut poll_file_descriptor = libc::pollfd {
        fd: file_descriptor.as_raw_fd(),
        events,
        revents: 0,
    };

    // SAFETY: `poll_file_descriptor` points to one valid `pollfd` for the duration of the call.
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

#[cfg(test)]
mod tests {
    use super::{read_ipv4_from_sockaddr, read_link_layer_address_from_sockaddr_dl};
    use std::mem::zeroed;
    use std::net::Ipv4Addr;

    #[test]
    fn reads_ipv4_from_sockaddr_in_fixture() {
        // Arrange
        let expected = Ipv4Addr::new(192, 168, 7, 42);
        let mut socket_address_internet: libc::sockaddr_in = unsafe { zeroed() };
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
        let outcome = read_ipv4_from_sockaddr(sockaddr_ref);

        // Assert
        assert_eq!(
            outcome,
            Some(expected),
            "fixture sockaddr_in should parse to its IPv4 octets"
        );
    }

    #[test]
    fn read_ipv4_from_sockaddr_returns_none_for_non_inet_family() {
        // Arrange
        let mut socket_address_internet: libc::sockaddr_in = unsafe { zeroed() };
        socket_address_internet.sin_family =
            libc::sa_family_t::try_from(libc::AF_LINK).expect("AF_LINK should fit sa_family_t");
        let sockaddr = std::ptr::from_ref(&socket_address_internet).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_in` for the lifetime of this test.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let outcome = read_ipv4_from_sockaddr(sockaddr_ref);

        // Assert
        assert_eq!(
            outcome, None,
            "non-AF_INET sockaddr should not yield an IPv4 address"
        );
    }

    #[test]
    fn reads_ethernet_address_from_sockaddr_dl_fixture() {
        // Arrange
        let expected = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let mut link_layer: libc::sockaddr_dl = unsafe { zeroed() };
        link_layer.sdl_family =
            u8::try_from(libc::AF_LINK).expect("AF_LINK should fit sockaddr_dl family");
        link_layer.sdl_type = crate::macos_packet::INTERFACE_TYPE_ETHERNET;
        // Name "en0" occupies the first three bytes of sdl_data; the address follows it.
        link_layer.sdl_nlen = 3;
        link_layer.sdl_alen = 6;
        link_layer.sdl_data[0] = b'e'.cast_signed();
        link_layer.sdl_data[1] = b'n'.cast_signed();
        link_layer.sdl_data[2] = b'0'.cast_signed();
        for (offset, octet) in expected.iter().enumerate() {
            link_layer.sdl_data[3 + offset] = octet.cast_signed();
        }
        let sockaddr = std::ptr::from_ref(&link_layer).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_dl` for the lifetime of this test, with
        // enough `sdl_data` bytes for the three-byte name and six-byte address.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let (interface_type, hardware_address) =
            read_link_layer_address_from_sockaddr_dl(sockaddr_ref);

        // Assert
        assert_eq!(
            interface_type,
            crate::macos_packet::INTERFACE_TYPE_ETHERNET,
            "fixture should report the Ethernet interface type"
        );
        assert_eq!(
            hardware_address,
            Some(expected),
            "Ethernet address should be read from sdl_data after the name bytes"
        );
    }

    #[test]
    fn read_link_layer_address_returns_none_when_address_length_is_not_six() {
        // Arrange
        let mut link_layer: libc::sockaddr_dl = unsafe { zeroed() };
        link_layer.sdl_family =
            u8::try_from(libc::AF_LINK).expect("AF_LINK should fit sockaddr_dl family");
        link_layer.sdl_type = crate::macos_packet::INTERFACE_TYPE_ETHERNET;
        link_layer.sdl_nlen = 3;
        link_layer.sdl_alen = 0;
        let sockaddr = std::ptr::from_ref(&link_layer).cast::<libc::sockaddr>();
        // SAFETY: `sockaddr` points to a valid `sockaddr_dl` for the lifetime of this test.
        let sockaddr_ref = unsafe { &*sockaddr };

        // Act
        let (_interface_type, hardware_address) =
            read_link_layer_address_from_sockaddr_dl(sockaddr_ref);

        // Assert
        assert_eq!(
            hardware_address, None,
            "a non-six-octet link-layer address should not be treated as Ethernet"
        );
    }

    #[test]
    fn ioctl_request_encoder_matches_libc_bioseesent() {
        // Arrange
        // `BIOCSSEESENT` is the one Berkeley Packet Filter request `libc` exposes on macOS; deriving
        // it with the encoder validates the `_IOW` encoding used for the other request codes.
        let encoded = super::encode_ioctl_request(super::IOCTL_DIRECTION_IN, b'B', 119, 4);

        // Act
        // Assert
        assert_eq!(
            encoded,
            libc::BIOCSSEESENT,
            "encoded _IOW('B', 119, u_int) should match libc::BIOCSSEESENT"
        );
    }

    #[test]
    fn bioc_setif_matches_documented_macos_value() {
        // Arrange
        let expected: libc::c_ulong = 0x8020_426c;

        // Act
        // Assert
        assert_eq!(
            std::mem::size_of::<libc::ifreq>(),
            32,
            "macOS ifreq should be 32 bytes for the BIOCSETIF size encoding"
        );
        assert_eq!(
            super::BIOCSETIF,
            expected,
            "BIOCSETIF should match the documented macOS request code 0x8020426c"
        );
    }

    #[test]
    fn open_bpf_device_returns_descriptor_or_permission_error() {
        // Act
        let outcome = super::open_bpf_device();

        // Assert
        match outcome {
            Ok(_device) => {
                // Running as root (or with BPF access): a device opened successfully.
            }
            Err(error) => {
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                    ),
                    "without privileges, opening a BPF device should fail with permission denied \
                     or exhaust the device range, got: {error:?}"
                );
            }
        }
    }

    #[test]
    fn collect_interface_address_records_succeeds_on_macos_host() {
        // Act
        let outcome = super::collect_interface_address_records();

        // Assert
        let records = outcome.expect("getifaddrs should succeed on macOS test hosts");
        for record in &records {
            assert!(
                !record.interface_name.is_empty(),
                "every record should carry a non-empty interface name, got: {record:?}"
            );
        }
    }
}
