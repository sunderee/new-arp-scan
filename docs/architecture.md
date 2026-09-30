# Architecture overview

This document helps **new contributors** navigate the crate layout, trust boundaries, and data flow. It complements [CONTRIBUTING.md](../CONTRIBUTING.md) (conventions) and [Linux platform](linux-platform.md) (kernel-facing details).

Tracked for release documentation: [GitHub issue #33](https://github.com/Bizjak-Tech-OU/new-arp-scan/issues/33).

---

## Module responsibilities (mental map)

| Area | Modules | Role |
|------|---------|------|
| **Entry** | `main.rs` | Parse arguments with `clap`, optional IEEE vendor file load, call `run()`, write [`ApplicationOutcome`](../src/application_outcome.rs) via [`write_operator_streams`](../src/application_outcome.rs) / [`write_operator_streams_with_mac_vendor_registry`](../src/application_outcome.rs), exit codes, print `AppError` on failure. |
| **Application surface** | `lib.rs`, `application_command.rs`, `application_outcome.rs` | Public `run(ApplicationCommand)` contract, outcomes, operator output layout, timing summary attachment after successful scans, and the passive monitor outcome. `ApplicationCommand` and `ApplicationOutcome` are `#[non_exhaustive]` as of 0.4.0. |
| **Operator parsing** | `cli.rs` | Command-line types and validation (delegated from `main.rs`). |
| **Errors** | `error.rs` | Single [`AppError`](../src/error.rs) enum; `Display` / `Error` for operators and tests. |
| **Pure IPv4 logic** | `ipv4_subnet.rs`, `ipv4_cidr.rs` | Subnet math and CIDR parsing; built on every target. |
| **Name / shape checks** | `interface_validation.rs` | Interface name rules and `ifreq` name packing helpers (shared by both backends). |
| **Link and ARP encoding** | `mac_address.rs`, `ethernet_frame.rs`, `address_resolution_protocol.rs` | Types and on-wire framing for Ethernet II + ARP; IEEE 802.1Q send (`--vlan`, `--pcp`, `--dei`) and receive; IEEE 802.1ad service tag send (`--svlan`, `--spcp`, `--sdei`) and receive; RFC 1042 SNAP send (`--llc`) and receive; RFC 5227 Probe/Announcement (`--arpspa`); Ethernet `--destaddr`/`--srcaddr`, remaining RFC 826 `ar$*` overrides, and `--padding`. |
| **IEEE MAC registries** | `mac_vendor_registry.rs`, `tools/mac-vendor-updater/` | Longest-prefix MA-L / MA-M / MA-S / IAB lookup from `ieee-oui.txt`. The updater fetches official CSVs with system `curl`, converts them, and atomically writes the mapping file. The scan crate never downloads. |
| **Portable link layer** | `link_layer_backend.rs`, `scanner.rs`, `monitor.rs`, `scan_timing.rs` | The `LinkLayerEndpoint` trait and shared interface/address value types; the backend-generic scan engine (target iteration, burst or strict inter-target scheduling, per-round receive on the rate-limited path, merge duplicate replies, warnings); the receive-only monitor engine (conflict, observation, and duplicate classification, bounded aggregation, checked deadline); checked bandwidth and backoff arithmetic with an injectable monotonic clock. |
| **Linux backend** | `linux_scanner.rs`, `linux_monitor.rs`, `linux_interface_discovery.rs`, `linux_socket.rs`, `linux_system_call.rs`, `linux_packet.rs` | `AF_PACKET` raw socket, `ioctl`/`if_nameindex` discovery, `getifaddrs(3)` for every IPv4 address on a monitor interface, `sockaddr_ll`, and the Linux scan and monitor entry points. |
| **macOS backend** | `macos_scanner.rs`, `macos_monitor.rs`, `macos_interface_discovery.rs`, `macos_bpf_socket.rs`, `macos_system_call.rs`, `macos_packet.rs` | Berkeley Packet Filter device (`/dev/bpf*`), `getifaddrs(3)` discovery, BPF ioctls/filter, and the macOS scan and monitor entry points. |

The pure logic, ARP/Ethernet encoders, portable boundary, scan engine, and monitor engine compile on **every** target. The Linux and macOS backend modules live behind `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]` in [`lib.rs`](../src/lib.rs). On operating systems without a backend, `run()` returns [`AppError::UnsupportedPlatform`](../src/error.rs) for scan, monitor, and list commands. A zero monitor timeout is [`AppError::MonitorTimeoutRejected`](../src/error.rs) before that platform check.

---

## `unsafe` boundaries

There is **no gratuitous `unsafe`**. It appears only where the language cannot express kernel **foreign function interface** contracts or **uninitialized structures** filled by `ioctl`.

Typical clusters:

- **`linux_system_call.rs`** — `libc` sockets, `ioctl`, `poll`, `if_nameindex` / `if_freenameindex`, `getifaddrs` / `freeifaddrs`, send/receive on file descriptors. Each block should carry a **`// SAFETY:`** comment per project rules.
- **`linux_interface_discovery.rs`**, **`linux_socket.rs`**, **`interface_validation.rs`** — `ifreq` and `sockaddr` manipulation, reading kernel-populated fields.
- **`linux_packet.rs`** — casting a known layout to `sockaddr_ll` for interpretation.
- **`macos_system_call.rs`** — all macOS `libc` calls (`getifaddrs`, `if_nametoindex`, BPF `ioctl`s, `read`/`write`/`poll`/`fcntl`) plus `sockaddr` / `sockaddr_dl` field reads. macOS `unsafe` is centralized here.
- **`macos_bpf_socket.rs`** — zeroed `ifreq` for `BIOCSETIF`; the BPF record de-aggregation itself is **safe** byte-slice arithmetic.

The portable `scanner.rs`, `monitor.rs`, and the pure encoders contain **no** `unsafe`. The monitor loop never sends.

**Rule of thumb:** treat new `unsafe` as a **last resort**, document invariants beside the block, and add a **DECISIONS.md** entry if the change is non-obvious.

---

## Packet flow (scan, simplified)

```text
CLI / library caller
       │
       ▼
  run() ──► resolve interface + discover addresses (linux_/macos_interface_discovery)
       │
       ▼
  open a LinkLayerEndpoint:
     Linux  → AF_PACKET SOCK_RAW bound to interface + ETH_P_ARP, or ETH_P_ALL when --vlan/--svlan/--llc is set
     macOS  → /dev/bpf* attached to interface + ARP / 802.1Q / 802.1ad / RFC 1042 SNAP filter (macos_bpf_socket)
       │
       ▼
  scanner (shared, backend-generic):
       ├──► Default: for each round, send every target immediately, sleep --pacing-ms between rounds,
       │    then one receive window of --timeout-ms
       ├──► Rate-limited (--bandwidth or --interval-ms): send still-unanswered targets with a strict
       │    minimum gap from the previous send completion (no catch-up), receive after that round for
       │    timeout * backoff^(round-1), drop answered targets, then wait until both the inter-send
       │    deadline and the receive window have passed before adding --pacing-ms
       └──► Receive loop (wait_until_readable + try_receive): parse Ethernet II + ARP;
            record opcode 2 replies; ignore well-formed non-reply ARP; warn on malformed frames
                 │
                 ▼
            Merge into DiscoveredHost map, collect warnings
       │
       ▼
  ScanOutcome (hosts + warnings; timing filled in run())
       │
       ▼
  write_operator_streams() → stdout / stderr (binary)
```

For field-level behavior, read module-level `//!` comments and the [operator docs](docs.html).

## Packet flow (monitor, simplified)

```text
CLI / library caller
       │
       ▼
  run() ──► reject a zero or unrepresentable timeout
       │
       ▼
  resolve interface + discover every configured IPv4 address and the interface MAC
       │
       ▼
  open a LinkLayerEndpoint and do not send:
     Linux  → AF_PACKET SOCK_RAW bound to ETH_P_ALL (outermost VLAN tag still stripped by the kernel)
     macOS  → existing /dev/bpf* opener; BIOCSSEESENT stays off
       │
       ▼
  monitor.rs:
       re-check the monotonic deadline before every read
       parse with the scan codecs
       suppress local SHA+SPA
       label request/reply local-SPA foreign-SHA as conflict
       label other well-formed ARP as observed
       label a nonzero nonlocal SPA claimed by two or more SHAs as duplicate-ip
       cap distinct packet records at 4,096
       │
       ▼
  MonitorOutcome
       │
       ▼
  write_operator_streams() → stdout lines, stderr warnings and completion summary
```

`monitor` does not call the scan engine and does not load the IEEE vendor registry.

---

## Testing strategy

| Layer | Location | Purpose |
|-------|----------|---------|
| **Unit** | `#[cfg(test)]` at bottom of each `src/*.rs`, plus [`src/protocol_conformance.rs`](../src/protocol_conformance.rs) | Default: fast, hermetic, covers parsing, math, error `Display`, RFC/IEEE packet contracts, and most Linux helpers that do not need raw ARP on the wire. |
| **Integration** | `tests/*.rs` | Subprocess CLI (`CARGO_BIN_EXE_*`) and public `run()` behavior across platforms. |
| **Doc tests** | ` ``` ` blocks on public API | Compile-checked examples (`cargo test` includes them). |

**Conventions** (see also [CONTRIBUTING.md](../CONTRIBUTING.md) and `.cursor/rules/testing.mdc` if present):

- Arrange / Act / Assert with blank lines.
- Test names are full **snake_case sentences**.
- Prefer matching **specific** `Err` variants over `is_err()` alone.
- Avoid external network dependencies; prefer fixtures and controlled syscalls. The IEEE updater is tested from CSV fixtures (`--from-dir`); CI never fetches IEEE listings.

Privileged **full-subnet** scans are validated manually (for example with `tcpdump`); automating them in CI would require a dedicated harness or namespace setup (see [Linux platform](linux-platform.md)).

---

## Where to change what

| Goal | Start here |
|------|----------------|
| New CLI flag | `cli.rs`, `application_command.rs`, `main.rs` dispatch only |
| New scan semantics (both platforms) | `scanner.rs`, possibly `ipv4_subnet.rs` |
| Passive monitor classification | `monitor.rs`; platform openers stay in `linux_monitor.rs` / `macos_monitor.rs` |
| New operator output | `application_outcome.rs` (`write_operator_streams`, formatting) |
| New `AppError` variant | `error.rs`, then every `Display` / `source` path and matching tests |
| New syscall wrapper | `linux_system_call.rs` (Linux) or `macos_system_call.rs` (macOS) |
| New link-layer backend operation | `link_layer_backend.rs` trait, then each backend endpoint |
| New IEEE OUI snapshot | `make update-mac-vendors` (`tools/mac-vendor-updater`); do not fetch from `scan` |

When in doubt, open a small pull request and point reviewers to this file for orientation.
