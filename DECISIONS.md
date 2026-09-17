# Decisions

Lightweight records of architectural choices. Each entry follows the same shape.

## 2026-05-10 — License: GNU Affero General Public License v3.0 only

**Decision:** Ship the project under `AGPL-3.0-only` (see `LICENSE` and `Cargo.toml`).

**Reason:** Network-facing tooling should preserve user freedom when deployed as a service; the Affero variant closes the “application service provider” loophole compared to the plain GNU General Public License. `AGPL-3.0-only` avoids implicitly licensing future Affero versions.

**Consequences:** Derivatives and hosted deployments must comply with Affero terms; compatibility reviews are required before linking with differently licensed code.

## 2026-05-10 — No dependencies until `std` is insufficient

**Decision:** Keep the crate free of external dependencies during bootstrap; remove unused crates rather than carrying speculative links.

**Reason:** Dependencies increase audit surface and build complexity. This entry described the earliest bootstrap; once Linux packet work landed, `libc` became required again (see the `libc` entry below).

**Consequences:** Any future crate addition must come with a fresh `DECISIONS.md` entry and clear justification.

## 2026-05-10 — Strict warnings and Clippy pedantic via Cargo lints

**Decision:** Configure `[lints.rust]` with warnings denied and `unsafe_op_in_unsafe_fn` denied; enable Clippy `pedantic` at warning level in `Cargo.toml`, and run `cargo fmt --all` followed by `cargo clippy --all-targets -- -D warnings` in local and continuous integration workflows (`Makefile` target `lint`).

**Reason:** Treat warnings as errors early so regressions do not accumulate; pedantic catches foot-guns consistent with project review standards.

**Consequences:** New pedantic findings block merges until addressed or explicitly documented with a rare, justified allowance.

## 2026-05-11 — `libc` for Linux packet sockets and ioctl

**Decision:** Add the `libc` crate for Linux `AF_PACKET` raw sockets, `bind(2)`, `ioctl(2)` (including `SIOCGIFFLAGS`, `SIOCGIFADDR`, `SIOCGIFNETMASK`, `SIOCGIFHWADDR`), `if_nametoindex(3)`, `if_nameindex(3)` / `if_freenameindex(3)`, `sendto(2)`, `recvfrom(2)`, `poll(2)`, and authoritative C layout types used to validate our `sockaddr_ll` mirror.

**Reason:** The standard library does not expose these system calls, socket options, or kernel ABI structures. Maintaining raw `extern "C"` declarations for the full surface would duplicate `libc`’s audited bindings without benefit.

**Consequences:** Dependency audits must include `libc` upgrades; Linux-only code paths rely on `libc` for foreign-function-interface correctness.

## 2026-05-13 — Isolated Linux syscall module and raw ARP scan path

**Decision:** Route Linux system calls through [`src/linux_system_call.rs`](src/linux_system_call.rs); keep descriptor lifetime management on `std::os::fd::OwnedFd` (drop closes the socket); implement Ethernet II framing in [`src/ethernet_frame.rs`](src/ethernet_frame.rs), IPv4 ARP over Ethernet in [`src/address_resolution_protocol.rs`](src/address_resolution_protocol.rs), and media access control addresses in [`src/mac_address.rs`](src/mac_address.rs); orchestrate subnet scanning in [`src/linux_scanner.rs`](src/linux_scanner.rs); return [`ApplicationOutcome`](src/application_outcome.rs) from [`run`](src/lib.rs) with warnings carried in [`ScanOutcome`](src/application_outcome.rs) for the binary to print to standard error.

**Reason:** GitHub issues #21 (syscall surface), #6 (transmit), and #7 (receive/parse) require a single audited foreign-function-interface boundary, wire-visible frames without unsafe serialization tricks, and testable pure parsing logic. Automated tests avoid requiring `CAP_NET_RAW`; live tcpdump or Wireshark checks stay manual.

**Consequences:** Linux-only unit tests cover frame layout and non-privileged syscall smoke checks; full scan behavior is validated on Linux hosts with appropriate privileges outside `cargo test` unless CI is later equipped for it.

## 2026-05-14 — Packet layer modules (`MacAddress`, Ethernet II, ARP)

**Decision:** Split former `ethernet_arp.rs` into `src/mac_address.rs` (public `MacAddress`), `src/ethernet_frame.rs` (Ethernet II encode/decode), and `src/address_resolution_protocol.rs` (IPv4 ARP over Ethernet); keep 60-octet minimum transmit frames for ARP requests; reject outer VLAN-tagged Ethernet before ARP interpretation.

**Reason:** Milestone issues #8–#11 and #22 call for explicit boundaries, defensive parsing, and a typed MAC address on public scan results without changing on-wire scan behavior.

**Consequences:** Library consumers use `MacAddress` and `DiscoveredHost::media_access_control_address`; future link-layer features extend the frame module first.

## 2026-05-11 — `clap` with derive for the `scan` subcommand

**Decision:** Add `clap` with the derive feature for `new-arp-scan scan --interface <name>`, layered `--help`, and examples.

**Reason:** The project explicitly approved a parser dependency over hand-rolled `std::env::args` parsing for this milestone. Derive macros keep the command surface typed and documented next to the definitions.

**Consequences:** Any future CLI expansion should extend the derive structs/enums and keep `main.rs` limited to parsing and dispatch.

## 2026-05-15 — Linux interface enumeration via `if_nameindex(3)` plus ioctl

**Decision:** Enumerate local interface names and indexes with `if_nameindex(3)` / `if_freenameindex(3)` (wrapped in [`src/linux_system_call.rs`](src/linux_system_call.rs)), then reuse existing `ioctl` reads for flags, IPv4 address, netmask, and hardware address when classifying usable ARP scan interfaces. Centralize copying an interface name into `struct ifreq` in [`src/interface_validation.rs`](src/interface_validation.rs) (Linux-only helper) for [`SIOCGIFFLAGS`](src/linux_system_call.rs) and related requests.

**Reason:** `if_nameindex(3)` is the documented portable way to list `(if_index, name)` pairs without rtnetlink complexity; `netdevice(7)` continues to document the ioctl surface already used for per-interface discovery. Sharing `ifreq` name population avoids duplicated length checks across modules.

**Consequences:** Listing and automatic interface selection share the same filtering rules as explicit scans; `libc` remains the only foreign-function-interface dependency for these calls.

## 2026-05-15 — Ungate pure IPv4 helpers for cross-platform unit tests

**Decision:** Compile [`src/ipv4_subnet.rs`](src/ipv4_subnet.rs) and [`src/ipv4_cidr.rs`](src/ipv4_cidr.rs) on every target; keep Linux-only modules (`linux_scanner`, raw sockets, and so on) behind `#[cfg(target_os = "linux")]`.

**Reason:** Subnet and classless inter-domain routing parsing are pure standard-library logic with no `libc` dependency; building them on non-Linux hosts lets `cargo test` validate traversal and parse edge cases in continuous integration without packet sockets.

**Consequences:** Public re-exports [`Ipv4Cidr`](src/ipv4_cidr.rs) and [`Ipv4HostAddressIterator`](src/ipv4_cidr.rs) document iterator-based expansion for library callers; the live scan path uses the same iterator as the tests.

## 2026-05-15 — Clippy: `cast_possible_truncation` after bounded CIDR prefix parse

**Decision:** Allow `clippy::cast_possible_truncation` when converting the parsed decimal `u32` prefix to `u8` immediately after rejecting values greater than `32`.

**Reason:** The guard makes truncation impossible; a `u8::try_from` error branch was logically unreachable and obscured the real control flow.

**Consequences:** If the accepted prefix range ever widens beyond what fits in `u8`, this site must be revisited together with the parser.

## 2026-05-17 — Configurable scan receive window and inter-target pacing

**Decision:** Extend [`ApplicationCommand::Scan`](src/application_command.rs) with `std::time::Duration` fields `timeout` and `pacing`, public defaults [`DEFAULT_SCAN_TIMEOUT`](src/application_command.rs) and [`DEFAULT_SCAN_PACING`](src/application_command.rs), and CLI flags `--timeout-ms` / `--pacing-ms`. The Linux scanner keeps a global receive phase after the last send while pacing only between sends; millisecond spans passed to `poll(2)` clamp to [`libc::c_int::MAX`](https://man7.org/linux/man-pages/man2/poll.2.html) when they do not fit the system call parameter type.

**Reason:** GitHub issue #14 requires configurable timeout and pacing without abandoning the existing burst-send plus single receive-window model operators already rely on.

**Consequences:** Library callers must supply explicit `Duration` values or the defaults; documentation and static site pages describe the new flags. Hermetic unit tests cover poll clamping, target ordering with the optional self-probe, and pacing gating without live sockets.

## 2026-05-18 — Scan rounds, inter-round pacing, attempts, and duplicate reply warnings

**Decision:** Extend [`ApplicationCommand::Scan`](src/application_command.rs) with `attempts: std::num::NonZeroU64` and public [`DEFAULT_SCAN_ATTEMPTS`](src/application_command.rs). Add CLI `--attempts` (minimum `1`, total scan rounds). Repurpose `--pacing-ms` to mean delay after each full round of target sends except the last round; keep `--timeout-ms` as the receive window after the final round. Implement round iteration in [`perform_arp_scan`](src/linux_scanner.rs). On conflicting address resolution replies for the same IPv4, keep the first media access control address and emit one warning per later conflicting reply.

**Reason:** Operators need optional retransmission across the subnet without per-target pacing; total rounds with inter-round pacing matches the agreed product behavior. Duplicate-safe merging avoids unstable output when multiple replies disagree.

**Consequences:** The 2026-05-17 “inter-target pacing” semantics are superseded: pacing is now strictly between rounds. Library callers pass `NonZeroU64` for `attempts` (or `DEFAULT_SCAN_ATTEMPTS`). README and static docs describe rounds, attempts, and conflict warnings.

## 2026-05-26 — Single-target ARP scan (`--host`) and `perform_arp_probe`

**Decision:** Add optional CLI `--host <IPv4>` on `scan`, optional `target_ipv4_address: Option<std::net::Ipv4Addr>` on [`ApplicationCommand::Scan`](src/application_command.rs), and public [`perform_arp_probe`](src/linux_scanner.rs) on Linux (re-exported from the crate root). Refactor [`linux_scanner`](src/linux_scanner.rs) so subnet scans and probes share send and receive scheduling, with separate reply filtering for subnet-wide versus exact-target modes. Validate targets with [`validate_strict_interior_scan_target_ipv4_address`](src/ipv4_subnet.rs); reject invalid targets with [`AppError::SingleScanTargetRejected`](src/error.rs) before opening the raw socket. Keep “no hosts found”, exit success, and stderr warnings aligned with full-subnet scans when the probe times out.

**Reason:** GitHub issue #24 requires an end-to-end single-address flow without duplicating packet logic; strict-interior validation matches full-scan interior rules and avoids ambiguous probes of network or broadcast addresses.

**Consequences:** Operators and library callers can probe one interior host with the same `--timeout-ms`, `--pacing-ms`, and `--attempts` semantics as subnet scans. README, static docs, and CLI examples describe `--host` and the new error variant.

## 2026-06-03 — macOS packet I/O strategy: direct BPF via `libc` and a portable link-layer backend

**Decision:** Add first-class macOS support for `scan` and `interfaces` using **direct Berkeley Packet Filter (BPF) access through `libc`**, not `libpcap`. Open a `/dev/bpf*` cloning device, attach it to a named interface with `BIOCSETIF`, and `read(2)` / `write(2)` complete Ethernet II frames. Reuse the existing Ethernet/ARP encoders ([`src/ethernet_frame.rs`](src/ethernet_frame.rs), [`src/address_resolution_protocol.rs`](src/address_resolution_protocol.rs)) and `MacAddress` ([`src/mac_address.rs`](src/mac_address.rs)) unchanged.

Introduce a **narrow portable link-layer boundary** that both Linux and macOS implement, so scan scheduling and ARP framing never branch on `AF_PACKET` versus BPF. The boundary exposes exactly four capabilities:

1. **Interface discovery** — enumerate usable ARP scan candidates and discover one interface's `(name, index, IPv4, netmask, MAC, usability flags)`. Produces the shared `InterfaceScanAddresses` / `ArpScanInterfaceCandidate` value types.
2. **Open a bound link-layer endpoint** — a handle attached to one interface for Ethernet II ARP frames, owning the underlying descriptor (`OwnedFd`, closed on drop).
3. **Send one Ethernet II frame** — the frame already carries its broadcast destination MAC; the backend hides any address structure (`sockaddr_ll` on Linux, plain `write` on BPF).
4. **Wait for readiness, then receive frames** — a `poll(2)`/`select(2)` readiness primitive plus a non-blocking frame read compatible with the shared scanner's deadline model. The macOS backend de-aggregates the multiple `BIOCGBLEN`-sized, `bpf_hdr`-prefixed, `BPF_WORDALIGN`-padded frames returned by a single BPF `read(2)` behind this primitive, so callers still observe one Ethernet frame at a time.

**Module and `cfg` plan:**

- **Shared, ungated, no FFI:** `ipv4_subnet`, `ipv4_cidr`, `mac_address`, `ethernet_frame`, `address_resolution_protocol`, the portable scan orchestration (target expansion, rounds/pacing/attempts, duplicate-reply merge, reply acceptance), and the cross-platform parts of `interface_validation`. The Ethernet/ARP modules are currently `#[cfg(target_os = "linux")]` only because the scanner is; they move behind the portable boundary so they compile on every target (#52, #55).
- **Linux backend (`#[cfg(target_os = "linux")]`):** existing `linux_socket`, `linux_interface_discovery`, `linux_system_call`, `linux_packet` retain their `linux_*` names and remain the only place `AF_PACKET`, `sockaddr_ll`, and `ioctl`-based discovery live.
- **macOS backend (`#[cfg(target_os = "macos")]`):** new sibling modules `macos_bpf_socket`, `macos_interface_discovery`, `macos_system_call`, `macos_packet`, mirroring the Linux split. All macOS `unsafe` is centralized in `macos_system_call` with `// SAFETY:` blocks, exactly as `linux_system_call` does for Linux (#21, #28).

**Privilege model:** macOS BPF devices require **root** (no special entitlement is assumed for this CLI). Opening or attaching a BPF device without privilege fails with `EACCES`/`EPERM`; that is surfaced as an operator-actionable "run with sudo" error, parallel to the Linux `CAP_NET_RAW` path (#31, #57). `/dev/bpf*` exhaustion (`EBUSY`) is handled by probing successive cloning minor devices.

**Reason:** The constitution's prime directive is to reach for `std`/`libc` before any external crate, and `libc` is already the sole FFI dependency for the Linux `AF_PACKET` path; direct BPF keeps macOS symmetric with Linux and adds no new dependency. The post-MVP backlog (#35) explicitly lists `libpcap` as a *future, optional* backend, so adopting it now would contradict a recorded scope decision and widen the audit surface for marginal convenience. A trait-style boundary (the constitution favors traits for behavior contracts) keeps the substantial, well-tested scan scheduling and ARP framing logic platform-neutral; only descriptor acquisition and raw send/receive differ per OS. The extra `unsafe` cost of hand-written BPF is bounded by the existing centralized-syscall pattern.

**Consequences:** Implementation proceeds as the macOS tracking issue (#60) breakdown: extract the portable backend (#52), macOS interface enumeration (#53), macOS BPF send/receive (#54), shared scan orchestration (#55), wire macOS into `run()` and fix macOS release builds (#56), macOS privilege diagnostics (#57), macOS CI job (#58), and macOS platform docs (#59). `libc` remains the only FFI dependency. Explicitly **deferred** to the post-MVP backlog (#35): the optional `libpcap` backend, Homebrew distribution / signed binaries, and passive monitor mode / VLAN handling. New macOS `unsafe` follows the documented `// SAFETY:` discipline; the BPF frame-aggregation parser is covered by hermetic unit tests over fixture buffers, while privileged live scans stay manual (same philosophy as Linux).

## 2026-05-26 — Scan timing summary on standard error and minimal exit codes

**Decision:** After a successful Linux `scan`, populate [`ScanOutcome::timing_summary`](src/application_outcome.rs) in [`run`](src/lib.rs) and have the binary print one stable standard-error line via [`ScanTimingSummary::format_stderr_timing_summary_line`](src/application_outcome.rs) after standard output. Document a minimal exit contract: `0` success (including empty results and help-only paths), `1` any [`AppError`](src/error.rs) from [`run`](src/lib.rs), `2` command-line parse or usage errors from `clap` (`error.exit()`). Do not assign distinct exit codes per [`AppError`](src/error.rs) variant (for example capability versus interface rejection).

**Reason:** Milestone issues #18–#19 call for readable timing context and deterministic operator-visible exit semantics without expanding the error surface into sysexits-style matrices.

**Consequences:** README and [`docs/docs.html`](docs/docs.html) describe the timing line template and exit table; integration tests assert parse failures exit `2` where the toolchain maps `clap` usage errors to that code.

## 2026-08-15 — RFC and IEEE packet fidelity, 802.1Q receive, IEEE MAC registries

**Decision:** Treat the on-wire Ethernet/ARP codecs as a standards contract, not a best-effort layout:

- **RFC 826:** keep transmitting Ethernet II ARP requests with `ar$hrd=1`, `ar$pro=0x0800`, `ar$hln=6`, `ar$pln=4`, `ar$op=1`, `ar$tha=0`, interface `ar$sha`/`ar$spa`, and target `ar$tpa`. Record replies from `ar$spa`/`ar$sha` (not the Ethernet source, which may differ).
- **RFC 5227:** add explicit ARP Probe (`ar$spa=0.0.0.0`) and ARP Announcement (`ar$spa=ar$tpa`) builders covered by tests. Default `scan` / `--host` remain RFC 826 requests using the interface IPv4 address (the same default as original `arp-scan`). `perform_arp_probe` keeps meaning “single-target scan”, not an RFC 5227 Probe.
- **RFC 5494:** reject reserved `ar$hrd` and `ar$op` values 0 and 65535 on receive.
- **IEEE 802.3:** pad transmitted ARP to 60 octets without FCS (46-octet MAC client data, 18 zero pad bytes). Parse length/type as a length when `<= 1500`, as an EtherType when `>= 1536`, and reject the undefined gap. Accept RFC 1042 LLC/SNAP ARP on receive.
- **IEEE 802.1Q:** decode a single customer VLAN tag on receive (VID is the low 12 TCI bits) and accept the inner ARP payload. Reject IEEE 802.1ad / unofficial QinQ TPIDs and stacked 0x8100 tags so the inner EtherType is never read from the wrong offset. Transmit stays untagged Ethernet II. macOS BPF now accepts both untagged ARP and 0x8100-tagged ARP. Linux `ETH_P_ARP` still relies on kernel VLAN tag stripping for tagged frames on the parent interface.
- **IEEE MA-L / MA-M / MA-S:** add [`MacVendorRegistry`](src/mac_vendor_registry.rs) with longest-prefix match over `arp-scan` `ieee-oui.txt` text (6 / 7 / 9 hex digits). CLI `--mac-vendor-file` loads an explicit file; `ieee-oui.txt` in the current directory is used when present. Host lines become `<IPv4> <MAC> <vendor>` only when a registry is loaded.

**Reason:** The core product is an ARP scanner. Silent misparse of 802.3 lengths, stacked VLAN TPIDs, and reserved ARP fields, plus no IEEE registry lookup, made the tool unverifiable against the RFCs/IEEE documents and weaker than original `arp-scan` on receive-side 802.1Q and vendor identification.

**Consequences:** Spec-facing tests live in [`src/protocol_conformance.rs`](src/protocol_conformance.rs) and the packet modules. Send-side `--vlan` (superseded below), LLC/SNAP transmit and RFC 5227 Probe as CLI (superseded further below), bundling a full IEEE database, passive ACD / monitor mode, and `libpcap` were still deferred at that time. Operators who want vendor names generate or copy an `ieee-oui.txt` (for example with original `arp-scan`'s `get-oui`).

## 2026-08-15 — IEEE 802.1Q send-side `--vlan` and Linux tagged capture

**Decision:** Operators can tag transmitted ARP requests with a single IEEE 802.1Q customer tag via `scan --vlan <VID>` (`0..=4095`, PCP and DEI zero). The request is still RFC 826 Ethernet II ARP padded to 60 octets without the frame check sequence (IEEE 802.3 / 802.3ac `ETH_ZLEN` behaviour, matching original `arp-scan --vlan`). On Linux, a VLAN scan opens `AF_PACKET` with `ETH_P_ALL` so replies may arrive tagged (`0x8100`) or with the tag stripped; non-ARP frames are ignored without malformed-frame warnings. Untagged scans keep `ETH_P_ARP`. macOS already captured tagged ARP via BPF; it now also transmits the tag when `--vlan` is set.

**Reason:** Receive-side 802.1Q parsing without a send path could not be claimed as IEEE 802.1Q fidelity, and Linux `ETH_P_ARP` silently dropped tagged replies on trunks that do not strip tags.

**Consequences:** LLC/SNAP transmit and RFC 5227 Probe as a CLI mode are superseded below. QinQ / IEEE 802.1ad, bundling a full IEEE database, passive ACD / monitor mode, and `libpcap` remain deferred. VID `4095` is reserved in IEEE 802.1Q but is accepted as a 12-bit TCI field, same as original `arp-scan`.

## 2026-08-15 — RFC 5227 `--arpspa` and RFC 1042 `--llc` transmit

**Decision:** Operators can override RFC 826 `ar$spa` and IEEE 802.3 framing on `scan`:

- **`--arpspa <IPv4|dest>`** matches original `arp-scan`. Omitted uses the interface IPv4 address (RFC 826 default). `0.0.0.0` is an RFC 5227 ARP Probe. `dest` (case-insensitive) is an RFC 5227 ARP Announcement (`ar$spa` equals each target `ar$tpa`). Any other dotted quad is a sender-protocol override. `--host` remains a single-target scan of one interior IPv4 address; it does not imply Probe semantics. Reply acceptance still uses the **interface** subnet (or the `--host` address), not the overridden SPA.
- **`--llc`** transmits IEEE 802.3 with RFC 1042 LLC/SNAP (`AA AA 03`, OUI `00:00:00`, EtherType `0x0806`) instead of Ethernet II. The IEEE 802.3 length field is LLC + SNAP + ARP payload (**36** for IPv4 ARP), which is the MAC client data after the length field. That is **not** original `arp-scan`'s `packet_size+8` formula when `packet_size` already includes Ethernet header octets. Frames are still zero-padded to 60 octets without FCS. Replies are decoded in Ethernet II, 802.1Q, or SNAP regardless of `--llc`. `--vlan` and `--llc` may be combined (TPID, then length, then SNAP).
- Linux opens `ETH_P_ALL` when `--vlan` **or** `--llc` is set so length-field SNAP and tagged replies are not dropped; untagged Ethernet II scans keep `ETH_P_ARP`. Untagged SNAP send uses `sockaddr_ll` protocol `ETH_P_802_2`; tagged send keeps `0x8100`.
- macOS BPF capture expands to Ethernet II ARP, one 802.1Q tag, RFC 1042 SNAP, and 802.1Q+SNAP. The previous 7-instruction filter dropped IEEE 802.3 SNAP because a length of 36 is neither `0x0806` nor `0x8100`.

Wire options are grouped in [`ScanWireOptions`](src/application_command.rs) on [`ApplicationCommand::Scan`](src/application_command.rs) so Linux/macOS scanners and the shared send path take one value instead of growing argument lists.

**Reason:** Library Probe/Announcement builders and SNAP receive without CLI transmit could not be claimed as RFC 5227 / RFC 1042 fidelity. Original `arp-scan` exposes `--arpspa` and `--llc`; sending SNAP with a standards-correct length avoids copying a known length-field bug.

**Consequences:** QinQ / IEEE 802.1ad (still rejected on receive), bundling a full IEEE OUI database, passive ACD / monitor mode, `libpcap`, custom `--padding`, and `--prototype` remain deferred. Default `scan` / `--host` stay RFC 826 Ethernet II with interface SPA. Ethernet destination/source and remaining `ar$*` overrides are superseded below.

## 2026-08-15 — RFC 826 / arp-scan Ethernet and ARP field overrides

**Decision:** Operators can override the remaining original `arp-scan` outgoing packet fields on `scan`, matching that tool's long option names:

- **Ethernet:** `--destaddr` (default broadcast), `--srcaddr` (default interface MAC). `--prototype` is not implemented: the SNAP/`EtherType` stays ARP (`0x0806`) so replies remain in the capture path.
- **RFC 826 ARP:** `--arphrd` (default 1), `--arppro` (default `0x0800`), `--arphln` (default 6), `--arppln` (default 4), `--arpop` (default 1), `--arpsha` (default interface MAC), `--arptha` (default zeroes). `--arpspa` was already present. Numeric flags accept decimal or `0x`-prefixed hexadecimal. `--arphln` / `--arppln` change only the advertised length octets; SHA/THA stay 6 bytes and SPA/TPA stay 4 bytes, as in original `arp-scan`.
- **`--srcaddr` vs `--arpsha`:** these are independent, matching RFC 826 (Ethernet source may differ from `ar$sha`; receive already records `ar$sha`).
- Transmit of RFC 5494 reserved `ar$hrd` / `ar$op` values 0 and 65535 is allowed (original `arp-scan` permits any 16-bit value). Receive still rejects those reserved values.

Resolved fields are encoded through [`AddressResolutionRequestLayout`](src/address_resolution_protocol.rs) so the scanner does not grow an argument list.

**Reason:** `--vlan`, `--llc`, and `--arpspa` left Ethernet addressing and the rest of the RFC 826 header fixed. Original `arp-scan` documents `--destaddr` as the commonly used Ethernet override, and treating `ar$sha` as distinct from the Ethernet source completes the receive-side RFC 826 contract on transmit.

**Consequences:** QinQ / IEEE 802.1ad, bundling a full IEEE OUI database, passive ACD / monitor mode, `libpcap`, JSON output, adaptive pacing, and `--prototype` remain deferred. Custom `--padding` and IEEE 802.1Q PCP/DEI are superseded below.

## 2026-08-15 — `--padding` and IEEE 802.1Q PCP/DEI

**Decision:** Operators can complete the remaining original `arp-scan` outgoing packet option and the rest of the IEEE 802.1Q TCI on `scan`:

- **`--padding <HEX>`** matches original `arp-scan`: hex-encoded binary with an even number of digits and **no** `0x` prefix, appended after the 28-octet ARP PDU. The Ethernet frame is still zero-padded to 60 octets without FCS when shorter. With `--llc`, custom padding is included in the IEEE 802.3 length (MAC client data = LLC + SNAP + ARP + padding). Padding that would make MAC client data exceed 1500 octets is rejected (Ethernet II maximum 1472 padding octets; SNAP maximum 1464). Oversize payloads are not silently truncated.
- **`--pcp <0..=7>`** and **`--dei`** require `--vlan`. They encode the IEEE 802.1Q TCI as `(PCP << 13) | (DEI << 12) | VID`. Omitted PCP is 0 and omitted DEI is 0, matching the previous VID-only send. VID 0 remains legal (priority tagging). Receive-side TCI decoding is superseded below.

**Reason:** `--vlan` left PCP and DEI stuck at zero, so tagged frames could not express IEEE 802.1Q class of service. Custom `--padding` was the last original `arp-scan` outgoing packet option that still needed a `Vec` encode path once the 60-octet buffer was no longer a hard ceiling.

**Consequences:** QinQ / IEEE 802.1ad (still rejected on receive), bundling a full IEEE OUI database, passive ACD / monitor mode, `libpcap`, JSON output, adaptive pacing, and `--prototype` remain deferred. Default `scan` / `--host` stay RFC 826 Ethernet II with interface SPA, PCP 0, DEI 0, and no custom padding.

## 2026-08-15 — Non-reply ARP is not malformed; receive decodes 802.1Q PCP/DEI

**Decision:** Scan receive treats well-formed IPv4-over-Ethernet ARP that is not opcode 2 as LAN noise, not a parse failure, and Ethernet receive exposes the full IEEE 802.1Q TCI:

- A crate-internal parser accepts any non-reserved RFC 826 opcode. The scanner records opcode 2 (`ares_op$REPLY`) only. Requests, RARP, and other well-formed opcodes are ignored without a `warning: received malformed Ethernet/ARP frame` line, matching original `arp-scan`. The public reply parser still rejects non-replies so library callers that asked for a reply keep that contract. RFC 5494 reserved `ar$op` values 0 and 65535 still warn as malformed.
- `try_parse_ethernet_frame` now returns PCP, DEI, and VID for a single customer tag (TCI `0xF044` is PCP 7, DEI 1, VID `0x044`). `vlan_identifier` remains the low 12 bits for existing tests.

**Reason:** Calling the reply parser on every ARP frame turned RFC 826 requests — including possible copies of our own transmitted requests — into operator-facing malformation warnings. Send-side `--pcp` / `--dei` without receive TCI decode left IEEE 802.1Q incomplete on the inbound path.

**Consequences:** Inbound requests are not recorded as discovered hosts (a self-echo would map every target to the scanning MAC). Full RFC 5227 conflict-from-request / passive ACD remains deferred, as do QinQ / IEEE 802.1ad receive, bundled IEEE OUI data, `libpcap`, JSON output, adaptive pacing, and `--prototype`.

## 2026-08-29 — IEEE 802.1ad service tag: `--svlan` send and S-TAG/C-TAG receive

**Decision:** `scan` transmits and decodes **exactly one** IEEE 802.1Q service tag wrapping **exactly one** customer tag — the IEEE 802.1ad Provider Bridge model later incorporated into IEEE 802.1Q. Nothing deeper, and no vendor variants.

- **Wire contract.** Outer **S-TAG** TPID `0x88A8` (IANA IEEE 802 Numbers decimal 34984, "IEEE Std 802.1Q - Service VLAN tag identifier (S-Tag)"; `ETH_P_8021AD` in `linux/if_ether.h`), then its 16-bit TCI, then inner **C-TAG** TPID `0x8100` (decimal 33024, registry reference RFC 9542), then its TCI, then the payload protocol — an Ethernet II `EtherType` or an IEEE 802.3 length introducing RFC 1042 LLC/SNAP. Each TCI is `(PCP << 13) | (DEI << 12) | VID`. VLAN tags precede the IEEE 802.3 length field, so they are never counted in it.
- **Receive** exposes both full TCIs in the parser (Linux platform delivery differs; see **Platforms**). `ParsedEthernetFrame` gains `service_vlan_tag`; `vlan_tag` and `vlan_identifier` keep meaning the **customer** tag, so existing callers are unaffected. Rejected, each with its own stable message: a lone S-TAG (never silently read as untagged ARP), a tag stacked inside a C-TAG (vendor double-`0x8100` QinQ, and the reverse C-then-S order), a third tag after a legal pair, truncated S-TAG or C-TAG headers, and the unofficial TPIDs `0x9100` / `0x9200` / `0x9300` (`linux/if_ether.h` marks all three "NOT AN OFFICIALLY REGISTERED ID"). An unsupported arrangement is unparseable Ethernet, which the scanner already treats as capture noise rather than a malformed-frame warning; a well-formed QinQ ARP request stays LAN noise, and a QinQ reply is recorded exactly like a single-tag one.
- **Transmit.** `--svlan <VID>` (`0..=4095`) requires `--vlan` and inserts the outer tag; `--spcp <0..=7>` and `--sdei` require `--svlan`. Omitted service PCP/DEI are 0, matching the customer-tag defaults. clap `requires` makes the bad combinations a usage error (exit 2). `--padding` and `--llc` remain valid on top of the stacked tags, and frames still zero-pad to the 60-octet IEEE 802.3 minimum without FCS.
- **Illegal states.** An internal `Ieee8021qTagStack` enum (`Customer` / `ServiceAndCustomer`) is what the encoders and `AddressResolutionRequestLayout` carry, so a service tag with no customer tag cannot be encoded. `ScanWireOptions` keeps flat public fields for CLI symmetry and rejects the combination in `validate_ieee_8021q_tag_stack` with `AppError::ServiceVlanTagRequiresCustomerVlanTag`, next to the existing MAC client data check. The encoder writes `Ieee8021qTagStack::outer_tag_protocol_identifier()` as its first TPID, which is the same value Linux puts in `sockaddr_ll`, so the octets on the wire and the send protocol cannot drift apart.
- **Platforms.** Linux binds `ETH_P_ALL` whenever any tagging or SNAP is requested, and sends a service-tagged frame with the outer TPID `0x88A8` (as a single customer tag already sends `0x8100`). On Linux receive, the kernel always moves the outermost tag into skb metadata before `AF_PACKET` delivery (`skb_vlan_untag()`, Linux 3.16, commit `0d5501c1c828`), so a QinQ reply is observed leading with its inner C-TAG and is recorded like a single-tag reply; the service TCI of received frames would only be recoverable via `PACKET_AUXDATA`, which is not yet requested. `ETH_P_ALL` remains necessary because the post-untag delivery protocol is the inner `0x8100`, which `ETH_P_ARP` never matches. The macOS BPF tap delivers both tags inline, and its filter grows from 17 to 27 instructions with a service branch that follows an S-TAG to its C-TAG and no further, so unsupported arrangements never reach userspace.
- **No new public builder.** The exported `build_address_resolution_request_ethernet_frame*` functions keep their exact signatures; QinQ is reached through `ScanWireOptions` and the CLI.

**Reason:** PR #77 made single-tag 802.1Q a standards contract and deliberately rejected everything stacked, so provider-bridge networks could be neither scanned nor decoded. Implementing only the IEEE S-TAG/C-TAG pair adds the interoperable case without inviting arbitrary-depth stacks, whose offsets cannot be trusted. Modelling the pair as an enum keeps the rejection guarantee structural rather than a runtime check that a future caller could forget.

**Consequences:** `proptest` is admitted as a dev-dependency (`default-features = false`, `std` only, so no `rusty-fork` / `tempfile`) for tag-stack invariants, and `fuzz/` carries a `cargo-fuzz` target for the Ethernet/ARP decode chain as a **separate workspace** — libFuzzer needs nightly, so fuzzing stays manual like privileged live scans. CI gains an `ubuntu-latest` job, because the `cfg(target_os = "linux")` modules were never compiled by the macOS-only pipeline. Version bumped to `0.2.0` for the new public surface. Arbitrary-depth stacks, the vendor TPIDs, IEEE 802.1ah Provider Backbone Bridges and I-TAGs, passive ACD / monitor mode, `libpcap`, JSON output, adaptive pacing, and `--prototype` remain deferred. Bundled IEEE OUI data is superseded by the 2026-09-17 updater decision below. The Linux kernel always strips the outermost VLAN tag before `AF_PACKET` delivery (and NIC offload or a `vlanN` sub-interface can remove more); no decoder can invent a tag that was already removed, so Linux receive-side service-TCI visibility is deferred until `PACKET_AUXDATA` support.

## 2026-09-17 — Isolated IEEE registry updater and opt-in bundled snapshot

**Decision:** Ship GitHub issue #79 as an explicit, reproducible updater plus an opt-in compile-time bundle, without live HTTP on the scan path or in CI.

- **Updater:** workspace tool [`tools/mac-vendor-updater`](tools/mac-vendor-updater) (`publish = false`). It fetches IEEE MA-L, MA-M, MA-S, and IAB CSVs with system `curl` (`--fail --location --proto =https --tlsv1.2`), parses strict four-column UTF-8 CSV with `csv` 1.4 (`default-features = false`), keeps Private / IEEE Registration Authority rows and Unicode names, trims outer vendor whitespace, and fails the whole run on any malformed row. Duplicate assignments keep the last source row (first-seen emit order). Output order is MA-L → MA-M → MA-S → IAB. Generated text is validated with [`MacVendorRegistry::parse_ieee_oui_text`](src/mac_vendor_registry.rs) before a same-directory temp file is synced and renamed over `ieee-oui.txt`.
- **No scan-time fetch:** [`src/main.rs`](src/main.rs) search order is explicit `--mac-vendor-file`, then `./ieee-oui.txt`, then compile-time embedded text when `--features bundled-mac-vendors` is on. Longest-prefix lookup is unchanged.
- **Packaging:** default and CI builds stay unbundled. Release builders who want an embedded snapshot run `make update-mac-vendors` then `cargo build --release --features bundled-mac-vendors` (or set `NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE`). There is no release workflow and no committed IEEE snapshot; `ieee-oui.txt` is gitignored. Feature-only packaging cannot guarantee future releases refresh the bundle.
- **Tests:** hermetic CSV fixtures only (`--from-dir`, fake `curl` on PATH). No test contacts IEEE.
- **Authorization:** the project owner authorized use of IEEE Registration Authority listings for this work on 2026-09-17. Attribution or redistribution terms in the actual IEEE permission are not checked into this repository and remain unauditable from git.

**Reason:** Operators need a get-oui equivalent that is reproducible, four-registry, and isolated from the privileged scan binary. Embedding a generated snapshot only in opt-in release builds avoids dragging multi-megabyte IEEE text through every CI compile while still allowing a self-contained binary.

**Consequences:** `csv` is a workspace dependency of the updater only. `make update-mac-vendors` / `make test` / `make lint` gain workspace and fixture-bundled invocations; CI matches. Refresh cadence is operator-driven (no 24-hour lockout). Updater hosts need `curl` and `date -u`.

## 2026-09-17 — `csv` 1.4 for the IEEE updater only

**Decision:** Add [`csv` 1.4](https://crates.io/crates/csv) (`default-features = false`) as a `[workspace.dependencies]` crate used solely by [`tools/mac-vendor-updater`](tools/mac-vendor-updater). Do not link it into `new-arp-scan`.

**Reason:** Official IEEE RA listings are quoted UTF-8 CSV with CRLF and commas inside organization names. Hand-rolling a RFC 4180 parser would be larger and weaker than the widely used `csv` crate (MIT OR Unlicense; `csv-core`, `itoa`, `ryu`, `serde_core`, `memchr`). The constitution prefers std first, then a vetted crate; putting `csv` in the updater keeps the privileged scan crate's dependency surface unchanged.

**Consequences:** `Cargo.lock` records `csv` 1.4. Dual-licensed `MIT OR Unlicense` is accepted via the existing MIT allow-list entry. Upgrades stay on the updater crate; scan/CI paths never parse IEEE CSV.
