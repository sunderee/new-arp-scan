# new-arp-scan

ARP scanning tool (Rust). On Linux, `scan` performs address resolution protocol discovery across the selected interface’s IPv4 subnet using raw `AF_PACKET` / `SOCK_RAW` sockets. On macOS it does the same over a Berkeley Packet Filter (`/dev/bpf*`) device, with identical command-line flags, output, and exit codes.

Copyright © Peter Aleksander Bizjak.

Licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).

## Usage

```text
new-arp-scan interfaces
new-arp-scan scan [--interface <NAME>] [--host <IPv4>] [--timeout-ms <MILLISECONDS>] [--pacing-ms <MILLISECONDS>] [--attempts <COUNT>] [--mac-vendor-file <PATH>] [--vlan <VID>] [--pcp <PRIORITY>] [--dei] [--svlan <VID>] [--spcp <PRIORITY>] [--sdei] [--padding <HEX>] [--arpspa <IPv4|dest>] [--llc] [--destaddr <MAC>] [--srcaddr <MAC>] [--arpsha <MAC>] [--arptha <MAC>] [--arphrd <UINT>] [--arppro <UINT>] [--arphln <UINT>] [--arppln <UINT>] [--arpop <UINT>]
```

- On Linux and macOS, `interfaces` lists interfaces that are usable for ARP scanning (Ethernet hardware type, administratively up, not loopback, not `NOARP`, with an IPv4 address, netmask, and a non-zero hardware address). Output is a plain aligned table; if none qualify, the tool prints `no usable interfaces found` and exits successfully. macOS enumerates interfaces with `getifaddrs(3)` rather than Linux `ioctl`, but applies the same usability rules.
- On Linux, `scan` reads the interface IPv4 address, netmask, and Ethernet hardware address via `ioctl`, opens a raw packet socket bound to ARP (`ETH_P_ARP`) — or to every Ethernet protocol (`ETH_P_ALL`) when `--vlan`, `--svlan`, or `--llc` is set — then runs `--attempts` full rounds (default `1`). With `--host <IPv4>`, each round sends one broadcast ARP request for that address only; the address must be strictly interior on the interface subnet (not the network or broadcast address, and not off-subnet). Otherwise each round sends one broadcast ARP request per target address in the subnet (excluding network and broadcast, but always including the interface’s own IPv4 address when it falls outside that open range). Between rounds it sleeps `--pacing-ms` milliseconds after each round except the last (default `0`). After the last round it collects replies until `--timeout-ms` elapses (default `3000`). In single-host mode, only replies whose sender IPv4 equals `--host` are recorded; timing flags behave the same as for a full subnet scan. Values larger than Linux `poll(2)` accepts in milliseconds are clamped internally. Discovered hosts are printed as `<IPv4> <MAC>` on standard output in ascending IPv4 order; with `--mac-vendor-file <PATH>` (or `ieee-oui.txt` in the current directory) the line becomes `<IPv4> <MAC> <vendor>` using longest-prefix IEEE MA-L / MA-M / MA-S matching, or `(Unknown)` when no prefix matches. The library represents each MAC as `MacAddress` on `DiscoveredHost::media_access_control_address` (colon-separated lowercase hex, same as the binary). Non-fatal issues (for example a failed send, a malformed ARP frame, or a conflicting duplicate address resolution reply for the same IPv4) are reported as `warning: ...` lines on standard error. After the scan’s standard output lines, the binary prints one timing summary line on standard error with the stable template `scan complete: interface <NAME>, <N> host(s), <R> round(s), <MS> ms` (singular `host` / `round` when the count is one). If nothing responds, the tool prints `no hosts found` on standard output, still prints the timing summary on standard error, and exits successfully. An invalid `--host` for the selected interface (for example the subnet network address) exits with an error before opening the socket.
- On macOS, `scan` behaves the same as on Linux (interface resolution, target expansion, rounds, pacing, timeout, `--host`, `--arpspa`, `--llc`, output, and exit codes) but uses a Berkeley Packet Filter device: it reads the interface IPv4 address, netmask, and Ethernet address with `getifaddrs(3)`, opens `/dev/bpf*`, attaches it to the interface, installs a filter so it captures untagged ARP, IEEE 802.1Q-tagged ARP, IEEE 802.1ad service-tagged ARP, and RFC 1042 LLC/SNAP ARP under any of those framings, and reads/writes complete Ethernet frames.
- Transmitted frames are RFC 826 Ethernet II ARP requests, zero-padded to the IEEE 802.3 60-octet minimum without the frame check sequence, unless `--llc` is set. With `--vlan <VID>` (`0..=4095`) each request carries a single IEEE 802.1Q tag (TPID `0x8100`; PCP and DEI default to zero). `--pcp <0..=7>` and `--dei` require `--vlan` and fill the rest of the TCI. `--svlan <VID>` (`0..=4095`) requires `--vlan` and wraps that customer tag in an IEEE 802.1ad service tag (S-TAG, TPID `0x88A8`), producing the interoperable two-tag QinQ frame; `--spcp <0..=7>` and `--sdei` require `--svlan` and fill the service TCI. Omitted service PCP and DEI are zero. `--svlan` without `--vlan`, or `--spcp` / `--sdei` without `--svlan`, is a usage error (exit code 2). With `--llc`, requests use IEEE 802.3 length plus RFC 1042 LLC/SNAP (`AA AA 03` + OUI `00:00:00` + EtherType `0x0806`); the length field is LLC+SNAP+ARP (36 octets for IPv4 ARP) plus any `--padding`. `--padding <HEX>` appends hex-encoded octets (no `0x` prefix, even number of digits) after the ARP PDU; the frame is still zero-padded to 60 octets when shorter. Padding that would exceed the 1500-octet IEEE 802.3 MAC client data maximum is rejected. `--arpspa 0.0.0.0` sends an RFC 5227 ARP Probe; `--arpspa dest` sends an RFC 5227 ARP Announcement (`ar$spa` equals each target); any other `--arpspa <IPv4>` overrides the sender protocol address. Omitted `--arpspa` uses the interface IPv4 address. `--destaddr` sets the Ethernet destination (default broadcast); `--srcaddr` sets the Ethernet source (default interface MAC) independently of `--arpsha` (RFC 826 `ar$sha`). `--arptha`, `--arphrd`, `--arppro`, `--arphln`, `--arppln`, and `--arpop` override the remaining ARP header fields with original `arp-scan` names and RFC 826 defaults. Received frames may be Ethernet II, a single IEEE 802.1Q customer tag, one IEEE 802.1ad service tag (TPID `0x88A8`) wrapping exactly one customer tag (TPID `0x8100`), or RFC 1042 LLC/SNAP under any of those framings; PCP, DEI, and VID are decoded for both tags. Every other tag arrangement is rejected so the inner `EtherType` is never read from the wrong offset: a service tag with no customer tag, a tag stacked inside a customer tag (including two `0x8100` tags and the reverse customer-then-service order), three or more tags, and the unofficial TPIDs `0x9100` / `0x9200` / `0x9300`. Note that the Linux kernel always strips the outermost VLAN tag from received frames before userspace sees them (a single-tagged reply arrives untagged, and an IEEE 802.1ad reply arrives with only the customer tag inline; hosts are still recorded), a NIC or a `vlanN` sub-interface may strip further, and no decoder can recover a tag that was already removed; on macOS the BPF tap delivers both tags inline. Well-formed ARP that is not a reply (for example a request on the LAN, or a copy of our own request) is ignored without a warning; RFC 5494 reserved opcodes still warn as malformed. `--host` is a single-target scan of one interior IPv4 address, not itself an RFC 5227 Probe.
- On Linux and macOS, when `scan` is run without `--interface` / `--iface`, the tool selects an interface automatically **only** when exactly one usable interface exists; otherwise it exits with an error that names the ambiguity or states that no usable interface was found.
- On operating systems without a raw link-layer backend, `scan` and `interfaces` return an unsupported-platform error without calling platform-only APIs.

Creating the raw packet socket requires Linux capability **`CAP_NET_RAW`** (often available to the superuser); permission denied when opening the socket is surfaced with an explicit `CAP_NET_RAW` hint. On macOS, opening a Berkeley Packet Filter device requires access to `/dev/bpf*` — typically **root** (run with `sudo`), unless your system grants BPF access to your user. See Linux `packet(7)` / `capabilities(7)` and macOS `bpf(4)`.

To verify frames on the wire, run `tcpdump` or Wireshark on the same interface (for example `tcpdump -ni eth0 arp`, or `tcpdump -ni eth0 'vlan and arp'` when using `--vlan`, or `tcpdump -ni eth0 'ether proto 0x88a8 and ether[16:2] == 0x8100 and ether[20:2] == 0x0806'` when using `--svlan` (libpcap's own `vlan and vlan and arp` also works but is broader: its `vlan` primitive matches `0x8100`, `0x88A8`, and `0x9100` alike), or `tcpdump -ni eth0` without an `arp` filter when using `--llc` because SNAP uses an IEEE 802.3 length field rather than EtherType `0x0806`, or `tcpdump -ni en0 arp` on macOS) while scanning; this is optional manual validation and is not part of automated tests. For a full acceptance check on hardware you control, run a privileged scan (for example `sudo ./target/debug/new-arp-scan scan --interface eth0`, or `sudo ./target/debug/new-arp-scan scan --interface en0` on macOS) or a single-host probe (for example `sudo ./target/debug/new-arp-scan scan --interface en0 --host 192.168.1.50`) and compare custom `--timeout-ms`, `--pacing-ms`, `--attempts`, `--vlan`, `--pcp`, `--svlan`, `--spcp`, `--padding`, `--arpspa`, and `--llc` values with the defaults documented above.

Run `new-arp-scan --help`, `new-arp-scan interfaces --help`, or `new-arp-scan scan --help` for built-in examples.

## Exit codes

The binary uses a minimal, deterministic exit code contract:

- `0` — successful command, including `no hosts found`, `no usable interfaces found`, printing help when invoked with no arguments, and successful `--help` invocations.
- `1` — any operational failure returned from the library (`AppError`), including unsupported platform, invalid interface or target, and raw socket errors (including missing `CAP_NET_RAW` when reported as permission denied).
- `2` — command-line usage or parse errors from the argument parser (typically unknown flags or invalid flag values).

## Requirements

- Rust toolchain with Cargo (`rustc`, `cargo fmt`, `cargo clippy`)
- GNU Make (optional but recommended for the targets below)

## Local development

| Command | Description |
| ------- | ----------- |
| `make build` | `cargo clean` then `cargo build --release` |
| `make test` | `cargo test` then `cargo test --tests` |
| `make lint` | `cargo fmt --all` then `cargo clippy --all-targets -- -D warnings` |
| `make coverage` | `cargo llvm-cov --all-targets --summary-only` (install once: `cargo install cargo-llvm-cov`; first run may need `rustup component add llvm-tools-preview`) |
| `make clean` | `cargo clean` |

Run the same commands manually if you prefer not to use Make.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

Additional notes live under [docs/](docs/):

| Guide | Audience |
|-------|----------|
| [Contributor onboarding](docs/contributor-onboarding.md) | First-time build, lint, test, and pull-request checklist |
| [Architecture overview](docs/architecture.md) | Module map, `unsafe` boundaries, packet flow, testing strategy |
| [Linux platform support](docs/linux-platform.md) | `AF_PACKET` / raw sockets, capabilities, CI vs local testing, namespaces |
| [macOS platform support](docs/macos-platform.md) | Berkeley Packet Filter, root requirements, interface naming, `tcpdump` validation |
| [Operator reference (HTML)](docs/docs.html) | CLI behavior, output, and library overview (static site) |
