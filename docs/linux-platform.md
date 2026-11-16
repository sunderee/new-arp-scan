# Linux platform support

This document is for **contributors** who work on or test Linux-only paths. End-user behavior is also summarized in the [README](../README.md) and [operator documentation](./docs.html).

Tracked for release documentation: [GitHub issue #32](https://github.com/Bizjak-Tech-OU/new-arp-scan/issues/32).

---

## Why `AF_PACKET` / raw sockets

On Linux, `new-arp-scan` sends and receives **Ethernet II frames** carrying **IPv4 ARP** directly on a chosen interface. That requires:

- A **packet socket** created with `AF_PACKET` and `SOCK_RAW` (see Linux `packet(7)`).
- Binding that socket to the **link layer** (specific interface index) and filtering for **`ETH_P_ARP`** so the kernel delivers ARP frames to userspace. When **`--vlan`**, **`--svlan`**, or **`--llc`** is set, the socket is opened with **`ETH_P_ALL`** instead so IEEE 802.1Q-tagged replies (`EtherType 0x8100`), IEEE 802.1ad service-tagged replies (`0x88A8` wrapping `0x8100`), and IEEE 802.3 RFC 1042 SNAP frames (length field, not `0x0806`) are not dropped before the parser; non-ARP frames and well-formed non-reply ARP are ignored in userspace. Untagged SNAP transmit uses **`ETH_P_802_2`** as the `sockaddr_ll` protocol; a customer-tagged frame is sent with **`ETH_P_8021Q`** (`0x8100`) and a service-tagged frame with **`ETH_P_8021AD`** (`0x88A8`), always the outermost TPID actually written into the frame.

Note that on receive the kernel **always** moves the outermost VLAN tag (`0x8100` or `0x88A8`) out of the packet data into skb metadata before an `AF_PACKET` socket sees the frame — `skb_vlan_untag()` on the ingress path, "net: Always untag vlan-tagged traffic on input" (Linux 3.16, commit `0d5501c1c828`) — regardless of NIC offload. The stripped tag is only recoverable through `PACKET_AUXDATA`, which the scanner does not currently request. A single-tagged reply is therefore received as untagged ARP, and an IEEE 802.1ad reply is received leading with its inner C-TAG; hosts are still recorded because the parser accepts both stripped shapes, but the outer TCI of received frames is not observable on Linux. NIC VLAN offload and scanning a `vlanN` sub-interface rather than the trunk parent remove tags before this point as well; no decoder can restore a tag that was already removed. `ETH_P_ALL` is still required for tagged scans: after the kernel untags the S-TAG of a QinQ reply, the delivery protocol is the inner `0x8100`, which an `ETH_P_ARP` socket would never match. (macOS differs: the BPF tap delivers the raw frame, so both tags arrive inline there.)

This path bypasses the normal UDP/TCP stack for the probe traffic itself. The crate still uses conventional **IPv4 datagram sockets** in a few places for **portable** operations (for example interface enumeration helpers), but **subnet scanning and reply collection** depend on raw packet access.

`--bandwidth`, `--interval-ms`, and `--backoff` do not change this socket. They schedule sends in the shared scanner: the default path still bursts within a round, and the opt-in path waits on the calling thread between targets. `--pacing-ms` remains extra delay between rounds only.

`monitor` opens the same kind of packet socket but always binds **`ETH_P_ALL`**, then filters in userspace. That lets the existing Ethernet II, single-customer-tag, service-plus-customer-tag, and RFC 1042 SNAP parsers see frames. The kernel still strips the outermost VLAN tag, and `monitor` does not request `PACKET_AUXDATA`, so an outer TCI is not recovered. The listen loop never transmits. It discovers every IPv4 address on the selected interface name with `getifaddrs(3)` in addition to the ioctl primary address used by `scan`. Alias names such as `eth0:1` are not folded into the parent name.

---

## Privilege and capability requirements

Opening `SOCK_RAW` for packet capture/injection typically requires:

- **`CAP_NET_RAW`**, commonly held by **root**, or
- An equivalent **file capability** or **security policy** on the binary or wrapper.

If the process lacks the capability, the kernel returns **permission denied**; the tool surfaces that with an explicit **`CAP_NET_RAW`** hint in the error text so operators know what to fix. `monitor` needs the same capability. A successful listen, including one that prints `no conflicts observed`, is not proof that no other station is using the address: ARP can be spoofed, and the command does not implement RFC 5227 address conflict detection.

**Contributors do not need raw privileges** to run the full unit test suite on Linux: many tests use fixtures, `ioctl` on safe sockets, or logic that fails before opening the raw ARP socket (for example **loopback rejection**). Tests that open raw packet sockets may still fail in **locked-down sandboxes**; run them on a normal developer machine or CI image that allows those syscalls.

---

## Testing environment setup

1. **Toolchain** — current **stable Rust** with **edition 2024** (see `rust-version` in `Cargo.toml`).

2. **Gate before pushing** (the same checks CI runs on `ubuntu-latest`):

   ```bash
   cargo fmt --all -- --check
   CARGO_BUILD_WARNINGS=deny cargo clippy --workspace --all-targets -- -D warnings
   NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=tests/fixtures/ieee-mac-registry.txt \
     CARGO_BUILD_WARNINGS=deny cargo clippy --workspace --all-targets --all-features -- -D warnings
   CARGO_BUILD_WARNINGS=deny cargo test --workspace
   NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=tests/fixtures/ieee-mac-registry.txt \
     CARGO_BUILD_WARNINGS=deny cargo test --workspace --features bundled-mac-vendors
   ```

   `make lint` / `make test` run equivalent commands (`make lint` rewrites formatting instead of only checking it). `make test` also runs `cargo test --tests`. CI jobs and those Make targets set `CARGO_BUILD_WARNINGS=deny`; `make build` does not. The Ubuntu `supply-chain` job matches `make audit`: `cargo audit`, `cargo audit --file fuzz/Cargo.lock`, then `cargo deny check` (install once: `cargo install cargo-audit --version 0.23.0` and `cargo install cargo-deny --version 0.20.2`; network required for the advisory DB). IEEE registry downloads stay on `make update-mac-vendors` (system `curl`; not run in CI). Privileged live scans stay manual.

3. **Coverage (optional)**  
   `make coverage` uses `cargo llvm-cov`. Install once (`cargo install cargo-llvm-cov`) and add `llvm-tools-preview` if prompted (`rustup component add llvm-tools-preview`).

4. **Environment-sensitive tests**  
   A small number of Linux tests depend on **host network stack details**. `computes_prefix_length_for_slash_24_netmask` and `returns_rejection_when_scanning_loopback_interface_on_linux` can fail in containers where the loopback hardware type differs from a stock Linux host. Tests that open `AF_INET` datagram or raw sockets can fail with permission denied in locked-down sandboxes; that is a host restriction, not a product bug. Compare with [AGENTS.md](../AGENTS.md) and re-run on a stock Linux host when validating merges.

5. **Manual acceptance scan** (needs `CAP_NET_RAW`, typically via `sudo`; touches your LAN; not part of CI):

   ```bash
   cargo build
   sudo ./target/debug/new-arp-scan interfaces
   sudo ./target/debug/new-arp-scan scan --interface eth0
   sudo ./target/debug/new-arp-scan scan --interface eth0 --host 192.168.1.50
   sudo ./target/debug/new-arp-scan scan --interface eth0 --mac-vendor-file ieee-oui.txt
   sudo ./target/debug/new-arp-scan monitor --interface eth0 --timeout-ms 1000
   ```

   Use the interface name from `interfaces` on your host. Discovered hosts print as `<IPv4> <MAC>`, or `<IPv4> <MAC> <vendor>` when a mapping file is loaded, followed by a `scan complete: …` timing line on standard error. Generate `ieee-oui.txt` first with `make update-mac-vendors`. Vendor loading happens before the raw socket open, so a missing or invalid mapping file fails without needing `CAP_NET_RAW`. `monitor` does not load that file. A listen prints `conflict`, `observed`, and `duplicate-ip` lines, or `no conflicts observed`, then one `monitor complete: …` line on standard error. `tcpdump` should show no frames sent by the monitor process.

---

## Verifying frames on the wire

While a scan runs, capture ARP on the same interface in another terminal:

```bash
sudo tcpdump -ni eth0 arp
```

You should see the tool's broadcast ARP **requests** and the **replies** from live hosts. Wireshark with an `arp` display filter works the same way. This is optional manual validation and is not part of automated tests.

---

## Network namespaces (optional isolation)

Namespaces are **not** required for automated tests in this repository. They are useful when you want to **experiment with real ARP traffic** on a disposable topology without touching the office LAN.

High-level approach:

1. Create a **network namespace** (see Linux `network_namespaces(7)` and `ip-netns(8)`).
2. Inside it, bring up interfaces, assign **IPv4 addresses and netmasks** on a **virtual Ethernet pair** (`veth`) or similar so you have a realistic subnet.
3. Run `new-arp-scan` **inside that namespace** with sufficient capability (`CAP_NET_RAW`) on the interface you configured.

Exact `ip`/`nft` commands vary by distribution and policy; treat the above as a **map**, not a script. For authoritative steps, follow your distribution’s networking documentation and the manual pages above.

---

## Further reading

- Linux `packet(7)`, `capabilities(7)`, `networkdevice(7)`
- [macOS platform support](./macos-platform.md) for the Berkeley Packet Filter counterpart
- Repository [DECISIONS.md](../DECISIONS.md) for past Linux and socket-related choices
