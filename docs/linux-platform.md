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

---

## Privilege and capability requirements

Opening `SOCK_RAW` for packet capture/injection typically requires:

- **`CAP_NET_RAW`**, commonly held by **root**, or
- An equivalent **file capability** or **security policy** on the binary or wrapper.

If the process lacks the capability, the kernel returns **permission denied**; the tool surfaces that with an explicit **`CAP_NET_RAW`** hint in the error text so operators know what to fix.

**Contributors do not need raw privileges** to run the full unit test suite on Linux: many tests use fixtures, `ioctl` on safe sockets, or logic that fails before opening the raw ARP socket (for example **loopback rejection**). Tests that open raw packet sockets may still fail in **locked-down sandboxes**; run them on a normal developer machine or CI image that allows those syscalls.

---

## Testing environment setup

1. **Toolchain**  
   Use **current stable Rust** with **edition 2024** (see `Cargo.toml` and [README](../README.md) requirements).

2. **Gate before pushing**  
   From the repository root:

   ```bash
   make lint    # cargo fmt --all, clippy, then clippy --all-features against the IEEE fixture
   make test    # cargo test --workspace, cargo test --tests, then fixture-bundled feature tests
   ```

   Or invoke the same `cargo` commands manually.

3. **Coverage (optional)**  
   `make coverage` uses `cargo llvm-cov`. Install once (`cargo install cargo-llvm-cov`) and add `llvm-tools-preview` if prompted (`rustup component add llvm-tools-preview`).

4. **Environment-sensitive tests**  
   A small number of Linux tests depend on **host network stack details** (for example loopback hardware classification). If they fail in an unusual container, compare with [AGENTS.md](../AGENTS.md) notes and re-run on a stock Linux host when validating merges.

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
- Repository [DECISIONS.md](../DECISIONS.md) for past Linux and socket-related choices
