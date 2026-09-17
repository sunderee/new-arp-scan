# Contributing

Thank you for contributing to **new-arp-scan**. If you are new to the repository, start with **[docs/contributor-onboarding.md](docs/contributor-onboarding.md)** (toolchain, build, lint, tests), then read **[docs/architecture.md](docs/architecture.md)** for a map of the codebase and **[docs/linux-platform.md](docs/linux-platform.md)** if you touch Linux packet paths.

This document records project-wide conventions that extend the Rust toolchain defaults and the expectations documented in this repository.

## Safety comments and `unsafe`

- **`unsafe` is reserved for real guarantees**, not convenience. Do not use `unsafe` unless there is no safe standard-library alternative.
- **Every `unsafe` block** must be preceded by a comment that states:
  - which invariants the caller must uphold,
  - what memory or concurrency assumptions the block relies on,
  - why the compiler cannot verify those facts automatically.
- Use the established Rust convention: a line-oriented `// SAFETY:` explanation immediately before the `unsafe` block, with enough detail for a reviewer to audit without guessing intent.

If you believe `unsafe` is required, record the architectural justification in `DECISIONS.md` as well.

## Foreign function interface boundaries

- Treat **foreign function interface** boundaries as trust boundaries: assume arguments from C or the operating system can violate Rust’s usual rules unless proven otherwise.
- Keep **foreign function interface calls** small and concentrated in dedicated modules; avoid scattering raw system calls across the crate.
- Prefer thin wrappers that translate foreign errors into the crate [`AppError`](src/error.rs) (or a dedicated error type) at the boundary.
- Document lifetime and threading assumptions where the foreign library keeps pointers or callbacks.

## Module ownership and layout

- **`src/main.rs`** contains only argument parsing (when implemented), minimal runtime setup, a single call into `run()` (or equivalent), process exit, and user-facing error printing. No business logic belongs here.
- **`src/lib.rs`** exposes the supported public application programming interface; integration tests depend on this surface.
- **`src/error.rs`** owns the crate-wide [`AppError`](src/error.rs) type unless a future change explicitly splits domain errors (document that split in `DECISIONS.md`).
- Prefer **flat modules** under `src/` over deep nesting. New domains get their own file or folder only when the responsibility is clearly distinct.

## Error handling

- Use **`Result` and `?`** for recoverable failures in library code. Do not use `unwrap()` or `expect()` in production paths.
- `expect()` is acceptable **only** in tests and in `main.rs` when the program cannot proceed (and the message must explain the invariant, not repeat the failure).
- Extend [`AppError`](src/error.rs) with new variants when behavior warrants it; avoid stringly-typed errors for control flow.
- Every fallible **public** function’s documentation must include an **`# Errors`** section describing which variants callers should handle.

## Dependencies

- **Standard library first.** Adding a crate is an architectural decision, not a shortcut.
- Any new dependency requires an entry in **`DECISIONS.md`**: what problem it solves, why `std` is insufficient, and what alternatives were rejected.
- Keep `[dependencies]` minimal and audit upgrades deliberately.

## Testing

- **Business logic** must be tested (unit tests beside the code, integration tests under `tests/` against the public library application programming interface).
- Follow **Arrange, Act, Assert** structure with a blank line between phases.
- Name tests as **full sentences** in `snake_case` describing the scenario.
- Cover **positive**, **negative**, and **adversarial** cases for behavior that matters; do not assert only `is_ok()` / `is_err()` without inspecting the outcome.
- Avoid tests that depend on the network, uncontrollable global state, or the real filesystem except behind isolation helpers approved in `DECISIONS.md`.
- Public functions require **documentation examples** that compile (`cargo test` runs them).

## Formatting and linting

- Run **`make lint`** (formats with `cargo fmt --all`, then runs `cargo clippy --all-targets -- -D warnings`), or invoke those commands yourself.
- Fix issues rather than silencing them.
- Undocumented `#[allow(...)]` attributes are not acceptable unless paired with a comment explaining why the suppression is correct **and** a `DECISIONS.md` entry.

## Platform testing

The crate supports **Linux** (`AF_PACKET` raw sockets) and **macOS** (Berkeley Packet Filter). Continuous integration runs the hermetic gate on **both `ubuntu-latest` and `macos-latest`** on every push and pull request to `master` (`.github/workflows/ci.yml`). Both jobs are needed: the `cfg(target_os = "linux")` modules (`src/linux_socket.rs`, `src/linux_packet.rs`, and friends) are not compiled at all on macOS, and vice versa. Each job runs:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=tests/fixtures/ieee-mac-registry.txt \
  cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=tests/fixtures/ieee-mac-registry.txt \
  cargo test --workspace --features bundled-mac-vendors
```

These are the same checks as `make lint` / `make test`, except CI uses `cargo fmt --all -- --check` (verify only, never rewrite). CI never fetches IEEE MAC listings; regenerate `ieee-oui.txt` locally with `make update-mac-vendors`.

If you only have one platform to hand, you can still type-check and lint the other target's modules without running its tests:

```sh
rustup target add x86_64-unknown-linux-gnu   # from macOS; use aarch64-apple-darwin from Linux
cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```

`cargo check` / `cargo clippy` do not link, so this needs no cross-linker. It catches compile and lint errors in the other platform's code, but it cannot run that platform's tests — CI does that.

**Privileged live scans stay manual** — CI never opens a packet socket or BPF device for a real scan. To acceptance-test on hardware you control:

- **macOS** (needs root / BPF access):

  ```sh
  cargo build
  sudo ./target/debug/new-arp-scan interfaces
  sudo ./target/debug/new-arp-scan scan --interface en0
  sudo ./target/debug/new-arp-scan scan --interface en0 --host 192.168.1.50
  sudo ./target/debug/new-arp-scan scan --interface en0 --mac-vendor-file ieee-oui.txt
  ```

  `interfaces` needs no privileges; `scan` opens `/dev/bpf*` and fails with a "run with sudo" error otherwise. Verify frames with `tcpdump -ni en0 arp` in another terminal. Vendor annotation needs a mapping file (`make update-mac-vendors` writes `ieee-oui.txt`); a missing or invalid file fails before BPF is opened.

- **Linux** (needs `CAP_NET_RAW`, typically via `sudo`): use the same commands with the appropriate interface (for example `eth0`). See [docs/linux-platform.md](docs/linux-platform.md).

## Fuzzing

The Ethernet / IEEE 802.1Q / RFC 1042 / RFC 826 decode chain is the crate's untrusted-input boundary, so it carries a `cargo-fuzz` target (`fuzz/fuzz_targets/parse_ethernet_arp.rs`). Like privileged live scans, **fuzzing is manual**: libFuzzer needs a nightly toolchain and a C++ sanitizer runtime that the stable CI jobs do not have, so `fuzz/` is a separate workspace that the root `cargo build` / `cargo test` / `cargo clippy --all-targets` never build.

```sh
cargo install cargo-fuzz          # once per machine
rustup toolchain install nightly  # once per machine
make fuzz                         # 60 s by default; FUZZ_SECONDS=300 make fuzz for longer
```

Run it after changing anything in `src/ethernet_frame.rs` or `src/address_resolution_protocol.rs`. See [fuzz/README.md](fuzz/README.md) for the corpus layout and how to reproduce a finding.

When you change the developer workflow commands, update the `Makefile`, this file, and the CI workflow together so they stay aligned.

## IEEE MAC registry updater

`tools/mac-vendor-updater` is an internal workspace binary. It depends on `csv` so the privileged `new-arp-scan` crate does not. Tests must stay hermetic: use `--from-dir` and the CSVs under `tools/mac-vendor-updater/tests/fixtures/`. Do not add live HTTP to `cargo test` or CI.

Default builds do not embed IEEE data. Release builders who want a bundled snapshot run `make update-mac-vendors` and then `cargo build --release --features bundled-mac-vendors`. Do not commit generated `ieee-oui.txt`.

## Licensing

By contributing, you agree that your contributions are licensed under the **GNU Affero General Public License v3.0 only**, the same license as the project (`LICENSE`).
