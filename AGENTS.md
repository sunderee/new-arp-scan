## Learned User Preferences

- For substantial or multi-issue work, investigate the full codebase and official documentation, follow project Cursor rules, and ask clarifying questions until the scope is unambiguous before implementing.
- When executing an attached implementation plan, do not edit the plan file itself; use existing todos (mark them in progress and complete them) instead of creating duplicate todo lists.
- CLI parsing uses the approved `clap` dependency (`DECISIONS.md`); do not remove `clap` or migrate to `std::env::args` unless the user explicitly requests it.
- After substantial feature work, when asked, run a self-correction pass: critically review tests for gaps, improve tests until satisfied, and verify coverage meets project requirements (constitution and `testing.mdc`).
- When changing developer workflow commands, update the `Makefile` and the matching documentation together so they stay aligned.

## Learned Workspace Facts

- The primary GitHub repository for this project is `Bizjak-Tech-OU/new-arp-scan`.
- Continuous integration (`.github/workflows/ci.yml`) runs format, clippy (default and `--all-features` with `NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=tests/fixtures/ieee-mac-registry.txt`), `cargo test --workspace`, and fixture-bundled feature tests on `ubuntu-latest` and `macos-latest` for every push and pull request to `master`; it never runs privileged ARP scans or IEEE registry downloads (those stay manual). The separate `static.yml` only deploys docs.
- The `Makefile` `lint` target runs `cargo fmt --all`, then clippy without features, then clippy `--all-features` against the IEEE fixture path.
- The `Makefile` `test` target runs `cargo test --workspace`, `cargo test --tests`, then fixture-bundled `--features bundled-mac-vendors`.
- The `Makefile` `build` target depends on `clean`, so `cargo clean` runs before `cargo build --release`.
- The `Makefile` `coverage` target runs `cargo llvm-cov --workspace --all-targets --summary-only` unbundled and again with `--features bundled-mac-vendors` (requires `cargo install cargo-llvm-cov` once on the machine).
- The `Makefile` `update-mac-vendors` target runs `cargo run -p mac-vendor-updater -- --output ieee-oui.txt` (needs `curl` and network; not used in CI). Generated `ieee-oui.txt` is gitignored.
- Roadmap and issue planning are driven from repository `issues.md` alongside GitHub issues and milestones.
- When decoding IPv4 addresses returned in `sockaddr_in` from Linux `ioctl`, read the four octets stored at `sin_addr.s_addr` in wire order as laid out by the kernel; using `s_addr.to_be_bytes()` on little-endian hosts can permute octets and make valid contiguous netmasks look invalid.
- Newer stable Rust toolchains paired with recent `libc` releases can change whether fields such as `ifreq.ifr_name` and `sockaddr.sa_data` expose `c_char` or `u8` elements; portable code should coerce through `as _` (or equivalent) instead of assuming signed octets indefinitely.
- Non-interactive `cargo llvm-cov` runs should install `llvm-tools-preview` first (`rustup component add llvm-tools-preview`) so coverage does not block on an interactive toolchain install prompt.
- Beyond the two known environment-sensitive tests, Linux tests that open `AF_INET` datagram or raw sockets can fail with permission denied in locked-down sandboxes; rerun outside those restrictions when validating the full suite.
- CLI scan targets derive from the selected interface's IPv4 address and netmask, with optional `--host` for a single address; there is no `--cidr` flag (`Ipv4Cidr` is library-only).
- Process exit codes are minimal: `0` success, `1` for `AppError`/operational failure, `2` for clap usage errors; after a successful `scan`, the binary prints host lines (or `no hosts found`) on standard output, then one `scan complete: interface …` timing summary line on standard error.

## Cursor Cloud specific instructions

- **Rust toolchain:** The project uses `edition = "2024"` which requires Rust ≥ 1.85. The update script ensures stable toolchain is installed. Use `cargo build` (not `make build`) to avoid the `cargo clean` that the Makefile prepends.
- **Running the CLI:** The binary is at `./target/debug/new-arp-scan` after `cargo build`. A full ARP scan requires `CAP_NET_RAW` (run as root or with `sudo`). The CLI argument parsing and error paths can be exercised without privileges.
- **Tests:** `make test` or `cargo test --workspace`. Two tests are environment-sensitive: `computes_prefix_length_for_slash_24_netmask` and `returns_rejection_when_scanning_loopback_interface_on_linux` may fail in containers where the loopback hardware type differs from a standard Linux host. Feature tests need `NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE=tests/fixtures/ieee-mac-registry.txt cargo test --workspace --features bundled-mac-vendors`.
- **Lint:** `make lint` runs `cargo fmt --all`, clippy, then clippy `--all-features` against the IEEE fixture. Clippy pedantic is enabled; newer Rust toolchains may surface additional lints not present when the code was last updated.
- **No external services for scan/CI:** this is a systems CLI — no databases, Docker, or network services are needed for the hermetic gate. `make update-mac-vendors` is the only command that contacts IEEE (via system `curl`).
