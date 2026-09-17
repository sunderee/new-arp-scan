# Contributor onboarding

This guide gets a **fresh Linux (or non-Linux) environment** from zero to a passing **format, lint, and test** gate. Deeper conventions live in [CONTRIBUTING.md](../CONTRIBUTING.md).

Tracked for release documentation: [GitHub issue #34](https://github.com/Bizjak-Tech-OU/new-arp-scan/issues/34).

---

## Prerequisites

- **Rust**: stable toolchain with `cargo`, `rustc`, `rustfmt`, and `clippy` (edition **2024**; see `Cargo.toml`).
- **Git** and a clone of [Bizjak-Tech-OU/new-arp-scan](https://github.com/Bizjak-Tech-OU/new-arp-scan).
- **GNU Make** (optional): the [Makefile](../Makefile) wraps common `cargo` invocations.

Verify:

```bash
rustc --version
cargo --version
```

---

## Local build

From the repository root:

```bash
cargo build
```

The debug binary is `target/debug/new-arp-scan`. The Makefile `build` target runs `cargo clean` then `cargo build --release` (binary at `target/release/new-arp-scan`); for everyday work, prefer plain **`cargo build`** to avoid a full rebuild every time (see [AGENTS.md](../AGENTS.md) Cursor Cloud notes).

---

## Formatting and linting

Canonical gate (same as CI-style expectations in this repo):

```bash
make lint
```

Which runs:

1. `cargo fmt --all`
2. `cargo clippy --all-targets -- -D warnings`
3. clippy again with `--all-features` (fixture path in `NEW_ARP_SCAN_BUNDLED_MAC_VENDOR_FILE`)

Fix warnings rather than adding `#[allow(...)]` unless you document why and record the exception in [DECISIONS.md](../DECISIONS.md) when required by [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Tests (unit and integration)

```bash
make test
```

Which runs **`cargo test --workspace`**, **`cargo test --tests`**, then the fixture-bundled feature tests. The second pass ensures integration test binaries under `tests/` are exercised explicitly.

- **Unit tests** live in `src/**/*.rs` under `#[cfg(test)]`.
- **Integration tests** live in `tests/**/*.rs` and call the **public library API** or the **built CLI** via `CARGO_BIN_EXE_new_arp_scan` / `CARGO_BIN_EXE_new-arp-scan`.
- **IEEE updater tests** live with `tools/mac-vendor-updater` and use CSV fixtures (`--from-dir`). They must not contact IEEE.

`make test` also rebuilds with `--features bundled-mac-vendors` against `tests/fixtures/ieee-mac-registry.txt` so the explicit → cwd → packaged search order is covered. That feature stays off for default `cargo test` / `cargo build`.

Some Linux tests are **environment-sensitive** (loopback classification, raw/datagram sockets in sandboxes). If a failure looks environment-related, re-run on a normal Linux host or compare with [AGENTS.md](../AGENTS.md).

---

## Coding conventions (short list)

Full detail: [CONTRIBUTING.md](../CONTRIBUTING.md) and repository **Cursor rules** (`.cursor/rules/`, including the Rust constitution).

Summary:

- **`Result` and `?`** in library code; no `unwrap()` in production paths.
- **Standard library first**; new dependencies need **DECISIONS.md** justification.
- **`unsafe` only with `// SAFETY:`** and reviewer-auditable invariants.
- **Public items**: doc comments with `# Errors` where applicable; **doc tests** for public functions.
- **Tests**: Arrange / Act / Assert; descriptive names; positive, negative, and adversarial coverage for important behavior.

---

## Platform paths and documentation depth

If you work on packet paths or CI behavior, read:

- [Linux platform support](linux-platform.md) — `AF_PACKET`, capabilities, namespaces (optional).
- [macOS platform support](macos-platform.md) — Berkeley Packet Filter, root requirements, interface naming, validation.
- [Architecture overview](architecture.md) — module map and packet flow.

---

## Checklist before opening a pull request

- [ ] `make lint` passes (or equivalent `cargo fmt` + `cargo clippy`).
- [ ] `make test` passes (or equivalent workspace tests plus the fixture-bundled feature run).
- [ ] New behavior has tests and, for public API, doc examples.
- [ ] Architectural changes recorded in **DECISIONS.md** when required by project rules.

Welcome aboard, and thank you for contributing.
