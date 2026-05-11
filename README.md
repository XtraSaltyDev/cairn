Cairn
=====

Passwords, recovery, and control in one local vault.

Cairn is an early-stage local-first password vault project. It is not production-ready and must not be used to store real secrets yet.

The MVP direction is a Rust core, a CLI-first workflow, and a monolithic encrypted vault file. The desktop UI is deferred until the core vault format, recovery model, and negative test suite have stabilized.

## MVP Non-Goals

- No sync.
- No browser extension.
- No desktop autofill.
- No mobile client.
- No sharing.
- No passkey provider.
- No analytics.

## Repo Layout

```text
cairn/
  crates/
    cairn-core/  security-sensitive core types and CVF-1 opaque envelope crypto
    cairn-cli/   thin CLI command surface
  docs/          product, security, format, recovery, test, roadmap, and ADR docs
```

## Developer Commands

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p cairn-cli -- --help
```

## Security Principles

- Do not implement custom cryptography.
- Do not log secrets or include them in tests, examples, fixtures, docs, telemetry, analytics, screenshots, or crash reports.
- Keep cryptographic and security-sensitive logic in `cairn-core`.
- Keep `cairn-cli` thin.
- Fail closed on wrong passwords, tampering, corruption, unsupported schemas, and malformed imports.
- Recovery must not imply a backdoor or account reset.
