# Cairn Agent Instructions

## Project Overview

Cairn is an early-stage local-first password vault project. The MVP direction is a Rust core, a CLI-only interface, and a monolithic encrypted vault file. Desktop UI, browser extension, sync, mobile, passkeys, sharing, and universal desktop autofill are out of scope for the MVP.

This project handles password vault design. Favor correctness, clear security boundaries, small reviewable changes, and negative tests over visible feature progress.

## Repo Layout

- `crates/cairn-core/`: security-sensitive core types, vault format logic, parsing, encryption, key handling, and invariants.
- `crates/cairn-cli/`: thin command-line interface. It may parse commands and display user-facing messages, but it must not own crypto logic.
- `docs/`: product, security, recovery, format, test, roadmap, and ADR documentation.
- `.github/workflows/ci.yml`: formatting, linting, and test checks.

## Build And Test Commands

Run these before claiming a change is complete:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p cairn-cli -- --help
```

## Security Rules

- Do not implement custom cryptography.
- Do not claim Cairn is production-ready.
- Do not log secrets.
- Do not put secrets in fixtures, screenshots, telemetry, analytics, crash reports, examples, tests, or docs.
- Keep security-sensitive logic in `cairn-core`.
- Keep `cairn-cli` thin.
- Do not weaken KDF/security parameters silently.
- Persist explicit algorithm IDs and parameters once cryptography exists.
- Treat rollback, tampering, truncation, malformed imports, and secret leakage as first-class failure cases.
- Any security-sensitive change must update the relevant docs and ADRs in the same change.
- Do not implement sync, autofill, browser extension, passkeys, mobile, or sharing unless an ADR is added first.

## Naming Rules

- Use `Cairn` for the product name.
- Use `cairn` for the CLI command, crate names, package names, file extension, and docs.
- Do not use previous working names except in `docs/ADR/0001-name-and-positioning.md` as historical context.

## Coding Conventions

- Prefer practical, minimal, reviewable changes.
- Keep global behavior minimal and repository-specific.
- Use safe Rust.
- Prefer small modules with clear ownership.
- Avoid placeholder comments that imply security guarantees. Use precise language such as design draft, placeholder, or not implemented.
- Avoid adding dependencies unless they reduce risk or match an explicit design decision.
- Do not print, debug-format, persist, or expose secret material.

## Testing Requirements

- Add or update tests for every behavioral change.
- Prefer negative tests for security-sensitive paths.
- Once the relevant features exist, negative tests are required for wrong password, tampered header, tampered ciphertext, truncation, corrupt nonce, corrupt wrapped key, old schema version, malformed import, and secret leakage.
- CLI tests should verify command shape and safe user-facing output without using real secrets.
- Format tests should verify explicit versions, algorithm IDs, authenticated header behavior, and fail-closed parsing.

## Documentation Requirements

- Keep `README.md` accurate for the current milestone.
- Update `docs/THREAT_MODEL.md` for new attack surfaces or trust boundaries.
- Update `docs/VAULT_FORMAT.md` for any vault format, parser, crypto suite, KDF, migration, or write-strategy change.
- Update `docs/RECOVERY_MODEL.md` for any recovery, backup, export, restore, or rehearsal change.
- Add an ADR before introducing sync, autofill, browser extension, passkeys, mobile, sharing, desktop UI, or any major cryptographic design change.

## What Done Means

A change is done only when:

- The implementation is scoped to the task.
- The repo builds and tests pass, or any environment blocker is reported clearly.
- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` have been run when the Rust toolchain is available.
- Relevant docs and ADRs are updated.
- No temporary files, scratch scripts, duplicate assets, debug outputs, or one-off reports are left behind.
- Newly created untracked files are intentional and called out when there is no git repository or no commit was requested.
