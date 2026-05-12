# Cairn Agent Instructions

## Project Overview

Cairn is an early-stage local-first password vault project. The MVP direction is a Rust core, a CLI-only interface, and a monolithic encrypted vault file. Desktop UI, browser extension, sync, mobile, passkeys, sharing, and universal desktop autofill are out of scope for the MVP.

This project handles password vault design. Favor correctness, clear security boundaries, small reviewable changes, and negative tests over visible feature progress.

## Repo Workflow Gate

- Base branch: resolve from `origin/HEAD` before starting work.
- Before making code edits, inspect the checkout state with `git status --short --branch`, `git branch --show-current`, and `git fetch origin`.
- For nontrivial work, do not edit directly on the remote default branch. Use a feature branch or an isolated worktree from `origin/HEAD` first.
- Nontrivial work includes broad features, risky changes, exploratory passes, multi-pass implementation, cryptographic or vault-format changes, or changes expected to touch multiple files.
- If the checkout is dirty, do not overwrite or reset existing changes. If the dirty state is unrelated, prefer a separate worktree from `origin/HEAD`. If it overlaps the task and the safe path is unclear, stop and ask.
- Do not stage, commit, push, open PRs, merge, publish, or tag releases unless the user explicitly asks.
- Before the final response, check `git status --short` and call out any untracked files that remain.

## Goal Prompt Contract

Fresh-thread `/goal` prompts for Cairn should include:

- Current repo state: path, current branch, dirty/clean status, remote default branch from `origin/HEAD`, and whether the task should use a feature branch or worktree.
- Scope fence: the exact `cairn-core`, `cairn-cli`, vault-format, docs, ADR, or test surface allowed to change.
- Out of scope: sync, autofill, browser extension, passkeys, mobile, sharing, desktop UI, production-readiness claims, publishing, releases, and custom cryptography unless explicitly requested with an ADR/design change.
- Success criteria: the precise format, parser, validation, CLI output, error handling, negative test, or documentation state that proves the task is done.
- Verification: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo run -p cairn-cli -- --help`, and `git diff --check` when relevant.
- Cleanup and final report: no temp files, secret-bearing fixtures, debug traces, or unreported untracked files; changed files, checks run, security boundaries, and known gaps must be listed.

## State Reporting

- Keep repo state separate from runtime/command state in final reports.
- Repo state includes branch, commit, PR, tracked diff, untracked files, docs/ADR changes, and tests run.
- Runtime/command state includes CLI output, exit code, sample vault-format behavior, generated test data, and any local files produced by commands.
- Do not blur passing Rust checks with security claims. State which threat, parser, format, or secret-handling behavior was actually verified.

## Repo Layout

- `crates/cairn-core/`: security-sensitive core types, vault format logic, parsing, encryption, key handling, and invariants.
- `crates/cairn-cli/`: thin command-line interface. It may parse commands and display user-facing messages, but it must not own crypto logic.
- `docs/`: product, security, recovery, format, test, roadmap, and ADR documentation.
- `.github/workflows/ci.yml`: formatting, linting, and test checks.

## How To Run This Project

Run locally:

```bash
cargo run -p cairn-cli -- --help
```

There is no server process for the current MVP. Cairn is a local CLI/core project.

Format, lint, and test:

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p cairn-cli -- --help
git diff --check
```

Deploy or release:

- Do not publish crates, create tags, cut releases, or distribute binaries unless the user explicitly asks.
- There is no production deploy path for the current MVP.

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
