# Test Plan

## Unit Tests

Unit tests cover constants, non-secret model behavior, explicit schema values, error behavior, and small pure functions in `cairn-core`.

## Format Parser Tests

Format parser tests must verify magic bytes, schema version handling, explicit crypto/KDF suite IDs, KDF parameter policy checks, header length checks, and fail-closed parse behavior.

Implemented CVF-1 parser tests currently cover:

- Round-trip deterministic envelope encode/decode.
- Bad magic bytes.
- Truncated prefix bytes.
- Truncated variable header bytes.
- Unsupported schema version.
- Unsupported crypto suite ID.
- Unsupported KDF suite ID.
- Invalid salt, wrapped root key, and payload nonce lengths.
- Header length values that are too large or inconsistent with the parsed body.
- Rejection of empty payload ciphertext.
- Debug output that reports lengths instead of wrapped-key or payload bytes.

## Tamper Tests

Tamper tests must cover modified header fields, modified ciphertext, changed KDF parameters, swapped nonce, corrupt wrapped key, and authenticated-data failures.

The current tamper-test foundation mutates every byte in a valid in-memory
header body and asserts that parsing either fails validation or produces a
different parsed header. AEAD ciphertext, swapped nonce, wrong password, and
header-as-AAD authentication tests remain future work because full encryption and
unlock are not implemented yet.

## Negative Tests

Negative tests must cover wrong password, truncated file, unsupported old schema version, unsupported future schema version, malformed import, missing required fields, and secret leakage.

## Property And Fuzz Future Plan

Future fuzz targets should exercise the CVF parser and import parser with arbitrary bytes. Property tests should check round-trip behavior, stable serialization, and rejection of malformed inputs.

## CLI Smoke Tests

CLI smoke tests should verify `cairn --help`, `cairn --version`, and placeholder command behavior. CLI tests must not use or print real secrets.

## Secret Leakage Tests

Secret leakage tests should verify that errors, debug output, CLI output, logs, panic paths, and future telemetry/crash surfaces do not include item secrets, passphrases, derived keys, root keys, wrapped key bytes, or recovery material.

## Recovery Rehearsal Tests

Recovery rehearsal tests should prove that the user can walk through locating a backup and required recovery material without exposing secrets. They should verify safe failure copy when materials are missing.

## Atomic Write And Corruption Tests

Atomic write tests should verify temporary-file behavior, fsync strategy where practical, rename behavior, interruption handling, backup preservation, truncation rejection, and safe failure after partial writes.

## Milestone 0 Acceptance Criteria

- Repo compiles.
- Tests pass.
- Docs exist.
- `README.md` is accurate.
- `AGENTS.md` is strict.
- No production-ready security claims.
