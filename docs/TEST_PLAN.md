# Test Plan

## Unit Tests

Unit tests cover constants, non-secret model behavior, explicit schema values, error behavior, and small pure functions in `cairn-core`.

## Format Parser Tests

Format parser tests must verify magic bytes, schema version handling, explicit crypto/KDF suite IDs, KDF parameter policy checks, header length checks, and fail-closed parse behavior.

Implemented CVF-1 parser tests currently cover:

- Round-trip deterministic envelope encode/decode.
- Deterministic test-only encrypted envelope encoding for fixed fake materials.
- Bad magic bytes.
- Truncated prefix bytes.
- Truncated variable header bytes.
- Unsupported format version.
- Unsupported schema version.
- Unsupported crypto suite ID.
- Unsupported KDF suite ID.
- Non-zero flags.
- Argon2id output length other than 32.
- Argon2id memory, time, and parallelism values below minimum policy.
- Argon2id memory, time, and parallelism values above maximum policy before derivation.
- Invalid salt, root-key wrap nonce, wrapped root key, and payload nonce lengths.
- Header length values that are too large, shortened, extended, or inconsistent with CVF-1's exact header length.
- Rejection of empty payload ciphertext.
- Malformed inputs do not panic.
- Payload AAD changes when authenticated header fields change.
- Root-key wrap AAD changes when KDF or wrap metadata changes.
- Debug output that reports lengths instead of wrapped-key or payload bytes.

## Snapshot Payload Tests

Snapshot payload tests cover the plaintext schema that lives inside the
encrypted CVF-1 payload. Implemented tests currently cover:

- JSON round-trip preservation for non-secret snapshot and item fields.
- Secret value preservation after decode.
- `Debug` redaction for secret values, items, and snapshots.
- Unsupported snapshot schema version rejection.
- Empty vault ID rejection.
- Empty item ID rejection.
- Duplicate item ID rejection.
- Empty item title rejection.
- Empty login/password primary secret rejection.
- Item `updated_at` earlier than `created_at` rejection.
- Snapshot `updated_at` earlier than `created_at` rejection.
- Malformed JSON rejection.
- Unknown item kind rejection.
- Encode-time validation before plaintext payload bytes are returned.
- Decode-time validation after JSON parsing.
- End-to-end in-memory flow from snapshot JSON payload bytes through CVF-1
  encryption, decryption, and snapshot decode.

## Tamper Tests

Tamper tests must cover modified header fields, modified ciphertext, changed KDF parameters, swapped nonce, corrupt wrapped key, and authenticated-data failures.

The current tamper-test foundation mutates every byte in a valid in-memory
header body and asserts that parsing either fails validation or produces a
different parsed header. Cryptographic envelope tests now cover wrong
passphrase, modified payload ciphertext, modified payload tag, modified payload
nonce, modified header AAD, modified KDF salt, modified Argon2id parameters,
modified root-key wrap nonce, modified wrapped root key, unsupported suites, and
weak KDF parameters under the default policy.

Tests use an explicit test-only KDF policy for fast round trips. Production
defaults are not weakened silently to make tests pass. Production policy also
sets maximum KDF bounds so excessive Argon2id parameters fail before expensive
derivation.

## Negative Tests

Negative tests must cover wrong password, truncated file, unsupported old schema version, unsupported future schema version, malformed import, missing required fields, and secret leakage.

## Property And Fuzz Future Plan

Future fuzz targets should exercise the CVF parser and import parser with arbitrary bytes. Property tests should check round-trip behavior, stable serialization, and rejection of malformed inputs.

## CLI Smoke Tests

CLI smoke tests should verify `cairn --help`, `cairn --version`, and placeholder command behavior. CLI tests must not use or print real secrets.

## Secret Leakage Tests

Secret leakage tests should verify that errors, debug output, CLI output, logs, panic paths, and future telemetry/crash surfaces do not include item secrets, passphrases, plaintext payloads, derived keys, root keys, wrapped key bytes, or recovery material.

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
