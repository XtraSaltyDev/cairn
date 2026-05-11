# Vault Format

This document is a design draft for CVF-1. It is not a completed audited vault format, and it must not be treated as production-ready.

## Overview

CVF-1 means Cairn Vault Format version 1.

- File extension: `.cairn`
- Shape: monolithic encrypted snapshot
- Header: minimal cleartext header
- Payload: encrypted vault snapshot

The current implementation covers deterministic CVF-1 envelope encoding, strict
header parsing, and malformed-input rejection. Full encryption, unlock, item
storage, recovery, and write-path behavior remain future work.

## Binary Layout

All integer fields are unsigned and encoded in big-endian byte order. Lengths are
byte lengths.

```text
offset  size  field
0       10    magic bytes: 43 41 49 52 4e 00 43 56 46 31 ("CAIRN\0CVF1")
10      2     format version: 1
12      4     header length
16      N     header body
16+N    ...   payload ciphertext bytes
```

The payload ciphertext is opaque to the parser in this milestone, but it must be
present and non-empty. There is no plaintext item database or item metadata
outside the encrypted payload.

The CVF-1 header body currently has a fixed length of 120 bytes:

```text
offset  size  field
0       2     schema version: 1
2       2     crypto suite ID: 1 (XChaCha20-Poly1305 direction)
4       2     KDF suite ID: 1 (Argon2id direction)
6       4     flags: 0
10      4     Argon2id memory cost KiB: 194560
14      4     Argon2id time cost: 2
18      4     Argon2id parallelism: 1
22      4     Argon2id output length: 32
26      2     KDF salt length: 16
28      16    KDF salt bytes
44      2     wrapped root key length: 48
46      48    wrapped root key placeholder bytes
94      2     payload nonce length: 24
96      24    payload nonce bytes
```

## Header Fields

The cleartext header should contain only the minimum non-sensitive data needed to parse and decrypt the vault:

- Magic bytes.
- Schema version.
- Crypto suite ID.
- KDF suite ID.
- Argon2id parameters.
- Salt.
- Wrapped root key slot metadata.
- Payload nonce.
- Optional non-sensitive flags.

No plaintext item metadata should exist outside the encrypted payload in v1 unless explicitly approved by ADR.

Unknown schema versions, crypto suite IDs, KDF suite IDs, non-zero flags,
unexpected fixed lengths, inconsistent header lengths, truncated inputs, and an
empty payload fail closed. The current parser also policy-checks the explicit
Argon2id parameters against the CVF-1 constants above instead of accepting
library defaults.

## Payload

The payload is the encrypted vault snapshot. It must be authenticated with AEAD, and the header must be authenticated as associated data so header tampering fails closed.

## Crypto Direction

- Use Argon2id for password-based key derivation.
- Use XChaCha20-Poly1305-style authenticated encryption.
- Generate a random root vault key.
- Use the master-passphrase-derived key to wrap the root vault key.
- Persist explicit algorithm IDs and parameters.
- Do not rely on changing library defaults.
- Do not implement custom cryptography.

## Write Strategy

- Write to an atomic temporary file.
- Flush and fsync where practical.
- Rename into place.
- Avoid partial writes.
- Preserve or create a recoverable backup path before replacing a known-good vault file.

## Migration

The schema version is required. Old versions must fail safely until migration is implemented. Unsupported future versions must fail closed rather than attempting partial parsing.

## Negative Cases

The parser and decrypt path must reject:

- Wrong password.
- Truncated file.
- Modified header.
- Modified ciphertext.
- Changed KDF parameters.
- Swapped nonce.
- Corrupt wrapped key.
- Unsupported schema.
