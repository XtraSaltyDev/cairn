# Vault Format

This document is a design draft for CVF-1. It is not a completed audited vault format, and it must not be treated as production-ready.

## Overview

CVF-1 means Cairn Vault Format version 1.

- File extension: `.cairn`
- Shape: monolithic encrypted snapshot
- Header: minimal cleartext header
- Payload: encrypted vault snapshot

The current implementation covers deterministic test-only CVF-1 envelope
encoding, strict header parsing, opaque payload encryption/decryption, and
malformed-input rejection. Item storage, unlock sessions, recovery kit
generation, import/export, CLI vault commands, production use, and write-path
behavior remain future work.

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

The CVF-1 header body currently has a fixed length of 146 bytes:

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
44      2     root-key wrap nonce length: 24
46      24    root-key wrap nonce bytes
70      2     wrapped root key length: 48
72      48    wrapped root key bytes
120     2     payload nonce length: 24
122     24    payload nonce bytes
```

CVF-1 is still a pre-release, unaudited draft. Schema version 1 is retained
while no stable `.cairn` files exist, and this layout may still change before a
production format is declared. The encoded header length must be exactly 146
bytes in CVF-1; extra header bytes and shortened headers are rejected.

## Header Fields

The cleartext header should contain only the minimum non-sensitive data needed to parse and decrypt the vault:

- Magic bytes.
- Schema version.
- Crypto suite ID.
- KDF suite ID.
- Argon2id parameters.
- Salt.
- Root-key wrap nonce.
- Wrapped root key bytes.
- Payload nonce.
- Optional non-sensitive flags.

No plaintext item metadata should exist outside the encrypted payload in v1 unless explicitly approved by ADR.

Unknown format versions, schema versions, crypto suite IDs, KDF suite IDs,
non-zero flags, unexpected fixed lengths, inconsistent header lengths, truncated
inputs, and an empty payload fail closed. Non-zero flags are rejected in CVF-1
unless a future ADR defines their meaning. Header length and all variable
length fields are exact in CVF-1, not extensible padding.

The decrypt path policy-checks the explicit Argon2id parameters before deriving
keys instead of accepting library defaults. The current default policy requires
Argon2id output length 32, memory cost 194,560-262,144 KiB, time cost 2-4, and
parallelism 1-4. Values below minimum or above maximum are rejected before
Argon2id derivation. Current parameters are pre-release and require final
tuning/calibration before production use.

## Payload

The payload is encrypted opaque bytes. The implementation does not define item
records or plaintext metadata yet. Payload ciphertext is produced with
XChaCha20-Poly1305 using the random vault root key and the payload nonce. The
canonical encoded prefix plus header body bytes are authenticated as AEAD
associated data so header tampering fails closed.

## Crypto Direction

- Use Argon2id for password-based key derivation.
- Use XChaCha20-Poly1305-style authenticated encryption.
- Generate a random root vault key.
- Use the master-passphrase-derived key-encryption key to wrap the root vault
  key.
- Use a distinct root-key wrap nonce for the key wrapping operation.
- Use a distinct payload nonce for payload encryption.
- Do not reuse the KDF salt as a nonce.
- Use the random root vault key to encrypt the opaque payload.
- Authenticate root-key wrapping metadata as AAD: magic bytes, format version,
  schema version, crypto suite ID, KDF suite ID, flags, Argon2id parameters,
  KDF salt length and bytes, and root-key wrap nonce length and bytes.
- Authenticate payload metadata as AAD: canonical encoded prefix and full header
  body bytes.
- Persist explicit algorithm IDs and parameters.
- Do not rely on changing library defaults.
- Do not implement custom cryptography.
- Do not claim this draft is audited or production-ready.

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
- Swapped or modified root-key wrap nonce.
- Swapped or modified payload nonce.
- Corrupt wrapped key.
- Unsupported schema.
