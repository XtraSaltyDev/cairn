# Vault Format

This document is a design draft for CVF-1. It is not a completed audited vault format, and it must not be treated as production-ready.

## Overview

CVF-1 means Cairn Vault Format version 1.

- File extension: `.cairn`
- Shape: monolithic encrypted snapshot
- Header: minimal cleartext header
- Payload: encrypted vault snapshot

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

