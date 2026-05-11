# ADR-0003: Monolithic vault format v1

## Status

Accepted for MVP design

## Decision

Use a monolithic encrypted snapshot format for CVF-1.

## Rationale

- Easier to reason about.
- Easier backup and restore story.
- Smaller metadata surface.
- Better for first security learning milestone.

## Tradeoffs

- Full-file rewrite on change.
- Poor incremental sync story.
- Corruption blast radius must be mitigated with atomic writes and backups.

## Consequences

Future append-only or per-record format is deferred until sync or sharing exists.

The current CVF-1 implementation uses a fixed magic/version/length prefix, a
strict cleartext header containing only non-sensitive parse/decrypt metadata, and
an opaque non-empty ciphertext payload.

The draft cryptographic envelope now generates a random 32-byte vault root key,
derives a 32-byte key-encryption key from the passphrase with explicit Argon2id
parameters, wraps the root key with XChaCha20-Poly1305, and encrypts the opaque
payload with XChaCha20-Poly1305 under the root key. The header stores explicit
suite IDs, KDF parameters, KDF salt, a distinct root-key wrap nonce, wrapped root
key bytes, and a distinct payload nonce.

Payload encryption authenticates the canonical encoded prefix and full header as
AAD. Root-key wrapping authenticates the stable wrapping metadata as AAD: magic
bytes, format version, schema version, suite IDs, flags, KDF parameters, salt,
and root-key wrap nonce. The KDF salt is not reused as a nonce, and the
root-key wrap nonce is not reused as the payload nonce.

CVF-1 remains pre-release and unaudited. Item storage, unlock-session handling,
recovery kits, import/export, CLI vault commands, browser extension, sync,
mobile, sharing, passkeys, desktop UI, and autofill remain outside this ADR's
implemented scope.
