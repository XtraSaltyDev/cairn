# Threat Model

This is a practical MVP threat model for Cairn. It is not a claim that the vault format is complete, audited, or production-ready.

## Assets

- Master passphrase.
- Derived keys.
- Root vault key.
- Wrapped key slots.
- Root-key wrap nonce.
- Payload nonce.
- Vault payload.
- Recovery kit.
- Encrypted export.
- Item secrets.
- Metadata.

## Trust Boundaries

- Local device.
- Locked vault file.
- Unlocked in-memory state.
- Clipboard.
- Terminal.
- Future UI.
- Future backup/export location.

## Protect Against

- Attacker copies the locked vault file and attacks it offline.
- Lost or stolen device while the vault is locked.
- Accidental truncation or corruption.
- Tampering with header, ciphertext, or KDF parameters.
- Rollback or stale backup confusion.
- Import parser bugs.
- Local clipboard exposure in normal use.
- Shoulder surfing in normal use.
- Future malicious or curious sync provider.

## Out Of Scope For MVP

- Fully compromised operating system.
- Malware or keylogger.
- Live exfiltration while the vault is unlocked.
- Malicious compiler or toolchain.
- Coercion.
- Advanced hardware attacks.

## Deferred Risky Surfaces

- Browser extension.
- Browser autofill.
- Universal desktop autofill.
- Cloud sync.
- Sharing or collaboration.
- Passkey provider.
- Mobile clients.

## Security Invariants

- Secrets are never logged.
- The full cleartext header is authenticated as payload AEAD associated data.
- Root-key wrapping metadata is authenticated as wrapping AEAD associated data.
- Wrong passwords and tampering fail closed.
- KDF parameters are explicit and policy-checked with minimum and maximum bounds before derivation.
- The root vault key is random, not derived directly from the password.
- The passphrase-derived key-encryption key wraps the root vault key; the root
  vault key encrypts opaque payload bytes.
- The KDF salt, root-key wrap nonce, and payload nonce are separate values and
  must not be reused for each other.
- Crypto suite IDs are explicit.
- Plaintext item metadata is not stored outside the encrypted payload in v1 unless an ADR approves it.
- CLI and UI code must not own cryptographic logic.
- Recovery does not imply a backdoor.
- Any new external surface requires a threat model update.

## Test Expectations

Negative tests are required for wrong password, tampered header, tampered ciphertext, truncation, corrupt nonce, corrupt wrapped key, old schema version, malformed import, and secret leakage once those features exist.

Format tests must prove that unsupported versions fail safely until migration is implemented. Import tests must treat malformed input as hostile. CLI and future UI tests must verify that secrets are not printed, logged, persisted in crash reports, or exposed through debug output.
