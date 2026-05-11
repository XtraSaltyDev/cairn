# Security Invariants

These invariants are non-negotiable engineering rules for Cairn.

- Secrets never logged.
- Header is authenticated as AAD.
- Wrong password and tampering fail closed.
- KDF params are explicit and policy-checked.
- Vault root key is random, not derived directly from the password.
- Crypto suite IDs are explicit.
- No plaintext item metadata outside the encrypted payload in v1 unless explicitly approved by ADR.
- CLI/UI must not own crypto logic.
- Recovery does not imply backdoor.
- Any new external surface needs threat model update.

## CVF-1 Parser Invariants

- CVF-1 integers are explicit big-endian values, not library-default serialization.
- Unknown schema versions, crypto suite IDs, KDF suite IDs, and non-zero flags fail closed.
- CVF-1 salt, wrapped root key placeholder, and payload nonce lengths are fixed and validated.
- The parser accepts only an opaque, non-empty ciphertext payload; item storage and unlock flows are not implemented yet.
