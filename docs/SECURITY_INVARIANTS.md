# Security Invariants

These invariants are non-negotiable engineering rules for Cairn.

- Secrets never logged.
- Full header bytes are authenticated as payload AAD.
- Root-key wrapping metadata is authenticated as wrapping AAD.
- Wrong password and tampering fail closed.
- KDF params are explicit and policy-checked.
- Vault root key is random, not derived directly from the password.
- The passphrase-derived key wraps the random root key; it does not encrypt
  payload bytes directly.
- The root-key wrap nonce, payload nonce, and KDF salt are distinct fields and
  must not be reused for each other.
- Crypto suite IDs are explicit.
- No plaintext item metadata outside the encrypted payload in v1 unless explicitly approved by ADR.
- CLI/UI must not own crypto logic.
- Recovery does not imply backdoor.
- Any new external surface needs threat model update.

## CVF-1 Parser Invariants

- CVF-1 integers are explicit big-endian values, not library-default serialization.
- Unknown schema versions, crypto suite IDs, KDF suite IDs, and non-zero flags fail closed.
- CVF-1 salt, root-key wrap nonce, wrapped root key, and payload nonce lengths are fixed and validated.
- The parser accepts only an opaque, non-empty ciphertext payload; item storage and unlock-session flows are not implemented yet.
- The decrypt path rejects weak KDF parameters under the default policy before deriving keys.
- Debug output reports lengths for secret-bearing fields rather than bytes.
