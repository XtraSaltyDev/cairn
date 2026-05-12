# Security Invariants

These invariants are non-negotiable engineering rules for Cairn.

- Secrets never logged.
- Full header bytes are authenticated as payload AAD.
- Root-key wrapping metadata is authenticated as wrapping AAD.
- Wrong password and tampering fail closed.
- KDF params are explicit and policy-checked with minimum and maximum bounds before derivation.
- Vault root key is random, not derived directly from the password.
- The passphrase-derived key wraps the random root key; it does not encrypt
  payload bytes directly.
- The root-key wrap nonce, payload nonce, and KDF salt are distinct fields and
  must not be reused for each other.
- Crypto suite IDs are explicit.
- No plaintext item metadata outside the encrypted payload in v1 unless explicitly approved by ADR.
- The CVF-1 encrypted payload contains the entire versioned plaintext
  `VaultSnapshot`; snapshot bytes are in-memory only and are not stored outside
  the encrypted envelope.
- Snapshot secret values must not appear in `Debug` output.
- CLI/UI must not own crypto logic.
- Recovery does not imply backdoor.
- Any new external surface needs threat model update.

## CVF-1 Parser Invariants

- CVF-1 integers are explicit big-endian values, not library-default serialization.
- Unknown format versions, schema versions, crypto suite IDs, KDF suite IDs, and non-zero flags fail closed.
- CVF-1 salt, root-key wrap nonce, wrapped root key, and payload nonce lengths are fixed and validated.
- CVF-1 header length is exactly 146 bytes; shortened headers, extra header bytes, and non-exact variable lengths fail closed.
- The parser accepts only a non-empty ciphertext payload. After decryption,
  snapshot decoding validates the plaintext `VaultSnapshot`; unlock-session
  flows are not implemented yet.
- The decrypt path rejects weak or excessive KDF parameters under the default policy before deriving keys.
- Debug output reports lengths for secret-bearing fields rather than bytes.
