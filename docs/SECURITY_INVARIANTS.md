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

