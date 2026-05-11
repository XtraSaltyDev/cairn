use std::fmt;

pub const FORMAT_NAME: &str = "Cairn Vault Format version 1";
pub const FORMAT_SHORT_NAME: &str = "CVF-1";
pub const FILE_EXTENSION: &str = "cairn";
pub const MAGIC_BYTES: [u8; 10] = *b"CAIRN\0CVF1";
pub const SCHEMA_VERSION: u16 = 1;
pub const CRYPTO_SUITE_ID_DESIGN_DRAFT: &str = "xchacha20poly1305-design-draft";
pub const KDF_SUITE_ID_DESIGN_DRAFT: &str = "argon2id-design-draft";
pub const PAYLOAD_NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

#[derive(Clone, Eq, PartialEq)]
pub struct Argon2idParameters {
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: u32,
}

impl Argon2idParameters {
    pub const fn design_draft() -> Self {
        Self {
            memory_cost_kib: 194_560,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }

    pub fn memory_cost_kib(&self) -> u32 {
        self.memory_cost_kib
    }

    pub fn time_cost(&self) -> u32 {
        self.time_cost
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    pub fn output_len(&self) -> u32 {
        self.output_len
    }
}

impl fmt::Debug for Argon2idParameters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Argon2idParameters")
            .field("memory_cost_kib", &self.memory_cost_kib)
            .field("time_cost", &self.time_cost)
            .field("parallelism", &self.parallelism)
            .field("output_len", &self.output_len)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WrappedRootKeySlotMetadata {
    slot_id: String,
    kdf_suite_id: &'static str,
}

impl WrappedRootKeySlotMetadata {
    pub fn new(slot_id: impl Into<String>) -> Self {
        Self {
            slot_id: slot_id.into(),
            kdf_suite_id: KDF_SUITE_ID_DESIGN_DRAFT,
        }
    }

    pub fn slot_id(&self) -> &str {
        &self.slot_id
    }

    pub fn kdf_suite_id(&self) -> &'static str {
        self.kdf_suite_id
    }
}

impl fmt::Debug for WrappedRootKeySlotMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedRootKeySlotMetadata")
            .field("slot_id", &self.slot_id)
            .field("kdf_suite_id", &self.kdf_suite_id)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VaultHeaderDesign {
    schema_version: u16,
    crypto_suite_id: &'static str,
    kdf_suite_id: &'static str,
    kdf_parameters: Argon2idParameters,
    salt_len: usize,
    wrapped_root_key_slots: usize,
    payload_nonce_len: usize,
    flags: u32,
}

impl VaultHeaderDesign {
    pub const fn cvf1_design_draft() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            crypto_suite_id: CRYPTO_SUITE_ID_DESIGN_DRAFT,
            kdf_suite_id: KDF_SUITE_ID_DESIGN_DRAFT,
            kdf_parameters: Argon2idParameters::design_draft(),
            salt_len: SALT_LEN,
            wrapped_root_key_slots: 1,
            payload_nonce_len: PAYLOAD_NONCE_LEN,
            flags: 0,
        }
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn crypto_suite_id(&self) -> &'static str {
        self.crypto_suite_id
    }

    pub fn kdf_suite_id(&self) -> &'static str {
        self.kdf_suite_id
    }

    pub fn kdf_parameters(&self) -> &Argon2idParameters {
        &self.kdf_parameters
    }

    pub fn salt_len(&self) -> usize {
        self.salt_len
    }

    pub fn wrapped_root_key_slots(&self) -> usize {
        self.wrapped_root_key_slots
    }

    pub fn payload_nonce_len(&self) -> usize {
        self.payload_nonce_len
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }
}

impl fmt::Debug for VaultHeaderDesign {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHeaderDesign")
            .field("schema_version", &self.schema_version)
            .field("crypto_suite_id", &self.crypto_suite_id)
            .field("kdf_suite_id", &self.kdf_suite_id)
            .field("kdf_parameters", &self.kdf_parameters)
            .field("salt_len", &self.salt_len)
            .field("wrapped_root_key_slots", &self.wrapped_root_key_slots)
            .field("payload_nonce_len", &self.payload_nonce_len)
            .field("flags", &self.flags)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvf1_header_design_uses_explicit_ids_and_lengths() {
        let design = VaultHeaderDesign::cvf1_design_draft();

        assert_eq!(design.schema_version(), SCHEMA_VERSION);
        assert_eq!(design.crypto_suite_id(), CRYPTO_SUITE_ID_DESIGN_DRAFT);
        assert_eq!(design.kdf_suite_id(), KDF_SUITE_ID_DESIGN_DRAFT);
        assert_eq!(design.salt_len(), SALT_LEN);
        assert_eq!(design.payload_nonce_len(), PAYLOAD_NONCE_LEN);
        assert_eq!(design.wrapped_root_key_slots(), 1);
        assert_eq!(design.flags(), 0);
    }

    #[test]
    fn design_debug_output_contains_no_wrapped_key_bytes() {
        let slot = WrappedRootKeySlotMetadata::new("master-passphrase");
        let debug_output = format!("{slot:?}");

        assert!(debug_output.contains("WrappedRootKeySlotMetadata"));
        assert!(!debug_output.contains("wrapped_key"));
        assert!(!debug_output.contains("ciphertext"));
    }
}
