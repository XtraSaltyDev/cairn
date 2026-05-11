pub mod error;
pub mod model;
pub mod vault_format;

pub const PRODUCT_NAME: &str = "Cairn";
pub const POSITIONING_LINE: &str = "Passwords, recovery, and control in one local vault.";
pub const CLI_COMMAND: &str = "cairn";

#[cfg(test)]
mod tests {
    use crate::model::{VaultId, VaultMetadata};
    use crate::vault_format::{
        AEAD_TAG_LEN, CRYPTO_SUITE_XCHACHA20_POLY1305, DERIVED_KEY_LEN, FILE_EXTENSION,
        KDF_SALT_LEN, KDF_SUITE_ARGON2ID, MAGIC_BYTES, PAYLOAD_NONCE_LEN, ROOT_KEY_LEN,
        ROOT_KEY_WRAP_NONCE_LEN, SCHEMA_VERSION, WRAPPED_ROOT_KEY_LEN,
    };

    #[test]
    fn cvf1_constants_are_stable() {
        assert_eq!(MAGIC_BYTES, *b"CAIRN\0CVF1");
        assert_eq!(SCHEMA_VERSION, 1);
        assert_eq!(FILE_EXTENSION, "cairn");
        assert_eq!(CRYPTO_SUITE_XCHACHA20_POLY1305, 1);
        assert_eq!(KDF_SUITE_ARGON2ID, 1);
        assert_eq!(ROOT_KEY_LEN, 32);
        assert_eq!(DERIVED_KEY_LEN, 32);
        assert_eq!(KDF_SALT_LEN, 16);
        assert_eq!(PAYLOAD_NONCE_LEN, 24);
        assert_eq!(ROOT_KEY_WRAP_NONCE_LEN, 24);
        assert_eq!(AEAD_TAG_LEN, 16);
        assert_eq!(WRAPPED_ROOT_KEY_LEN, ROOT_KEY_LEN + AEAD_TAG_LEN);
    }

    #[test]
    fn vault_metadata_exposes_only_non_secret_summary_data() {
        let metadata = VaultMetadata::new(VaultId::new("local-test-vault"));

        assert_eq!(metadata.vault_id().as_str(), "local-test-vault");
        assert_eq!(metadata.item_count(), 0);
        assert!(format!("{metadata:?}").contains("VaultMetadata"));
        assert!(!format!("{metadata:?}").contains("password"));
    }

    #[test]
    fn product_naming_is_cairn() {
        assert_eq!(crate::PRODUCT_NAME, "Cairn");
        assert_eq!(
            crate::POSITIONING_LINE,
            "Passwords, recovery, and control in one local vault."
        );
        assert_eq!(crate::CLI_COMMAND, "cairn");
    }
}
