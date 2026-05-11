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
        CRYPTO_SUITE_XCHACHA20_POLY1305, FILE_EXTENSION, KDF_SUITE_ARGON2ID, MAGIC_BYTES,
        SCHEMA_VERSION,
    };

    #[test]
    fn cvf1_constants_are_stable() {
        assert_eq!(MAGIC_BYTES, *b"CAIRN\0CVF1");
        assert_eq!(SCHEMA_VERSION, 1);
        assert_eq!(FILE_EXTENSION, "cairn");
        assert_eq!(CRYPTO_SUITE_XCHACHA20_POLY1305, 1);
        assert_eq!(KDF_SUITE_ARGON2ID, 1);
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
