use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CairnError;

pub const SNAPSHOT_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct VaultTimestamp(u64);

impl VaultTimestamp {
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub const fn as_unix_seconds(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for VaultTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultTimestamp")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VaultItemId(String);

impl VaultItemId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VaultItemId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultItemId")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretString")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultItemKind {
    LoginPassword,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultItem {
    id: VaultItemId,
    kind: VaultItemKind,
    title: String,
    username: Option<String>,
    primary_secret: SecretString,
    #[serde(default)]
    urls: Vec<String>,
    notes: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    created_at: VaultTimestamp,
    updated_at: VaultTimestamp,
}

impl VaultItem {
    pub fn login_password(
        id: VaultItemId,
        title: impl Into<String>,
        primary_secret: SecretString,
        created_at: VaultTimestamp,
        updated_at: VaultTimestamp,
    ) -> Self {
        Self {
            id,
            kind: VaultItemKind::LoginPassword,
            title: title.into(),
            username: None,
            primary_secret,
            urls: Vec::new(),
            notes: None,
            tags: Vec::new(),
            created_at,
            updated_at,
        }
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_urls<I, S>(mut self, urls: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.urls = urls.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn id(&self) -> &VaultItemId {
        &self.id
    }

    pub fn kind(&self) -> VaultItemKind {
        self.kind
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn primary_secret(&self) -> &SecretString {
        &self.primary_secret
    }

    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    pub fn created_at(&self) -> VaultTimestamp {
        self.created_at
    }

    pub fn updated_at(&self) -> VaultTimestamp {
        self.updated_at
    }
}

impl fmt::Debug for VaultItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultItem")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("primary_secret", &self.primary_secret)
            .field("url_count", &self.urls.len())
            .field("notes_present", &self.notes.is_some())
            .field("tag_count", &self.tags.len())
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSnapshot {
    schema_version: u16,
    vault_id: String,
    created_at: VaultTimestamp,
    updated_at: VaultTimestamp,
    items: Vec<VaultItem>,
}

impl VaultSnapshot {
    pub fn new(
        vault_id: impl Into<String>,
        created_at: VaultTimestamp,
        updated_at: VaultTimestamp,
        items: Vec<VaultItem>,
    ) -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            vault_id: vault_id.into(),
            created_at,
            updated_at,
            items,
        }
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn created_at(&self) -> VaultTimestamp {
        self.created_at
    }

    pub fn updated_at(&self) -> VaultTimestamp {
        self.updated_at
    }

    pub fn items(&self) -> &[VaultItem] {
        &self.items
    }

    pub fn validate(&self) -> Result<(), CairnError> {
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(CairnError::UnsupportedSnapshotVersion {
                found: self.schema_version,
                supported: SNAPSHOT_SCHEMA_VERSION,
            });
        }

        if self.vault_id.trim().is_empty() {
            return Err(CairnError::InvalidSnapshot("vault_id is required"));
        }

        if self.updated_at < self.created_at {
            return Err(CairnError::InvalidSnapshot(
                "snapshot updated_at must not be earlier than created_at",
            ));
        }

        let mut item_ids = HashSet::new();
        for item in &self.items {
            if item.id.as_str().trim().is_empty() {
                return Err(CairnError::InvalidSnapshot("item id is required"));
            }

            if !item_ids.insert(item.id.as_str()) {
                return Err(CairnError::InvalidSnapshot("item ids must be unique"));
            }

            if item.title.trim().is_empty() {
                return Err(CairnError::InvalidSnapshot("item title is required"));
            }

            if item.updated_at < item.created_at {
                return Err(CairnError::InvalidSnapshot(
                    "item updated_at must not be earlier than created_at",
                ));
            }

            match item.kind {
                VaultItemKind::LoginPassword if item.primary_secret.is_empty() => {
                    return Err(CairnError::InvalidSnapshot(
                        "login/password primary secret is required",
                    ));
                }
                VaultItemKind::LoginPassword => {}
            }
        }

        Ok(())
    }
}

impl fmt::Debug for VaultSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultSnapshot")
            .field("schema_version", &self.schema_version)
            .field("vault_id", &self.vault_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("item_count", &self.items.len())
            .finish()
    }
}

pub fn encode_snapshot_payload(snapshot: &VaultSnapshot) -> Result<Vec<u8>, CairnError> {
    snapshot.validate()?;
    serde_json::to_vec(snapshot)
        .map_err(|_| CairnError::SerializationFailed("snapshot JSON serialization failed"))
}

pub fn decode_snapshot_payload(bytes: &[u8]) -> Result<VaultSnapshot, CairnError> {
    let snapshot: VaultSnapshot = serde_json::from_slice(bytes)
        .map_err(|_| CairnError::MalformedSnapshot("snapshot JSON is malformed"))?;
    snapshot.validate()?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CairnError;
    use crate::vault_format::{create_encrypted_envelope_for_tests, decrypt_envelope_for_tests};

    const TEST_PASSPHRASE: &[u8] = b"snapshot-envelope-test-input";
    const TEST_SECRET_VALUE: &str = "redacted-placeholder";

    fn timestamp(seconds: u64) -> VaultTimestamp {
        VaultTimestamp::from_unix_seconds(seconds)
    }

    fn valid_item() -> VaultItem {
        VaultItem::login_password(
            VaultItemId::new("item-login-1"),
            "Example login",
            SecretString::new(TEST_SECRET_VALUE),
            timestamp(1_700_000_000),
            timestamp(1_700_000_100),
        )
        .with_username("alice@example.test")
        .with_urls(["https://example.test/login"])
        .with_notes("fake test notes")
        .with_tags(["personal", "test"])
    }

    fn valid_snapshot() -> VaultSnapshot {
        VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![valid_item()],
        )
    }

    fn valid_snapshot_payload_with_version(schema_version: u16) -> Vec<u8> {
        format!(
            r#"{{
                "schema_version": {schema_version},
                "vault_id": "vault-test-1",
                "created_at": 1700000000,
                "updated_at": 1700000200,
                "items": [
                    {{
                        "id": "item-login-1",
                        "kind": "login_password",
                        "title": "Example login",
                        "username": "alice@example.test",
                        "primary_secret": "{TEST_SECRET_VALUE}",
                        "urls": ["https://example.test/login"],
                        "notes": "fake test notes",
                        "tags": ["personal", "test"],
                        "created_at": 1700000000,
                        "updated_at": 1700000100
                    }}
                ]
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn snapshot_roundtrip_preserves_non_secret_fields() {
        let snapshot = valid_snapshot();

        let encoded = encode_snapshot_payload(&snapshot).expect("valid snapshot should encode");
        let decoded = decode_snapshot_payload(&encoded).expect("valid snapshot should decode");

        assert_eq!(decoded.schema_version(), SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(decoded.vault_id(), "vault-test-1");
        assert_eq!(decoded.created_at(), timestamp(1_700_000_000));
        assert_eq!(decoded.updated_at(), timestamp(1_700_000_200));
        assert_eq!(decoded.items().len(), 1);

        let item = &decoded.items()[0];
        assert_eq!(item.id().as_str(), "item-login-1");
        assert_eq!(item.kind(), VaultItemKind::LoginPassword);
        assert_eq!(item.title(), "Example login");
        assert_eq!(item.username(), Some("alice@example.test"));
        assert_eq!(item.urls(), &["https://example.test/login".to_string()]);
        assert_eq!(item.notes(), Some("fake test notes"));
        assert_eq!(item.tags(), &["personal".to_string(), "test".to_string()]);
        assert_eq!(item.created_at(), timestamp(1_700_000_000));
        assert_eq!(item.updated_at(), timestamp(1_700_000_100));
    }

    #[test]
    fn snapshot_roundtrip_preserves_secret_value_after_decode() {
        let encoded =
            encode_snapshot_payload(&valid_snapshot()).expect("valid snapshot should encode");
        let decoded = decode_snapshot_payload(&encoded).expect("valid snapshot should decode");

        assert_eq!(
            decoded.items()[0].primary_secret().as_str(),
            TEST_SECRET_VALUE
        );
    }

    #[test]
    fn debug_output_redacts_secret_value() {
        let secret = SecretString::new(TEST_SECRET_VALUE);
        let debug_output = format!("{secret:?}");

        assert!(debug_output.contains("SecretString"));
        assert!(!debug_output.contains(TEST_SECRET_VALUE));
    }

    #[test]
    fn debug_output_redacts_snapshot_item_secrets() {
        let item_debug = format!("{:?}", valid_item());
        let snapshot_debug = format!("{:?}", valid_snapshot());

        assert!(!item_debug.contains(TEST_SECRET_VALUE));
        assert!(!snapshot_debug.contains(TEST_SECRET_VALUE));
        assert!(!item_debug.contains("primary_secret: \""));
        assert!(!snapshot_debug.contains("primary_secret: \""));
    }

    #[test]
    fn reject_unsupported_snapshot_version() {
        assert_eq!(
            decode_snapshot_payload(&valid_snapshot_payload_with_version(
                SNAPSHOT_SCHEMA_VERSION + 1
            )),
            Err(CairnError::UnsupportedSnapshotVersion {
                found: SNAPSHOT_SCHEMA_VERSION + 1,
                supported: SNAPSHOT_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn reject_empty_vault_id() {
        let snapshot = VaultSnapshot::new(
            " ",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![valid_item()],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot("vault_id is required"))
        );
    }

    #[test]
    fn reject_empty_item_id() {
        let item = VaultItem::login_password(
            VaultItemId::new(""),
            "Example login",
            SecretString::new(TEST_SECRET_VALUE),
            timestamp(1_700_000_000),
            timestamp(1_700_000_100),
        );
        let snapshot = VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![item],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot("item id is required"))
        );
    }

    #[test]
    fn reject_duplicate_item_ids() {
        let first = valid_item();
        let second = valid_item().with_title("Second login");
        let snapshot = VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![first, second],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot("item ids must be unique"))
        );
    }

    #[test]
    fn reject_empty_item_title() {
        let item = valid_item().with_title(" ");
        let snapshot = VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![item],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot("item title is required"))
        );
    }

    #[test]
    fn reject_empty_login_secret() {
        let item = VaultItem::login_password(
            VaultItemId::new("item-login-1"),
            "Example login",
            SecretString::new(""),
            timestamp(1_700_000_000),
            timestamp(1_700_000_100),
        );
        let snapshot = VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![item],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot(
                "login/password primary secret is required"
            ))
        );
    }

    #[test]
    fn reject_item_updated_before_created() {
        let item = VaultItem::login_password(
            VaultItemId::new("item-login-1"),
            "Example login",
            SecretString::new(TEST_SECRET_VALUE),
            timestamp(1_700_000_100),
            timestamp(1_700_000_000),
        );
        let snapshot = VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![item],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot(
                "item updated_at must not be earlier than created_at"
            ))
        );
    }

    #[test]
    fn reject_snapshot_updated_before_created() {
        let snapshot = VaultSnapshot::new(
            "vault-test-1",
            timestamp(1_700_000_200),
            timestamp(1_700_000_000),
            vec![valid_item()],
        );

        assert_eq!(
            snapshot.validate(),
            Err(CairnError::InvalidSnapshot(
                "snapshot updated_at must not be earlier than created_at"
            ))
        );
    }

    #[test]
    fn reject_malformed_snapshot_payload() {
        assert_eq!(
            decode_snapshot_payload(b"{not valid json"),
            Err(CairnError::MalformedSnapshot("snapshot JSON is malformed"))
        );
    }

    #[test]
    fn reject_unknown_item_kind() {
        let payload = br#"{
            "schema_version": 1,
            "vault_id": "vault-test-1",
            "created_at": 1700000000,
            "updated_at": 1700000200,
            "items": [
                {
                    "id": "item-login-1",
                    "kind": "secure_note",
                    "title": "Example login",
                    "username": null,
                    "primary_secret": "redacted-placeholder",
                    "urls": [],
                    "notes": null,
                    "tags": [],
                    "created_at": 1700000000,
                    "updated_at": 1700000100
                }
            ]
        }"#;

        assert_eq!(
            decode_snapshot_payload(payload),
            Err(CairnError::MalformedSnapshot("snapshot JSON is malformed"))
        );
    }

    #[test]
    fn encode_rejects_invalid_snapshot() {
        let snapshot = VaultSnapshot::new(
            "",
            timestamp(1_700_000_000),
            timestamp(1_700_000_200),
            vec![valid_item()],
        );

        assert_eq!(
            encode_snapshot_payload(&snapshot),
            Err(CairnError::InvalidSnapshot("vault_id is required"))
        );
    }

    #[test]
    fn decode_rejects_invalid_snapshot() {
        let payload = br#"{
            "schema_version": 1,
            "vault_id": "",
            "created_at": 1700000000,
            "updated_at": 1700000200,
            "items": []
        }"#;

        assert_eq!(
            decode_snapshot_payload(payload),
            Err(CairnError::InvalidSnapshot("vault_id is required"))
        );
    }

    #[test]
    fn snapshot_payload_roundtrips_through_encrypted_envelope() {
        let snapshot = valid_snapshot();
        let payload = encode_snapshot_payload(&snapshot).expect("valid snapshot should encode");
        let envelope = create_encrypted_envelope_for_tests(TEST_PASSPHRASE, &payload)
            .expect("test envelope should encrypt");
        let decrypted = decrypt_envelope_for_tests(TEST_PASSPHRASE, &envelope)
            .expect("test envelope should decrypt");
        let decoded = decode_snapshot_payload(&decrypted).expect("snapshot should decode");

        decoded
            .validate()
            .expect("decoded snapshot should validate");
        assert_eq!(decoded, snapshot);
    }
}
