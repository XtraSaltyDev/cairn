use std::fmt;

use crate::error::CairnError;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct VaultId(String);

impl VaultId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn try_new(value: impl Into<String>) -> Result<Self, CairnError> {
        let value = value.into();

        if value.trim().is_empty() {
            return Err(CairnError::InvalidVaultId);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VaultId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultId")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VaultMetadata {
    vault_id: VaultId,
    item_count: usize,
}

impl VaultMetadata {
    pub fn new(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            item_count: 0,
        }
    }

    pub fn with_item_count(mut self, item_count: usize) -> Self {
        self.item_count = item_count;
        self
    }

    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    pub fn item_count(&self) -> usize {
        self.item_count
    }
}

impl fmt::Debug for VaultMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultMetadata")
            .field("vault_id", &self.vault_id)
            .field("item_count", &self.item_count)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultItemKind {
    Login,
    SecureNote,
    RecoveryMaterial,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VaultItemSummary {
    id: String,
    label: String,
    kind: VaultItemKind,
}

impl VaultItemSummary {
    pub fn new(id: impl Into<String>, label: impl Into<String>, kind: VaultItemKind) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn kind(&self) -> &VaultItemKind {
        &self.kind
    }
}

impl fmt::Debug for VaultItemSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultItemSummary")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .finish()
    }
}
