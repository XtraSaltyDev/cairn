use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CairnError {
    InvalidVaultId,
    InvalidVaultFormat(&'static str),
    NotImplemented(&'static str),
    SecurityPolicyViolation(&'static str),
    UnsupportedSchemaVersion { found: u16, supported: u16 },
}

impl fmt::Display for CairnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVaultId => formatter.write_str("vault identifier is invalid"),
            Self::InvalidVaultFormat(reason) => {
                write!(formatter, "vault format is invalid: {reason}")
            }
            Self::NotImplemented(feature) => write!(formatter, "{feature} is not implemented yet"),
            Self::SecurityPolicyViolation(reason) => {
                write!(formatter, "security policy violation: {reason}")
            }
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported schema version {found}; supported version is {supported}"
            ),
        }
    }
}

impl std::error::Error for CairnError {}
