use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CairnError {
    AuthenticationFailed,
    InvalidLength { field: &'static str },
    InvalidKdfParameters(&'static str),
    InvalidMagic,
    InvalidSnapshot(&'static str),
    InvalidVaultId,
    InvalidVaultFormat(&'static str),
    MalformedEnvelope(&'static str),
    MalformedHeader(&'static str),
    MalformedSnapshot(&'static str),
    NotImplemented(&'static str),
    RandomSourceFailed,
    SecurityPolicyViolation(&'static str),
    SerializationFailed(&'static str),
    TruncatedInput { section: &'static str },
    UnsupportedCryptoSuite { found: u16, supported: u16 },
    UnsupportedFormatVersion { found: u16, supported: u16 },
    UnsupportedKdfSuite { found: u16, supported: u16 },
    UnsupportedSchemaVersion { found: u16, supported: u16 },
    UnsupportedSnapshotVersion { found: u16, supported: u16 },
}

impl fmt::Display for CairnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::InvalidLength { field } => write!(formatter, "{field} length is invalid"),
            Self::InvalidKdfParameters(reason) => {
                write!(formatter, "KDF parameters are invalid: {reason}")
            }
            Self::InvalidMagic => formatter.write_str("vault magic bytes are invalid"),
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "vault snapshot is invalid: {reason}")
            }
            Self::InvalidVaultId => formatter.write_str("vault identifier is invalid"),
            Self::InvalidVaultFormat(reason) => {
                write!(formatter, "vault format is invalid: {reason}")
            }
            Self::MalformedEnvelope(reason) => {
                write!(formatter, "vault envelope is malformed: {reason}")
            }
            Self::MalformedHeader(reason) => {
                write!(formatter, "vault header is malformed: {reason}")
            }
            Self::MalformedSnapshot(reason) => {
                write!(formatter, "vault snapshot is malformed: {reason}")
            }
            Self::NotImplemented(feature) => write!(formatter, "{feature} is not implemented yet"),
            Self::RandomSourceFailed => formatter.write_str("secure random source failed"),
            Self::SecurityPolicyViolation(reason) => {
                write!(formatter, "security policy violation: {reason}")
            }
            Self::SerializationFailed(reason) => {
                write!(formatter, "serialization failed: {reason}")
            }
            Self::TruncatedInput { section } => {
                write!(formatter, "vault input is truncated in {section}")
            }
            Self::UnsupportedCryptoSuite { found, supported } => write!(
                formatter,
                "unsupported crypto suite {found}; supported suite is {supported}"
            ),
            Self::UnsupportedFormatVersion { found, supported } => write!(
                formatter,
                "unsupported format version {found}; supported version is {supported}"
            ),
            Self::UnsupportedKdfSuite { found, supported } => write!(
                formatter,
                "unsupported KDF suite {found}; supported suite is {supported}"
            ),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported schema version {found}; supported version is {supported}"
            ),
            Self::UnsupportedSnapshotVersion { found, supported } => write!(
                formatter,
                "unsupported snapshot schema version {found}; supported version is {supported}"
            ),
        }
    }
}

impl std::error::Error for CairnError {}
