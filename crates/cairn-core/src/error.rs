use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CairnError {
    AuthenticationFailed,
    InvalidLength { field: &'static str },
    InvalidMagic,
    InvalidVaultId,
    InvalidVaultFormat(&'static str),
    MalformedEnvelope(&'static str),
    MalformedHeader(&'static str),
    NotImplemented(&'static str),
    SecurityPolicyViolation(&'static str),
    TruncatedInput { section: &'static str },
    UnsupportedCryptoSuite { found: u16, supported: u16 },
    UnsupportedKdfSuite { found: u16, supported: u16 },
    UnsupportedSchemaVersion { found: u16, supported: u16 },
}

impl fmt::Display for CairnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("authentication failed"),
            Self::InvalidLength { field } => write!(formatter, "{field} length is invalid"),
            Self::InvalidMagic => formatter.write_str("vault magic bytes are invalid"),
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
            Self::NotImplemented(feature) => write!(formatter, "{feature} is not implemented yet"),
            Self::SecurityPolicyViolation(reason) => {
                write!(formatter, "security policy violation: {reason}")
            }
            Self::TruncatedInput { section } => {
                write!(formatter, "vault input is truncated in {section}")
            }
            Self::UnsupportedCryptoSuite { found, supported } => write!(
                formatter,
                "unsupported crypto suite {found}; supported suite is {supported}"
            ),
            Self::UnsupportedKdfSuite { found, supported } => write!(
                formatter,
                "unsupported KDF suite {found}; supported suite is {supported}"
            ),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported schema version {found}; supported version is {supported}"
            ),
        }
    }
}

impl std::error::Error for CairnError {}
