use std::fmt;

use crate::error::CairnError;

pub const FORMAT_NAME: &str = "Cairn Vault Format version 1";
pub const FORMAT_SHORT_NAME: &str = "CVF-1";
pub const FILE_EXTENSION: &str = "cairn";
pub const MAGIC_BYTES: [u8; 10] = *b"CAIRN\0CVF1";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CRYPTO_SUITE_XCHACHA20_POLY1305: u16 = 1;
pub const KDF_SUITE_ARGON2ID: u16 = 1;
pub const FLAGS_NONE: u32 = 0;
pub const PAYLOAD_NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
pub const WRAPPED_ROOT_KEY_LEN: usize = 48;
pub const MAX_HEADER_LEN: usize = 4096;

pub(crate) const MAGIC_LEN: usize = MAGIC_BYTES.len();
pub(crate) const FORMAT_VERSION_OFFSET: usize = MAGIC_LEN;
pub(crate) const HEADER_LENGTH_OFFSET: usize = FORMAT_VERSION_OFFSET + 2;
pub(crate) const PREFIX_LEN: usize = HEADER_LENGTH_OFFSET + 4;

pub(crate) const BODY_SCHEMA_VERSION_OFFSET: usize = 0;
pub(crate) const BODY_CRYPTO_SUITE_OFFSET: usize = BODY_SCHEMA_VERSION_OFFSET + 2;
pub(crate) const BODY_KDF_SUITE_OFFSET: usize = BODY_CRYPTO_SUITE_OFFSET + 2;
pub(crate) const BODY_FLAGS_OFFSET: usize = BODY_KDF_SUITE_OFFSET + 2;
pub(crate) const BODY_ARGON_MEMORY_COST_OFFSET: usize = BODY_FLAGS_OFFSET + 4;
pub(crate) const BODY_ARGON_TIME_COST_OFFSET: usize = BODY_ARGON_MEMORY_COST_OFFSET + 4;
pub(crate) const BODY_ARGON_PARALLELISM_OFFSET: usize = BODY_ARGON_TIME_COST_OFFSET + 4;
pub(crate) const BODY_ARGON_OUTPUT_LEN_OFFSET: usize = BODY_ARGON_PARALLELISM_OFFSET + 4;
pub(crate) const BODY_SALT_LEN_OFFSET: usize = BODY_ARGON_OUTPUT_LEN_OFFSET + 4;
pub(crate) const BODY_SALT_OFFSET: usize = BODY_SALT_LEN_OFFSET + 2;
pub(crate) const BODY_WRAPPED_ROOT_KEY_LEN_OFFSET: usize = BODY_SALT_OFFSET + SALT_LEN;
pub(crate) const BODY_WRAPPED_ROOT_KEY_OFFSET: usize = BODY_WRAPPED_ROOT_KEY_LEN_OFFSET + 2;
pub(crate) const BODY_NONCE_LEN_OFFSET: usize = BODY_WRAPPED_ROOT_KEY_OFFSET + WRAPPED_ROOT_KEY_LEN;
pub(crate) const BODY_NONCE_OFFSET: usize = BODY_NONCE_LEN_OFFSET + 2;
pub(crate) const HEADER_BODY_LEN: usize = BODY_NONCE_OFFSET + PAYLOAD_NONCE_LEN;

#[derive(Clone, Eq, PartialEq)]
pub struct Argon2idParameters {
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: u32,
}

impl Argon2idParameters {
    pub const fn cvf1_default() -> Self {
        Self {
            memory_cost_kib: 194_560,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }

    pub const fn design_draft() -> Self {
        Self::cvf1_default()
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

    fn matches_cvf1_policy(&self) -> bool {
        self == &Self::cvf1_default()
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
    kdf_suite_id: u16,
}

impl WrappedRootKeySlotMetadata {
    pub fn new(slot_id: impl Into<String>) -> Self {
        Self {
            slot_id: slot_id.into(),
            kdf_suite_id: KDF_SUITE_ARGON2ID,
        }
    }

    pub fn slot_id(&self) -> &str {
        &self.slot_id
    }

    pub fn kdf_suite_id(&self) -> u16 {
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
    crypto_suite_id: u16,
    kdf_suite_id: u16,
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
            crypto_suite_id: CRYPTO_SUITE_XCHACHA20_POLY1305,
            kdf_suite_id: KDF_SUITE_ARGON2ID,
            kdf_parameters: Argon2idParameters::cvf1_default(),
            salt_len: SALT_LEN,
            wrapped_root_key_slots: 1,
            payload_nonce_len: PAYLOAD_NONCE_LEN,
            flags: FLAGS_NONE,
        }
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn crypto_suite_id(&self) -> u16 {
        self.crypto_suite_id
    }

    pub fn kdf_suite_id(&self) -> u16 {
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

#[derive(Clone, Eq, PartialEq)]
pub struct CvfHeader {
    schema_version: u16,
    crypto_suite_id: u16,
    kdf_suite_id: u16,
    flags: u32,
    kdf_parameters: Argon2idParameters,
    kdf_salt: Vec<u8>,
    wrapped_root_key: Vec<u8>,
    payload_nonce: Vec<u8>,
}

impl CvfHeader {
    pub fn new(
        kdf_parameters: Argon2idParameters,
        kdf_salt: Vec<u8>,
        wrapped_root_key: Vec<u8>,
        payload_nonce: Vec<u8>,
        flags: u32,
    ) -> Result<Self, CairnError> {
        Self::from_parts(CvfHeaderParts {
            schema_version: SCHEMA_VERSION,
            crypto_suite_id: CRYPTO_SUITE_XCHACHA20_POLY1305,
            kdf_suite_id: KDF_SUITE_ARGON2ID,
            flags,
            kdf_parameters,
            kdf_salt,
            wrapped_root_key,
            payload_nonce,
        })
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn crypto_suite_id(&self) -> u16 {
        self.crypto_suite_id
    }

    pub fn kdf_suite_id(&self) -> u16 {
        self.kdf_suite_id
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn kdf_parameters(&self) -> &Argon2idParameters {
        &self.kdf_parameters
    }

    pub fn kdf_salt(&self) -> &[u8] {
        &self.kdf_salt
    }

    pub fn wrapped_root_key(&self) -> &[u8] {
        &self.wrapped_root_key
    }

    pub fn payload_nonce(&self) -> &[u8] {
        &self.payload_nonce
    }

    fn from_parts(parts: CvfHeaderParts) -> Result<Self, CairnError> {
        let header = Self {
            schema_version: parts.schema_version,
            crypto_suite_id: parts.crypto_suite_id,
            kdf_suite_id: parts.kdf_suite_id,
            flags: parts.flags,
            kdf_parameters: parts.kdf_parameters,
            kdf_salt: parts.kdf_salt,
            wrapped_root_key: parts.wrapped_root_key,
            payload_nonce: parts.payload_nonce,
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<(), CairnError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CairnError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }

        if self.crypto_suite_id != CRYPTO_SUITE_XCHACHA20_POLY1305 {
            return Err(CairnError::UnsupportedCryptoSuite {
                found: self.crypto_suite_id,
                supported: CRYPTO_SUITE_XCHACHA20_POLY1305,
            });
        }

        if self.kdf_suite_id != KDF_SUITE_ARGON2ID {
            return Err(CairnError::UnsupportedKdfSuite {
                found: self.kdf_suite_id,
                supported: KDF_SUITE_ARGON2ID,
            });
        }

        if self.flags != FLAGS_NONE {
            return Err(CairnError::MalformedHeader("unsupported CVF-1 flags"));
        }

        if !self.kdf_parameters.matches_cvf1_policy() {
            return Err(CairnError::SecurityPolicyViolation(
                "Argon2id parameters do not match CVF-1 policy",
            ));
        }

        if self.kdf_salt.len() != SALT_LEN {
            return Err(CairnError::InvalidLength { field: "kdf_salt" });
        }

        if self.wrapped_root_key.len() != WRAPPED_ROOT_KEY_LEN {
            return Err(CairnError::InvalidLength {
                field: "wrapped_root_key",
            });
        }

        if self.payload_nonce.len() != PAYLOAD_NONCE_LEN {
            return Err(CairnError::InvalidLength {
                field: "payload_nonce",
            });
        }

        Ok(())
    }

    fn encode_body(&self) -> Result<Vec<u8>, CairnError> {
        self.validate()?;

        let mut output = Vec::with_capacity(HEADER_BODY_LEN);
        write_u16(&mut output, self.schema_version);
        write_u16(&mut output, self.crypto_suite_id);
        write_u16(&mut output, self.kdf_suite_id);
        write_u32(&mut output, self.flags);
        write_u32(&mut output, self.kdf_parameters.memory_cost_kib());
        write_u32(&mut output, self.kdf_parameters.time_cost());
        write_u32(&mut output, self.kdf_parameters.parallelism());
        write_u32(&mut output, self.kdf_parameters.output_len());
        write_len_u16(&mut output, self.kdf_salt.len(), "kdf_salt")?;
        output.extend_from_slice(&self.kdf_salt);
        write_len_u16(&mut output, self.wrapped_root_key.len(), "wrapped_root_key")?;
        output.extend_from_slice(&self.wrapped_root_key);
        write_len_u16(&mut output, self.payload_nonce.len(), "payload_nonce")?;
        output.extend_from_slice(&self.payload_nonce);

        if output.len() != HEADER_BODY_LEN {
            return Err(CairnError::MalformedHeader(
                "encoded header length does not match CVF-1 fields",
            ));
        }

        Ok(output)
    }

    fn decode_body(body: &[u8]) -> Result<Self, CairnError> {
        let mut cursor = Cursor::new(body);
        let schema_version = cursor.read_u16()?;
        let crypto_suite_id = cursor.read_u16()?;
        let kdf_suite_id = cursor.read_u16()?;
        let flags = cursor.read_u32()?;
        let kdf_parameters = Argon2idParameters {
            memory_cost_kib: cursor.read_u32()?,
            time_cost: cursor.read_u32()?,
            parallelism: cursor.read_u32()?,
            output_len: cursor.read_u32()?,
        };

        let salt_len = cursor.read_u16()? as usize;
        if salt_len != SALT_LEN {
            return Err(CairnError::InvalidLength { field: "kdf_salt" });
        }
        let kdf_salt = cursor.read_bytes(salt_len)?.to_vec();

        let wrapped_root_key_len = cursor.read_u16()? as usize;
        if wrapped_root_key_len != WRAPPED_ROOT_KEY_LEN {
            return Err(CairnError::InvalidLength {
                field: "wrapped_root_key",
            });
        }
        let wrapped_root_key = cursor.read_bytes(wrapped_root_key_len)?.to_vec();

        let payload_nonce_len = cursor.read_u16()? as usize;
        if payload_nonce_len != PAYLOAD_NONCE_LEN {
            return Err(CairnError::InvalidLength {
                field: "payload_nonce",
            });
        }
        let payload_nonce = cursor.read_bytes(payload_nonce_len)?.to_vec();

        if !cursor.is_finished() {
            return Err(CairnError::MalformedHeader(
                "header length does not match CVF-1 fields",
            ));
        }

        Self::from_parts(CvfHeaderParts {
            schema_version,
            crypto_suite_id,
            kdf_suite_id,
            flags,
            kdf_parameters,
            kdf_salt,
            wrapped_root_key,
            payload_nonce,
        })
    }
}

impl fmt::Debug for CvfHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CvfHeader")
            .field("schema_version", &self.schema_version)
            .field("crypto_suite_id", &self.crypto_suite_id)
            .field("kdf_suite_id", &self.kdf_suite_id)
            .field("flags", &self.flags)
            .field("kdf_parameters", &self.kdf_parameters)
            .field("kdf_salt_len", &self.kdf_salt.len())
            .field("wrapped_root_key_len", &self.wrapped_root_key.len())
            .field("payload_nonce_len", &self.payload_nonce.len())
            .finish()
    }
}

struct CvfHeaderParts {
    schema_version: u16,
    crypto_suite_id: u16,
    kdf_suite_id: u16,
    flags: u32,
    kdf_parameters: Argon2idParameters,
    kdf_salt: Vec<u8>,
    wrapped_root_key: Vec<u8>,
    payload_nonce: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CvfEnvelope {
    header: CvfHeader,
    payload_ciphertext: Vec<u8>,
}

impl CvfEnvelope {
    pub fn new(header: CvfHeader, payload_ciphertext: Vec<u8>) -> Result<Self, CairnError> {
        if payload_ciphertext.is_empty() {
            return Err(CairnError::MalformedEnvelope(
                "payload ciphertext is required",
            ));
        }

        header.validate()?;

        Ok(Self {
            header,
            payload_ciphertext,
        })
    }

    pub fn header(&self) -> &CvfHeader {
        &self.header
    }

    pub fn payload_ciphertext(&self) -> &[u8] {
        &self.payload_ciphertext
    }

    pub fn encode(&self) -> Result<Vec<u8>, CairnError> {
        let header_body = self.header.encode_body()?;
        if header_body.len() > MAX_HEADER_LEN {
            return Err(CairnError::InvalidLength { field: "header" });
        }

        let header_len = u32::try_from(header_body.len())
            .map_err(|_| CairnError::InvalidLength { field: "header" })?;
        let capacity = PREFIX_LEN
            .checked_add(header_body.len())
            .and_then(|len| len.checked_add(self.payload_ciphertext.len()))
            .ok_or(CairnError::InvalidLength { field: "envelope" })?;

        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(&MAGIC_BYTES);
        write_u16(&mut output, FORMAT_VERSION);
        write_u32(&mut output, header_len);
        output.extend_from_slice(&header_body);
        output.extend_from_slice(&self.payload_ciphertext);

        Ok(output)
    }
}

impl fmt::Debug for CvfEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CvfEnvelope")
            .field("header", &self.header)
            .field("payload_ciphertext_len", &self.payload_ciphertext.len())
            .finish()
    }
}

pub fn parse_envelope(input: &[u8]) -> Result<CvfEnvelope, CairnError> {
    if input.len() < PREFIX_LEN {
        return Err(CairnError::TruncatedInput { section: "prefix" });
    }

    if input[..MAGIC_LEN] != MAGIC_BYTES {
        return Err(CairnError::InvalidMagic);
    }

    let format_version = u16::from_be_bytes([
        input[FORMAT_VERSION_OFFSET],
        input[FORMAT_VERSION_OFFSET + 1],
    ]);
    if format_version != FORMAT_VERSION {
        return Err(CairnError::UnsupportedSchemaVersion {
            found: format_version,
            supported: FORMAT_VERSION,
        });
    }

    let header_len = u32::from_be_bytes([
        input[HEADER_LENGTH_OFFSET],
        input[HEADER_LENGTH_OFFSET + 1],
        input[HEADER_LENGTH_OFFSET + 2],
        input[HEADER_LENGTH_OFFSET + 3],
    ]) as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(CairnError::InvalidLength { field: "header" });
    }

    let header_end = PREFIX_LEN
        .checked_add(header_len)
        .ok_or(CairnError::InvalidLength { field: "header" })?;
    if input.len() < header_end {
        return Err(CairnError::TruncatedInput { section: "header" });
    }

    if input.len() == header_end {
        return Err(CairnError::MalformedEnvelope(
            "payload ciphertext is required",
        ));
    }

    let header = CvfHeader::decode_body(&input[PREFIX_LEN..header_end])?;
    let payload_ciphertext = input[header_end..].to_vec();

    CvfEnvelope::new(header, payload_ciphertext)
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_len_u16(output: &mut Vec<u8>, len: usize, field: &'static str) -> Result<(), CairnError> {
    let len = u16::try_from(len).map_err(|_| CairnError::InvalidLength { field })?;
    write_u16(output, len);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, CairnError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, CairnError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CairnError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CairnError::InvalidLength { field: "header" })?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CairnError::TruncatedInput { section: "header" })?;
        self.offset = end;
        Ok(bytes)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SALT: [u8; SALT_LEN] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const TEST_WRAPPED_ROOT_KEY: [u8; WRAPPED_ROOT_KEY_LEN] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
        0x6d, 0x6e, 0x6f,
    ];
    const TEST_NONCE: [u8; PAYLOAD_NONCE_LEN] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    ];
    const TEST_PAYLOAD: [u8; 5] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4];

    fn valid_header() -> CvfHeader {
        CvfHeader::new(
            Argon2idParameters::cvf1_default(),
            TEST_SALT.to_vec(),
            TEST_WRAPPED_ROOT_KEY.to_vec(),
            TEST_NONCE.to_vec(),
            FLAGS_NONE,
        )
        .expect("test header should be valid")
    }

    fn valid_envelope() -> CvfEnvelope {
        CvfEnvelope::new(valid_header(), TEST_PAYLOAD.to_vec())
            .expect("test envelope should be valid")
    }

    fn valid_envelope_bytes() -> Vec<u8> {
        valid_envelope()
            .encode()
            .expect("test envelope should encode")
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn cvf1_header_design_uses_explicit_ids_and_lengths() {
        let design = VaultHeaderDesign::cvf1_design_draft();

        assert_eq!(design.schema_version(), SCHEMA_VERSION);
        assert_eq!(design.crypto_suite_id(), CRYPTO_SUITE_XCHACHA20_POLY1305);
        assert_eq!(design.kdf_suite_id(), KDF_SUITE_ARGON2ID);
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

    #[test]
    fn envelope_debug_output_contains_lengths_not_bytes() {
        let debug_output = format!("{:?}", valid_envelope());

        assert!(debug_output.contains("payload_ciphertext_len"));
        assert!(debug_output.contains("wrapped_root_key_len"));
        assert!(!debug_output.contains("64, 65, 66"));
        assert!(!debug_output.contains("160, 161, 162"));
    }

    #[test]
    fn roundtrip_valid_envelope() {
        let envelope = valid_envelope();
        let encoded = envelope.encode().expect("valid envelope should encode");
        let decoded = parse_envelope(&encoded).expect("valid envelope should parse");

        assert_eq!(decoded, envelope);
        assert_eq!(decoded.header().schema_version(), SCHEMA_VERSION);
        assert_eq!(
            decoded.header().crypto_suite_id(),
            CRYPTO_SUITE_XCHACHA20_POLY1305
        );
        assert_eq!(decoded.header().kdf_suite_id(), KDF_SUITE_ARGON2ID);
        assert_eq!(decoded.payload_ciphertext(), TEST_PAYLOAD);
        assert_eq!(encoded, decoded.encode().expect("roundtrip should encode"));
    }

    #[test]
    fn reject_bad_magic() {
        let mut bytes = valid_envelope_bytes();
        bytes[0] ^= 0xff;

        assert_eq!(parse_envelope(&bytes), Err(CairnError::InvalidMagic));
    }

    #[test]
    fn reject_truncated_prefix() {
        let bytes = &valid_envelope_bytes()[..PREFIX_LEN - 1];

        assert_eq!(
            parse_envelope(bytes),
            Err(CairnError::TruncatedInput { section: "prefix" })
        );
    }

    #[test]
    fn reject_truncated_header() {
        let mut bytes = valid_envelope_bytes();
        bytes.truncate(PREFIX_LEN + HEADER_BODY_LEN - 1);

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::TruncatedInput { section: "header" })
        );
    }

    #[test]
    fn reject_unsupported_schema_version() {
        let mut bytes = valid_envelope_bytes();
        write_u16(
            &mut bytes,
            PREFIX_LEN + BODY_SCHEMA_VERSION_OFFSET,
            SCHEMA_VERSION + 1,
        );

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::UnsupportedSchemaVersion {
                found: SCHEMA_VERSION + 1,
                supported: SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn reject_unsupported_crypto_suite() {
        let mut bytes = valid_envelope_bytes();
        write_u16(&mut bytes, PREFIX_LEN + BODY_CRYPTO_SUITE_OFFSET, 99);

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::UnsupportedCryptoSuite {
                found: 99,
                supported: CRYPTO_SUITE_XCHACHA20_POLY1305,
            })
        );
    }

    #[test]
    fn reject_unsupported_kdf_suite() {
        let mut bytes = valid_envelope_bytes();
        write_u16(&mut bytes, PREFIX_LEN + BODY_KDF_SUITE_OFFSET, 77);

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::UnsupportedKdfSuite {
                found: 77,
                supported: KDF_SUITE_ARGON2ID,
            })
        );
    }

    #[test]
    fn reject_invalid_salt_length() {
        let mut bytes = valid_envelope_bytes();
        write_u16(
            &mut bytes,
            PREFIX_LEN + BODY_SALT_LEN_OFFSET,
            (SALT_LEN - 1) as u16,
        );

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::InvalidLength { field: "kdf_salt" })
        );
    }

    #[test]
    fn reject_invalid_nonce_length() {
        let mut bytes = valid_envelope_bytes();
        write_u16(
            &mut bytes,
            PREFIX_LEN + BODY_NONCE_LEN_OFFSET,
            (PAYLOAD_NONCE_LEN - 1) as u16,
        );

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::InvalidLength {
                field: "payload_nonce"
            })
        );
    }

    #[test]
    fn reject_invalid_wrapped_key_length() {
        let mut bytes = valid_envelope_bytes();
        write_u16(
            &mut bytes,
            PREFIX_LEN + BODY_WRAPPED_ROOT_KEY_LEN_OFFSET,
            (WRAPPED_ROOT_KEY_LEN - 1) as u16,
        );

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::InvalidLength {
                field: "wrapped_root_key"
            })
        );
    }

    #[test]
    fn reject_header_length_too_large_or_inconsistent() {
        let mut too_large = valid_envelope_bytes();
        write_u32(
            &mut too_large,
            HEADER_LENGTH_OFFSET,
            (MAX_HEADER_LEN as u32) + 1,
        );
        assert_eq!(
            parse_envelope(&too_large),
            Err(CairnError::InvalidLength { field: "header" })
        );

        let mut inconsistent = valid_envelope_bytes();
        write_u32(
            &mut inconsistent,
            HEADER_LENGTH_OFFSET,
            (HEADER_BODY_LEN + 1) as u32,
        );
        assert_eq!(
            parse_envelope(&inconsistent),
            Err(CairnError::MalformedHeader(
                "header length does not match CVF-1 fields"
            ))
        );
    }

    #[test]
    fn reject_empty_payload_if_disallowed() {
        let mut bytes = valid_envelope_bytes();
        bytes.truncate(PREFIX_LEN + HEADER_BODY_LEN);

        assert_eq!(
            parse_envelope(&bytes),
            Err(CairnError::MalformedEnvelope(
                "payload ciphertext is required"
            ))
        );
    }

    #[test]
    fn tamper_header_byte_changes_parsed_header_or_fails_validation() {
        let original = valid_envelope_bytes();

        for index in PREFIX_LEN..PREFIX_LEN + HEADER_BODY_LEN {
            let mut tampered = original.clone();
            tampered[index] ^= 0x01;

            if let Ok(parsed) = parse_envelope(&tampered) {
                assert_ne!(
                    parsed.header(),
                    valid_envelope().header(),
                    "header byte {index} changed but parsed header stayed the same"
                );
            }
        }
    }
}
