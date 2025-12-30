//! License parsing and decoding functionality.
//!
//! This module handles the loading and decoding of signed licenses.
//! It verifies cryptographic signatures and extracts the license payload.
//!
//! # Client-Side Usage
//!
//! This module is intended for use in client applications to load and
//! verify licenses issued by the software publisher.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::crypto::PublicKey;
use crate::error::{LicenseError, Result};
use crate::models::{
    LicensePayload, SignedLicense, MAX_SUPPORTED_LICENSE_VERSION, MIN_SUPPORTED_LICENSE_VERSION,
};

// =============================================================================
// License Parser
// =============================================================================

/// Parser for loading and verifying signed licenses.
///
/// The parser takes a public key and uses it to verify license signatures.
/// Only licenses signed by the corresponding private key will be accepted.
///
/// # Security
///
/// The parser only accepts licenses with valid signatures. Any tampering
/// with the license payload will cause signature verification to fail.
///
/// # Example
///
/// ```
/// use rust_license_key::parser::LicenseParser;
/// use rust_license_key::crypto::PublicKey;
///
/// // The public key embedded in your application
/// let public_key_base64 = "..."; // Your public key here
///
/// // In a real application:
/// // let public_key = PublicKey::from_base64(public_key_base64).unwrap();
/// // let parser = LicenseParser::new(public_key);
/// // let license = parser.parse_json(&license_file_contents).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct LicenseParser {
    /// The public key used to verify license signatures.
    public_key: PublicKey,
}

impl LicenseParser {
    /// Creates a new license parser with the given public key.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The publisher's public key for signature verification.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Creates a new license parser from a base64-encoded public key.
    ///
    /// # Arguments
    ///
    /// * `public_key_base64` - The base64-encoded public key string.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is invalid or malformed.
    pub fn from_public_key_base64(public_key_base64: &str) -> Result<Self> {
        let public_key = PublicKey::from_base64(public_key_base64)?;
        Ok(Self::new(public_key))
    }

    /// Parses a signed license from a JSON string.
    ///
    /// This method:
    /// 1. Parses the JSON structure.
    /// 2. Verifies the cryptographic signature.
    /// 3. Decodes the license payload.
    /// 4. Validates the license format version.
    ///
    /// # Arguments
    ///
    /// * `json` - The JSON string containing the signed license.
    ///
    /// # Returns
    ///
    /// The verified and decoded license payload.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The JSON is malformed.
    /// - The signature is invalid.
    /// - The payload cannot be decoded.
    /// - The license version is not supported.
    pub fn parse_json(&self, json: &str) -> Result<LicensePayload> {
        // Step 1: Parse the signed license structure
        let signed_license = SignedLicense::from_json(json).map_err(|e| {
            LicenseError::JsonDeserializationFailed {
                reason: e.to_string(),
            }
        })?;

        self.parse_signed_license(&signed_license)
    }

    /// Parses a `SignedLicense` structure directly.
    ///
    /// Use this when you already have a `SignedLicense` object,
    /// for example from custom deserialization logic.
    ///
    /// # Arguments
    ///
    /// * `signed_license` - The signed license to verify and decode.
    ///
    /// # Returns
    ///
    /// The verified and decoded license payload.
    pub fn parse_signed_license(&self, signed_license: &SignedLicense) -> Result<LicensePayload> {
        // Step 2: Verify the signature
        // The signature is computed over the base64-encoded payload
        self.public_key
            .verify_base64(
                signed_license.encoded_payload.as_bytes(),
                &signed_license.encoded_signature,
            )
            .map_err(|_| LicenseError::InvalidSignature)?;

        // Step 3: Decode the payload from base64
        let payload_bytes = BASE64_STANDARD
            .decode(&signed_license.encoded_payload)
            .map_err(|e| LicenseError::Base64DecodingFailed {
                reason: e.to_string(),
            })?;

        // Step 4: Parse the JSON payload
        let payload: LicensePayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
            LicenseError::JsonDeserializationFailed {
                reason: e.to_string(),
            }
        })?;

        // Step 5: Validate the license format version
        if payload.format_version < MIN_SUPPORTED_LICENSE_VERSION {
            return Err(LicenseError::UnsupportedLicenseVersion {
                found: payload.format_version,
                supported: format!(
                    "{} to {}",
                    MIN_SUPPORTED_LICENSE_VERSION, MAX_SUPPORTED_LICENSE_VERSION
                ),
            });
        }

        if payload.format_version > MAX_SUPPORTED_LICENSE_VERSION {
            return Err(LicenseError::UnsupportedLicenseVersion {
                found: payload.format_version,
                supported: format!(
                    "{} to {}",
                    MIN_SUPPORTED_LICENSE_VERSION, MAX_SUPPORTED_LICENSE_VERSION
                ),
            });
        }

        Ok(payload)
    }

    /// Attempts to decode a license without signature verification.
    ///
    /// # Warning
    ///
    /// This method bypasses security and should only be used for debugging
    /// or inspection purposes. Never use the returned payload for access
    /// control decisions.
    ///
    /// # Arguments
    ///
    /// * `json` - The JSON string containing the signed license.
    ///
    /// # Returns
    ///
    /// The decoded payload and a boolean indicating if the signature was valid.
    pub fn decode_unverified(&self, json: &str) -> Result<(LicensePayload, bool)> {
        // Parse the signed license structure
        let signed_license = SignedLicense::from_json(json).map_err(|e| {
            LicenseError::JsonDeserializationFailed {
                reason: e.to_string(),
            }
        })?;

        // Check signature validity
        let signature_valid = self
            .public_key
            .verify_base64(
                signed_license.encoded_payload.as_bytes(),
                &signed_license.encoded_signature,
            )
            .is_ok();

        // Decode the payload regardless of signature
        let payload_bytes = BASE64_STANDARD
            .decode(&signed_license.encoded_payload)
            .map_err(|e| LicenseError::Base64DecodingFailed {
                reason: e.to_string(),
            })?;

        let payload: LicensePayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
            LicenseError::JsonDeserializationFailed {
                reason: e.to_string(),
            }
        })?;

        Ok((payload, signature_valid))
    }

    /// Returns a reference to the parser's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Parses a signed license using a base64-encoded public key.
///
/// This is a convenience function for one-shot license parsing.
/// For multiple license parsing operations, create a `LicenseParser` instance.
///
/// # Arguments
///
/// * `license_json` - The JSON string containing the signed license.
/// * `public_key_base64` - The base64-encoded public key.
///
/// # Returns
///
/// The verified and decoded license payload.
pub fn parse_license(license_json: &str, public_key_base64: &str) -> Result<LicensePayload> {
    let parser = LicenseParser::from_public_key_base64(public_key_base64)?;
    parser.parse_json(license_json)
}

/// Extracts the raw payload from a signed license without verification.
///
/// # Warning
///
/// This function is for inspection only. Never trust unverified payload data.
///
/// # Arguments
///
/// * `license_json` - The JSON string containing the signed license.
///
/// # Returns
///
/// The raw payload JSON as a string.
pub fn extract_payload_unverified(license_json: &str) -> Result<String> {
    let signed_license = SignedLicense::from_json(license_json).map_err(|e| {
        LicenseError::JsonDeserializationFailed {
            reason: e.to_string(),
        }
    })?;

    let payload_bytes = BASE64_STANDARD
        .decode(&signed_license.encoded_payload)
        .map_err(|e| LicenseError::Base64DecodingFailed {
            reason: e.to_string(),
        })?;

    String::from_utf8(payload_bytes).map_err(|e| LicenseError::InvalidLicenseFormat {
        reason: format!("payload is not valid UTF-8: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::LicenseBuilder;
    use crate::crypto::KeyPair;
    use chrono::Duration;

    fn create_test_license(key_pair: &KeyPair) -> String {
        LicenseBuilder::new()
            .license_id("TEST-LIC-001")
            .customer_id("TEST-CUST-001")
            .customer_name("Test Customer")
            .expires_in(Duration::days(30))
            .allowed_feature("premium")
            .build_and_sign_to_json(key_pair)
            .expect("Should create test license")
    }

    #[test]
    fn test_parse_valid_license() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let license_json = create_test_license(&key_pair);

        let parser = LicenseParser::new(key_pair.public_key());
        let payload = parser
            .parse_json(&license_json)
            .expect("Should parse license");

        assert_eq!(payload.license_id, "TEST-LIC-001");
        assert_eq!(payload.customer_id, "TEST-CUST-001");
        assert_eq!(payload.customer_name.as_deref(), Some("Test Customer"));
    }

    #[test]
    fn test_parse_with_wrong_key_fails() {
        let key_pair_1 = KeyPair::generate().expect("Key generation should succeed");
        let key_pair_2 = KeyPair::generate().expect("Key generation should succeed");

        // Create license with key_pair_1
        let license_json = create_test_license(&key_pair_1);

        // Try to parse with key_pair_2's public key
        let parser = LicenseParser::new(key_pair_2.public_key());
        let result = parser.parse_json(&license_json);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::InvalidSignature
        ));
    }

    #[test]
    fn test_parse_tampered_license_fails() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let license_json = create_test_license(&key_pair);

        // Parse the license JSON to get the structure
        let mut signed: SignedLicense = serde_json::from_str(&license_json).expect("Should parse");

        // Tamper with the payload (modify a character in the base64)
        let mut chars: Vec<char> = signed.encoded_payload.chars().collect();
        if let Some(c) = chars.get_mut(10) {
            *c = if *c == 'A' { 'B' } else { 'A' };
        }
        signed.encoded_payload = chars.into_iter().collect();

        // Serialize back to JSON
        let tampered_json = serde_json::to_string(&signed).expect("Should serialize");

        // Try to parse the tampered license
        let parser = LicenseParser::new(key_pair.public_key());
        let result = parser.parse_json(&tampered_json);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_json() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let parser = LicenseParser::new(key_pair.public_key());

        let result = parser.parse_json("not valid json");
        assert!(matches!(
            result.unwrap_err(),
            LicenseError::JsonDeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_decode_unverified() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let license_json = create_test_license(&key_pair);

        let parser = LicenseParser::new(key_pair.public_key());
        let (payload, signature_valid) = parser
            .decode_unverified(&license_json)
            .expect("Should decode");

        assert!(signature_valid);
        assert_eq!(payload.license_id, "TEST-LIC-001");
    }

    #[test]
    fn test_decode_unverified_with_wrong_key() {
        let key_pair_1 = KeyPair::generate().expect("Key generation should succeed");
        let key_pair_2 = KeyPair::generate().expect("Key generation should succeed");

        let license_json = create_test_license(&key_pair_1);

        let parser = LicenseParser::new(key_pair_2.public_key());
        let (payload, signature_valid) = parser
            .decode_unverified(&license_json)
            .expect("Should decode");

        // Signature should be invalid but payload still decoded
        assert!(!signature_valid);
        assert_eq!(payload.license_id, "TEST-LIC-001");
    }

    #[test]
    fn test_extract_payload_unverified() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let license_json = create_test_license(&key_pair);

        let payload_json = extract_payload_unverified(&license_json).expect("Should extract");

        // Verify it's valid JSON containing expected fields
        let value: serde_json::Value =
            serde_json::from_str(&payload_json).expect("Should be valid JSON");
        assert_eq!(value["id"], "TEST-LIC-001");
    }

    #[test]
    fn test_from_public_key_base64() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let public_key_base64 = key_pair.public_key_base64();

        let parser = LicenseParser::from_public_key_base64(&public_key_base64)
            .expect("Should create parser");

        let license_json = create_test_license(&key_pair);
        let payload = parser.parse_json(&license_json).expect("Should parse");

        assert_eq!(payload.license_id, "TEST-LIC-001");
    }

    #[test]
    fn test_parse_license_convenience_function() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let public_key_base64 = key_pair.public_key_base64();
        let license_json = create_test_license(&key_pair);

        let payload =
            parse_license(&license_json, &public_key_base64).expect("Should parse license");

        assert_eq!(payload.license_id, "TEST-LIC-001");
    }
}
