//! Cryptographic operations for license signing and verification.
//!
//! This module provides Ed25519 key pair generation, signing, and verification
//! functionality. It uses the `ed25519-dalek` crate for cryptographic operations.
//!
//! # Security Notes
//!
//! - Private keys must be kept secret by the license publisher.
//! - Public keys can be safely embedded in client applications.
//! - The Ed25519 algorithm provides 128-bit security level.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;

use crate::error::{LicenseError, Result};

// =============================================================================
// Key Pair
// =============================================================================

/// An Ed25519 key pair for signing and verifying licenses.
///
/// The key pair consists of:
/// - A private key (32 bytes) used by the publisher to sign licenses.
/// - A public key (32 bytes) embedded in client applications for verification.
///
/// # Example
///
/// ```
/// use rust_license_key::crypto::KeyPair;
///
/// // Generate a new key pair
/// let key_pair = KeyPair::generate().expect("Failed to generate key pair");
///
/// // Export keys for storage
/// let private_key_base64 = key_pair.private_key_base64();
/// let public_key_base64 = key_pair.public_key_base64();
///
/// println!("Keep this private: {}", private_key_base64);
/// println!("Embed in client: {}", public_key_base64);
/// ```
#[derive(Debug)]
pub struct KeyPair {
    /// The Ed25519 signing key (private key).
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generates a new random Ed25519 key pair.
    ///
    /// Uses the operating system's cryptographically secure random number
    /// generator (CSPRNG) to generate the key material.
    ///
    /// # Returns
    ///
    /// A new `KeyPair` instance, or an error if key generation fails.
    ///
    /// # Security
    ///
    /// The generated private key should be stored securely and never shared.
    /// Only the public key should be distributed with client applications.
    pub fn generate() -> Result<Self> {
        // Use OS-provided CSPRNG for secure key generation
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        Ok(Self { signing_key })
    }

    /// Creates a key pair from a base64-encoded private key.
    ///
    /// # Arguments
    ///
    /// * `private_key_base64` - The base64-encoded private key (32 bytes when decoded).
    ///
    /// # Security
    ///
    /// This function should only be used in secure publisher-side tooling,
    /// never in client applications.
    pub fn from_private_key_base64(private_key_base64: &str) -> Result<Self> {
        let private_key_bytes = BASE64_STANDARD.decode(private_key_base64).map_err(|e| {
            LicenseError::InvalidPrivateKey {
                reason: format!("invalid base64 encoding: {}", e),
            }
        })?;

        if private_key_bytes.len() != SECRET_KEY_LENGTH {
            return Err(LicenseError::InvalidPrivateKey {
                reason: format!(
                    "invalid key length: expected {} bytes, got {}",
                    SECRET_KEY_LENGTH,
                    private_key_bytes.len()
                ),
            });
        }

        let key_bytes: [u8; SECRET_KEY_LENGTH] =
            private_key_bytes
                .try_into()
                .map_err(|_| LicenseError::InvalidPrivateKey {
                    reason: "failed to convert key bytes".to_string(),
                })?;

        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Self { signing_key })
    }

    /// Creates a key pair from raw private key bytes.
    ///
    /// # Arguments
    ///
    /// * `private_key_bytes` - The raw private key bytes (exactly 32 bytes).
    pub fn from_private_key_bytes(private_key_bytes: &[u8]) -> Result<Self> {
        if private_key_bytes.len() != SECRET_KEY_LENGTH {
            return Err(LicenseError::InvalidPrivateKey {
                reason: format!(
                    "invalid key length: expected {} bytes, got {}",
                    SECRET_KEY_LENGTH,
                    private_key_bytes.len()
                ),
            });
        }

        let key_bytes: [u8; SECRET_KEY_LENGTH] =
            private_key_bytes
                .try_into()
                .map_err(|_| LicenseError::InvalidPrivateKey {
                    reason: "failed to convert key bytes".to_string(),
                })?;

        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Self { signing_key })
    }

    /// Returns the public key for this key pair.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Returns the private key as raw bytes.
    ///
    /// # Security
    ///
    /// Handle the returned bytes with care. They should be stored securely
    /// and never exposed to untrusted parties.
    pub fn private_key_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Returns the private key as a base64-encoded string.
    ///
    /// # Security
    ///
    /// Handle the returned string with care. It should be stored securely
    /// and never exposed to untrusted parties.
    pub fn private_key_base64(&self) -> String {
        BASE64_STANDARD.encode(self.signing_key.to_bytes())
    }

    /// Returns the public key as a base64-encoded string.
    ///
    /// This is the value that should be embedded in client applications.
    pub fn public_key_base64(&self) -> String {
        self.public_key().to_base64()
    }

    /// Signs the given data with the private key.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign (typically the serialized license payload).
    ///
    /// # Returns
    ///
    /// The Ed25519 signature as raw bytes.
    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let signature = self.signing_key.sign(data);
        signature.to_bytes()
    }

    /// Signs the given data and returns the signature as base64.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign.
    ///
    /// # Returns
    ///
    /// The base64-encoded signature.
    pub fn sign_base64(&self, data: &[u8]) -> String {
        BASE64_STANDARD.encode(self.sign(data))
    }
}

// =============================================================================
// Public Key
// =============================================================================

/// An Ed25519 public key for verifying license signatures.
///
/// This is the key that should be embedded in client applications.
/// It can only verify signatures, not create them.
///
/// # Example
///
/// ```
/// use rust_license_key::crypto::PublicKey;
///
/// // Load from base64 (e.g., embedded in application)
/// let public_key_base64 = "..."; // Your public key here
/// // let public_key = PublicKey::from_base64(public_key_base64).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The Ed25519 verifying key.
    verifying_key: VerifyingKey,
}

impl PublicKey {
    /// Creates a public key from a base64-encoded string.
    ///
    /// # Arguments
    ///
    /// * `public_key_base64` - The base64-encoded public key (32 bytes when decoded).
    pub fn from_base64(public_key_base64: &str) -> Result<Self> {
        let public_key_bytes = BASE64_STANDARD.decode(public_key_base64).map_err(|e| {
            LicenseError::InvalidPublicKey {
                reason: format!("invalid base64 encoding: {}", e),
            }
        })?;

        Self::from_bytes(&public_key_bytes)
    }

    /// Creates a public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw public key bytes (exactly 32 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(LicenseError::InvalidPublicKey {
                reason: format!(
                    "invalid key length: expected {} bytes, got {}",
                    PUBLIC_KEY_LENGTH,
                    bytes.len()
                ),
            });
        }

        let key_bytes: [u8; PUBLIC_KEY_LENGTH] =
            bytes
                .try_into()
                .map_err(|_| LicenseError::InvalidPublicKey {
                    reason: "failed to convert key bytes".to_string(),
                })?;

        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|e| LicenseError::InvalidPublicKey {
                reason: format!("invalid public key: {}", e),
            })?;

        Ok(Self { verifying_key })
    }

    /// Returns the public key as raw bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.verifying_key.to_bytes()
    }

    /// Returns the public key as a base64-encoded string.
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.verifying_key.to_bytes())
    }

    /// Verifies a signature against the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The original data that was signed.
    /// * `signature_bytes` - The signature to verify (64 bytes).
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, or an error if verification fails.
    pub fn verify(&self, data: &[u8], signature_bytes: &[u8]) -> Result<()> {
        if signature_bytes.len() != SIGNATURE_LENGTH {
            return Err(LicenseError::InvalidSignature);
        }

        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature_bytes
            .try_into()
            .map_err(|_| LicenseError::InvalidSignature)?;

        let signature = Signature::from_bytes(&sig_bytes);

        self.verifying_key
            .verify(data, &signature)
            .map_err(|_| LicenseError::InvalidSignature)
    }

    /// Verifies a base64-encoded signature against the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - The original data that was signed.
    /// * `signature_base64` - The base64-encoded signature.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, or an error if verification fails.
    pub fn verify_base64(&self, data: &[u8], signature_base64: &str) -> Result<()> {
        let signature_bytes = BASE64_STANDARD
            .decode(signature_base64)
            .map_err(|_| LicenseError::InvalidSignature)?;

        self.verify(data, &signature_bytes)
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Generates a new key pair and returns the keys as base64 strings.
///
/// This is a convenience function for quickly generating keys.
///
/// # Returns
///
/// A tuple of (private_key_base64, public_key_base64).
///
/// # Example
///
/// ```
/// use rust_license_key::crypto::generate_key_pair_base64;
///
/// let (private_key, public_key) = generate_key_pair_base64().expect("Key generation failed");
/// println!("Private (keep secret): {}", private_key);
/// println!("Public (embed in app): {}", public_key);
/// ```
pub fn generate_key_pair_base64() -> Result<(String, String)> {
    let key_pair = KeyPair::generate()?;
    Ok((key_pair.private_key_base64(), key_pair.public_key_base64()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pair_generation() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");

        // Verify key lengths
        assert_eq!(key_pair.private_key_bytes().len(), SECRET_KEY_LENGTH);
        assert_eq!(key_pair.public_key().to_bytes().len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn test_key_pair_from_private_key() {
        let original = KeyPair::generate().expect("Key generation should succeed");
        let private_key_base64 = original.private_key_base64();

        let restored =
            KeyPair::from_private_key_base64(&private_key_base64).expect("Should restore key pair");

        // Public keys should match
        assert_eq!(
            original.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
    }

    #[test]
    fn test_public_key_from_base64() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let public_key_base64 = key_pair.public_key_base64();

        let public_key =
            PublicKey::from_base64(&public_key_base64).expect("Should parse public key");

        assert_eq!(public_key.to_bytes(), key_pair.public_key().to_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let data = b"This is the license payload data";

        // Sign with private key
        let signature = key_pair.sign(data);

        // Verify with public key
        let public_key = key_pair.public_key();
        public_key
            .verify(data, &signature)
            .expect("Signature should be valid");
    }

    #[test]
    fn test_sign_and_verify_base64() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let data = b"This is the license payload data";

        // Sign with private key
        let signature_base64 = key_pair.sign_base64(data);

        // Verify with public key
        let public_key = key_pair.public_key();
        public_key
            .verify_base64(data, &signature_base64)
            .expect("Signature should be valid");
    }

    #[test]
    fn test_verify_invalid_signature() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let data = b"This is the license payload data";
        let wrong_data = b"This is different data";

        // Sign correct data
        let signature = key_pair.sign(data);

        // Verify against wrong data should fail
        let public_key = key_pair.public_key();
        assert!(public_key.verify(wrong_data, &signature).is_err());
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let key_pair_1 = KeyPair::generate().expect("Key generation should succeed");
        let key_pair_2 = KeyPair::generate().expect("Key generation should succeed");
        let data = b"This is the license payload data";

        // Sign with key_pair_1
        let signature = key_pair_1.sign(data);

        // Verify with key_pair_2 should fail
        let public_key_2 = key_pair_2.public_key();
        assert!(public_key_2.verify(data, &signature).is_err());
    }

    #[test]
    fn test_invalid_private_key_length() {
        let invalid_key = BASE64_STANDARD.encode(vec![0u8; 16]); // Wrong length
        let result = KeyPair::from_private_key_base64(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key_length() {
        let invalid_key = BASE64_STANDARD.encode(vec![0u8; 16]); // Wrong length
        let result = PublicKey::from_base64(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base64_encoding() {
        let result = KeyPair::from_private_key_base64("not valid base64!!!");
        assert!(result.is_err());

        let result = PublicKey::from_base64("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_key_pair_base64_convenience() {
        let (private_key, public_key) =
            generate_key_pair_base64().expect("Key generation should succeed");

        // Verify we can recreate the key pair from the private key
        let key_pair = KeyPair::from_private_key_base64(&private_key)
            .expect("Should create key pair from private key");

        // And the public key matches
        assert_eq!(key_pair.public_key_base64(), public_key);
    }
}
