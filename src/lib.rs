//! # rust-license-key
//!
//! A production-grade Rust library for creating and validating offline software
//! licenses using Ed25519 cryptography.
//!
//! ## Overview
//!
//! `rust-license-key` provides a secure, offline licensing system for software applications.
//! It uses Ed25519 digital signatures to create tamper-proof licenses that can be
//! verified without any network access.
//!
//! ### Key Features
//!
//! - **Asymmetric Cryptography**: Licenses are signed with a private key and verified
//!   with a public key. The client never has access to the signing key.
//! - **Offline Verification**: No network calls required for license validation.
//! - **Rich Constraints**: Support for expiration dates, feature flags, hostname
//!   restrictions, version limits, and custom constraints.
//! - **Tamper-Proof**: Any modification to the license invalidates the signature.
//! - **Human-Readable**: License payloads are JSON, making debugging easy.
//! - **Versioned Format**: Built-in version checking for forward compatibility.
//!
//! ## Quick Start
//!
//! ### Publisher Side: Creating Licenses
//!
//! ```rust
//! use rust_license_key::prelude::*;
//! use chrono::Duration;
//!
//! // Generate a key pair (do this once and store securely)
//! let key_pair = KeyPair::generate().expect("Key generation failed");
//!
//! // Save these keys:
//! // - Private key (keep secret!): key_pair.private_key_base64()
//! // - Public key (embed in app): key_pair.public_key_base64()
//!
//! // Create a license
//! let license_json = LicenseBuilder::new()
//!     .license_id("LIC-2024-001")
//!     .customer_id("ACME-CORP")
//!     .customer_name("Acme Corporation")
//!     .expires_in(Duration::days(365))
//!     .allowed_features(vec!["basic", "premium", "analytics"])
//!     .max_connections(100)
//!     .build_and_sign_to_json(&key_pair)
//!     .expect("License creation failed");
//!
//! // Send license_json to the customer
//! println!("{}", license_json);
//! ```
//!
//! ### Client Side: Validating Licenses
//!
//! ```rust
//! use rust_license_key::prelude::*;
//! use semver::Version;
//!
//! // The public key embedded in your application
//! let public_key_base64 = "..."; // Your public key here
//!
//! // The license file content
//! let license_json = "..."; // Customer's license file
//!
//! // Create a validator
//! // let validator = LicenseValidator::from_public_key_base64(public_key_base64)
//! //     .expect("Invalid public key");
//!
//! // Set up validation context
//! // let context = ValidationContext::new()
//! //     .with_hostname("myserver.example.com")
//! //     .with_software_version(Version::new(1, 2, 3))
//! //     .with_feature("premium");
//!
//! // Validate the license
//! // let result = validator.validate_json(&license_json, &context)
//! //     .expect("Validation error");
//!
//! // if result.is_valid {
//! //     println!("License valid! Days remaining: {:?}", result.days_remaining());
//! //     if result.is_feature_allowed("premium") {
//! //         println!("Premium features enabled!");
//! //     }
//! // } else {
//! //     for failure in &result.failures {
//! //         println!("Validation failed: {}", failure.message);
//! //     }
//! // }
//! ```
//!
//! ## Module Organization
//!
//! - [`crypto`] - Ed25519 key generation, signing, and verification.
//! - [`builder`] - Fluent API for creating and signing licenses.
//! - [`parser`] - Loading and decoding signed licenses.
//! - [`validator`] - Comprehensive license validation.
//! - [`models`] - Data structures for licenses, constraints, and results.
//! - [`error`] - Error types and validation failure information.
//!
//! ## Security Considerations
//!
//! - **Private Key Security**: The private key must be kept secret and should only
//!   exist on the license generation server. Never include it in client applications.
//! - **Public Key Distribution**: The public key can be safely embedded in client
//!   applications. It can only verify signatures, not create them.
//! - **No Encryption**: License payloads are signed but not encrypted. Do not store
//!   sensitive information in license metadata.
//! - **Offline Only**: This library does not provide license revocation or online
//!   validation. For these features, implement a separate online check.

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

// =============================================================================
// Module Declarations
// =============================================================================

pub mod builder;
pub mod crypto;
pub mod error;
pub mod models;
pub mod parser;
pub mod validator;

// =============================================================================
// Prelude - Common Imports
// =============================================================================

/// Convenient re-exports of the most commonly used types.
///
/// Import this module to get quick access to the main API:
///
/// ```rust
/// use rust_license_key::prelude::*;
/// ```
pub mod prelude {
    // Crypto types
    pub use crate::crypto::{generate_key_pair_base64, KeyPair, PublicKey};

    // Builder
    pub use crate::builder::LicenseBuilder;

    // Parser
    pub use crate::parser::{parse_license, LicenseParser};

    // Validator
    pub use crate::validator::{
        is_feature_allowed, is_license_valid, validate_license, LicenseValidator,
    };

    // Models
    pub use crate::models::{
        LicenseConstraints, LicensePayload, SignedLicense, ValidationContext, ValidationResult,
        LICENSE_FORMAT_VERSION,
    };

    // Errors
    pub use crate::error::{LicenseError, Result, ValidationFailure, ValidationFailureType};
}

// =============================================================================
// Top-Level Re-exports for Convenience
// =============================================================================

// Re-export key types at the crate root for convenience
pub use builder::LicenseBuilder;
pub use crypto::{generate_key_pair_base64, KeyPair, PublicKey};
pub use error::{LicenseError, Result};
pub use models::{
    LicenseConstraints, LicensePayload, SignedLicense, ValidationContext, ValidationResult,
};
pub use parser::{parse_license, LicenseParser};
pub use validator::{is_feature_allowed, is_license_valid, validate_license, LicenseValidator};

// =============================================================================
// Integration Tests as Doctests
// =============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;
    use chrono::Duration;
    use semver::Version;

    /// Complete end-to-end workflow test.
    #[test]
    fn test_complete_workflow() {
        // === PUBLISHER SIDE ===

        // 1. Generate key pair
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let public_key_base64 = key_pair.public_key_base64();

        // 2. Create a license with various constraints
        let license_json = LicenseBuilder::new()
            .license_id("E2E-TEST-001")
            .customer_id("INTEGRATION-TEST")
            .customer_name("Integration Test Customer")
            .expires_in(Duration::days(365))
            .allowed_features(vec!["basic", "premium", "analytics"])
            .denied_feature("experimental")
            .max_connections(50)
            .allowed_hostname("test.example.com")
            .minimum_version(Version::new(1, 0, 0))
            .maximum_version(Version::new(3, 0, 0))
            .metadata("department", serde_json::json!("Engineering"))
            .custom_constraint("max_users", serde_json::json!(100))
            .build_and_sign_to_json(&key_pair)
            .expect("License creation should succeed");

        // === CLIENT SIDE ===

        // 3. Create validator with public key
        let validator = LicenseValidator::from_public_key_base64(&public_key_base64)
            .expect("Validator creation should succeed");

        // 4. Create validation context
        let context = ValidationContext::new()
            .with_hostname("test.example.com")
            .with_software_version(Version::new(2, 0, 0))
            .with_connection_count(25)
            .with_feature("premium")
            .with_feature("analytics");

        // 5. Validate the license
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Validation should not error");

        // 6. Verify the results
        assert!(result.is_valid, "License should be valid");
        assert!(result.is_active(), "License should be active");
        assert!(result.failures.is_empty(), "Should have no failures");

        // Check remaining time
        let days_remaining = result.days_remaining().expect("Should have days remaining");
        assert!(
            days_remaining >= 364,
            "Should have approximately 365 days remaining"
        );

        // Check feature access
        assert!(result.is_feature_allowed("premium"));
        assert!(result.is_feature_allowed("analytics"));
        assert!(!result.is_feature_allowed("experimental")); // Denied

        // Check payload contents
        let payload = result.payload.expect("Should have payload");
        assert_eq!(payload.license_id, "E2E-TEST-001");
        assert_eq!(payload.customer_id, "INTEGRATION-TEST");
        assert_eq!(
            payload.customer_name.as_deref(),
            Some("Integration Test Customer")
        );

        // Check metadata
        let metadata = payload.metadata.expect("Should have metadata");
        assert_eq!(metadata["department"], serde_json::json!("Engineering"));
    }

    /// Test that tampering with the license is detected.
    #[test]
    fn test_tampering_detection() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");

        let license_json = LicenseBuilder::new()
            .license_id("TAMPER-TEST")
            .customer_id("TAMPER-CUST")
            .build_and_sign_to_json(&key_pair)
            .expect("License creation should succeed");

        // Parse the license JSON
        let mut signed: SignedLicense =
            serde_json::from_str(&license_json).expect("Should parse JSON");

        // Tamper with the payload
        signed.encoded_payload = signed.encoded_payload.replace('A', "B");

        let tampered_json = serde_json::to_string(&signed).expect("Should serialize");

        // Try to validate
        let validator = LicenseValidator::new(key_pair.public_key());
        let result = validator
            .validate_json(&tampered_json, &ValidationContext::new())
            .expect("Should return result");

        assert!(!result.is_valid, "Tampered license should be invalid");
    }

    /// Test convenience functions.
    #[test]
    fn test_convenience_functions() {
        let key_pair = KeyPair::generate().expect("Key generation should succeed");
        let public_key_base64 = key_pair.public_key_base64();

        let license_json = LicenseBuilder::new()
            .license_id("CONVENIENCE-TEST")
            .customer_id("CONVENIENCE-CUST")
            .allowed_feature("premium")
            .build_and_sign_to_json(&key_pair)
            .expect("License creation should succeed");

        // Test is_license_valid
        assert!(is_license_valid(&license_json, &public_key_base64));

        // Test is_feature_allowed
        assert!(is_feature_allowed(
            &license_json,
            &public_key_base64,
            "premium"
        ));
        assert!(!is_feature_allowed(
            &license_json,
            &public_key_base64,
            "enterprise"
        ));

        // Test parse_license
        let payload =
            parse_license(&license_json, &public_key_base64).expect("Should parse license");
        assert_eq!(payload.license_id, "CONVENIENCE-TEST");
    }
}
