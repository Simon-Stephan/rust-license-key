//! License validation logic.
//!
//! This module provides comprehensive validation of license payloads against
//! a given runtime context. It checks temporal constraints, feature restrictions,
//! host limitations, version compatibility, and custom constraints.
//!
//! # Validation Philosophy
//!
//! Validation is strict and deterministic:
//! - Any constraint violation results in validation failure.
//! - All failures are explicitly reported with detailed information.
//! - The validation result provides complete status information.

use chrono::{DateTime, Utc};

use crate::crypto::PublicKey;
use crate::error::{LicenseError, Result, ValidationFailure, ValidationFailureType};
use crate::models::{LicensePayload, ValidationContext, ValidationResult};
use crate::parser::LicenseParser;

// =============================================================================
// License Validator
// =============================================================================

/// Validator for checking license constraints against runtime context.
///
/// The validator performs comprehensive checking of all license constraints
/// and produces detailed validation results suitable for logging and
/// application logic.
///
/// # Example
///
/// ```
/// use rust_license_key::validator::LicenseValidator;
/// use rust_license_key::models::ValidationContext;
/// use rust_license_key::crypto::PublicKey;
/// use semver::Version;
///
/// // Create validator with the embedded public key
/// // let public_key = PublicKey::from_base64("...").unwrap();
/// // let validator = LicenseValidator::new(public_key);
///
/// // Set up the validation context
/// // let context = ValidationContext::new()
/// //     .with_hostname("myserver.example.com")
/// //     .with_software_version(Version::new(1, 2, 3))
/// //     .with_feature("premium");
///
/// // Validate the license
/// // let result = validator.validate_json(&license_json, &context).unwrap();
/// // if result.is_valid {
/// //     println!("License is valid for {} more days", result.days_remaining().unwrap_or(i64::MAX));
/// // }
/// ```
#[derive(Debug, Clone)]
pub struct LicenseValidator {
    /// The parser used to load and verify licenses.
    parser: LicenseParser,
}

impl LicenseValidator {
    /// Creates a new validator with the given public key.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The publisher's public key for signature verification.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            parser: LicenseParser::new(public_key),
        }
    }

    /// Creates a new validator from a base64-encoded public key.
    ///
    /// # Arguments
    ///
    /// * `public_key_base64` - The base64-encoded public key string.
    pub fn from_public_key_base64(public_key_base64: &str) -> Result<Self> {
        let parser = LicenseParser::from_public_key_base64(public_key_base64)?;
        Ok(Self { parser })
    }

    /// Validates a license from a JSON string.
    ///
    /// This is the primary validation method. It:
    /// 1. Parses and verifies the license signature.
    /// 2. Checks all constraints against the provided context.
    /// 3. Returns a comprehensive validation result.
    ///
    /// # Arguments
    ///
    /// * `license_json` - The JSON string containing the signed license.
    /// * `context` - The runtime context to validate against.
    ///
    /// # Returns
    ///
    /// A `ValidationResult` indicating whether the license is valid and
    /// providing detailed information about any failures.
    pub fn validate_json(
        &self,
        license_json: &str,
        context: &ValidationContext,
    ) -> Result<ValidationResult> {
        // First, parse and verify the license
        let payload = match self.parser.parse_json(license_json) {
            Ok(p) => p,
            Err(LicenseError::InvalidSignature) => {
                return Ok(ValidationResult::failure(vec![ValidationFailure::new(
                    ValidationFailureType::InvalidSignature,
                    "License signature is invalid or has been tampered with",
                )]));
            }
            Err(LicenseError::UnsupportedLicenseVersion { found, supported }) => {
                return Ok(ValidationResult::failure(vec![ValidationFailure::new(
                    ValidationFailureType::UnsupportedVersion,
                    format!("License version {} is not supported ({})", found, supported),
                )]));
            }
            Err(e) => return Err(e),
        };

        // Validate the payload against the context
        Ok(self.validate_payload(&payload, context))
    }

    /// Validates a license payload directly.
    ///
    /// Use this when you already have a parsed and verified payload.
    /// This method assumes the signature has already been verified.
    ///
    /// # Arguments
    ///
    /// * `payload` - The license payload to validate.
    /// * `context` - The runtime context to validate against.
    ///
    /// # Returns
    ///
    /// A `ValidationResult` with detailed status information.
    pub fn validate_payload(
        &self,
        payload: &LicensePayload,
        context: &ValidationContext,
    ) -> ValidationResult {
        let mut failures = Vec::new();

        // Determine the current time for temporal checks
        let current_time = context.current_time.unwrap_or_else(Utc::now);

        // Check expiration
        self.check_expiration(payload, current_time, &mut failures);

        // Check valid_from
        self.check_valid_from(payload, current_time, &mut failures);

        // Check hostname constraint
        self.check_hostname(payload, context, &mut failures);

        // Check machine ID constraint
        self.check_machine_id(payload, context, &mut failures);

        // Check version constraint
        self.check_version(payload, context, &mut failures);

        // Check connection limit
        self.check_connection_limit(payload, context, &mut failures);

        // Check requested features
        self.check_features(payload, context, &mut failures);

        // Build the result
        if failures.is_empty() {
            ValidationResult::success(payload.clone())
        } else {
            // Create a partial result with the payload for informational purposes
            let mut result = ValidationResult::success(payload.clone());
            result.is_valid = false;
            result.failures = failures;
            result
        }
    }

    /// Checks the license expiration constraint.
    fn check_expiration(
        &self,
        payload: &LicensePayload,
        current_time: DateTime<Utc>,
        failures: &mut Vec<ValidationFailure>,
    ) {
        if let Some(expiration) = payload.constraints.expiration_date {
            if current_time > expiration {
                failures.push(
                    ValidationFailure::new(
                        ValidationFailureType::Expired,
                        format!(
                            "License expired on {}",
                            expiration.format("%Y-%m-%d %H:%M:%S UTC")
                        ),
                    )
                    .with_context(format!(
                        "Current time: {}",
                        current_time.format("%Y-%m-%d %H:%M:%S UTC")
                    )),
                );
            }
        }
    }

    /// Checks the valid_from constraint (license activation date).
    fn check_valid_from(
        &self,
        payload: &LicensePayload,
        current_time: DateTime<Utc>,
        failures: &mut Vec<ValidationFailure>,
    ) {
        if let Some(valid_from) = payload.constraints.valid_from {
            if current_time < valid_from {
                failures.push(
                    ValidationFailure::new(
                        ValidationFailureType::NotYetValid,
                        format!(
                            "License becomes valid on {}",
                            valid_from.format("%Y-%m-%d %H:%M:%S UTC")
                        ),
                    )
                    .with_context(format!(
                        "Current time: {}",
                        current_time.format("%Y-%m-%d %H:%M:%S UTC")
                    )),
                );
            }
        }
    }

    /// Checks the hostname constraint.
    fn check_hostname(
        &self,
        payload: &LicensePayload,
        context: &ValidationContext,
        failures: &mut Vec<ValidationFailure>,
    ) {
        if let Some(ref hostname) = context.current_hostname {
            if !payload.constraints.is_hostname_allowed(hostname) {
                let allowed = payload
                    .constraints
                    .allowed_hostnames
                    .as_ref()
                    .map(|h| h.iter().cloned().collect::<Vec<_>>().join(", "))
                    .unwrap_or_else(|| "(none specified)".to_string());

                failures.push(
                    ValidationFailure::new(
                        ValidationFailureType::HostnameConstraint,
                        format!("Hostname '{}' is not allowed by this license", hostname),
                    )
                    .with_context(format!("Allowed hostnames: {}", allowed)),
                );
            }
        }
    }

    /// Checks the machine ID constraint.
    fn check_machine_id(
        &self,
        payload: &LicensePayload,
        context: &ValidationContext,
        failures: &mut Vec<ValidationFailure>,
    ) {
        if let Some(ref machine_id) = context.current_machine_id {
            if !payload.constraints.is_machine_id_allowed(machine_id) {
                failures.push(ValidationFailure::new(
                    ValidationFailureType::MachineIdConstraint,
                    format!(
                        "Machine identifier '{}' is not allowed by this license",
                        machine_id
                    ),
                ));
            }
        }
    }

    /// Checks the software version constraint.
    fn check_version(
        &self,
        payload: &LicensePayload,
        context: &ValidationContext,
        failures: &mut Vec<ValidationFailure>,
    ) {
        if let Some(ref version) = context.current_software_version {
            if let Err(reason) = payload.constraints.check_version_compatibility(version) {
                failures.push(
                    ValidationFailure::new(
                        ValidationFailureType::VersionConstraint,
                        format!("Software version {} is not compatible", version),
                    )
                    .with_context(reason),
                );
            }
        }
    }

    /// Checks the connection limit constraint.
    fn check_connection_limit(
        &self,
        payload: &LicensePayload,
        context: &ValidationContext,
        failures: &mut Vec<ValidationFailure>,
    ) {
        if let (Some(max_allowed), Some(current_count)) = (
            payload.constraints.max_connections,
            context.current_connection_count,
        ) {
            if current_count >= max_allowed {
                failures.push(
                    ValidationFailure::new(
                        ValidationFailureType::ConnectionLimit,
                        format!(
                            "Connection limit exceeded: {} connections in use, maximum {} allowed",
                            current_count, max_allowed
                        ),
                    )
                    .with_context(format!(
                        "Attempting to use connection {} of {} allowed",
                        current_count + 1,
                        max_allowed
                    )),
                );
            }
        }
    }

    /// Checks that all requested features are allowed.
    fn check_features(
        &self,
        payload: &LicensePayload,
        context: &ValidationContext,
        failures: &mut Vec<ValidationFailure>,
    ) {
        for feature in &context.requested_features {
            if !payload.constraints.is_feature_allowed(feature) {
                // Determine why the feature is not allowed
                let reason = if payload
                    .constraints
                    .denied_features
                    .as_ref()
                    .map(|d| d.contains(feature))
                    .unwrap_or(false)
                {
                    "feature is explicitly denied"
                } else {
                    "feature is not in the allowed list"
                };

                failures.push(
                    ValidationFailure::new(
                        ValidationFailureType::FeatureConstraint,
                        format!("Feature '{}' is not allowed", feature),
                    )
                    .with_context(reason.to_string()),
                );
            }
        }
    }

    /// Returns a reference to the underlying parser.
    pub fn parser(&self) -> &LicenseParser {
        &self.parser
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Validates a license using a base64-encoded public key.
///
/// This is a convenience function for one-shot license validation.
/// For multiple validations, create a `LicenseValidator` instance.
///
/// # Arguments
///
/// * `license_json` - The JSON string containing the signed license.
/// * `public_key_base64` - The base64-encoded public key.
/// * `context` - The runtime context to validate against.
///
/// # Returns
///
/// A `ValidationResult` with detailed status information.
pub fn validate_license(
    license_json: &str,
    public_key_base64: &str,
    context: &ValidationContext,
) -> Result<ValidationResult> {
    let validator = LicenseValidator::from_public_key_base64(public_key_base64)?;
    validator.validate_json(license_json, context)
}

/// Performs a quick check to see if a license is currently valid.
///
/// This function only checks signature validity and expiration.
/// For full validation, use `validate_license` or `LicenseValidator`.
///
/// # Arguments
///
/// * `license_json` - The JSON string containing the signed license.
/// * `public_key_base64` - The base64-encoded public key.
///
/// # Returns
///
/// `true` if the license is valid and not expired, `false` otherwise.
pub fn is_license_valid(license_json: &str, public_key_base64: &str) -> bool {
    let context = ValidationContext::new();
    validate_license(license_json, public_key_base64, &context)
        .map(|r| r.is_valid)
        .unwrap_or(false)
}

/// Checks if a specific feature is allowed by a license.
///
/// # Arguments
///
/// * `license_json` - The JSON string containing the signed license.
/// * `public_key_base64` - The base64-encoded public key.
/// * `feature` - The feature to check.
///
/// # Returns
///
/// `true` if the license is valid and the feature is allowed.
pub fn is_feature_allowed(license_json: &str, public_key_base64: &str, feature: &str) -> bool {
    let context = ValidationContext::new().with_feature(feature);
    validate_license(license_json, public_key_base64, &context)
        .map(|r| r.is_valid)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::LicenseBuilder;
    use crate::crypto::KeyPair;
    use chrono::Duration;
    use semver::Version;

    fn create_key_pair() -> KeyPair {
        KeyPair::generate().expect("Key generation should succeed")
    }

    fn create_basic_license(key_pair: &KeyPair) -> String {
        LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .expires_in(Duration::days(30))
            .build_and_sign_to_json(key_pair)
            .expect("Should create license")
    }

    #[test]
    fn test_validate_valid_license() {
        let key_pair = create_key_pair();
        let license_json = create_basic_license(&key_pair);

        let validator = LicenseValidator::new(key_pair.public_key());
        let context = ValidationContext::new();

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");

        assert!(result.is_valid);
        assert!(result.failures.is_empty());
        assert!(result.payload.is_some());
    }

    #[test]
    fn test_validate_expired_license() {
        let key_pair = create_key_pair();

        // Create an already-expired license
        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .expires_in(Duration::days(-1)) // Expired yesterday
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());
        let context = ValidationContext::new();

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");

        assert!(!result.is_valid);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::Expired
        );
    }

    #[test]
    fn test_validate_not_yet_valid_license() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .valid_after(Duration::days(7)) // Valid in 7 days
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());
        let context = ValidationContext::new();

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");

        assert!(!result.is_valid);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::NotYetValid
        );
    }

    #[test]
    fn test_validate_hostname_restriction() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .allowed_hostname("allowed.example.com")
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());

        // Valid hostname
        let context = ValidationContext::new().with_hostname("allowed.example.com");
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(result.is_valid);

        // Invalid hostname
        let context = ValidationContext::new().with_hostname("other.example.com");
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(!result.is_valid);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::HostnameConstraint
        );
    }

    #[test]
    fn test_validate_version_constraints() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .minimum_version(Version::new(1, 0, 0))
            .maximum_version(Version::new(2, 0, 0))
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());

        // Valid version
        let context = ValidationContext::new().with_software_version(Version::new(1, 5, 0));
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(result.is_valid);

        // Version too low
        let context = ValidationContext::new().with_software_version(Version::new(0, 9, 0));
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(!result.is_valid);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::VersionConstraint
        );

        // Version too high
        let context = ValidationContext::new().with_software_version(Version::new(2, 1, 0));
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_feature_constraints() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .allowed_features(vec!["basic", "premium"])
            .denied_feature("admin")
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());

        // Allowed feature
        let context = ValidationContext::new().with_feature("premium");
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(result.is_valid);

        // Unlisted feature
        let context = ValidationContext::new().with_feature("enterprise");
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(!result.is_valid);

        // Denied feature
        let context = ValidationContext::new().with_feature("admin");
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_connection_limit() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .max_connections(10)
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());

        // Under limit
        let context = ValidationContext::new().with_connection_count(5);
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(result.is_valid);

        // At limit (trying to add one more)
        let context = ValidationContext::new().with_connection_count(10);
        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");
        assert!(!result.is_valid);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::ConnectionLimit
        );
    }

    #[test]
    fn test_validate_invalid_signature() {
        let key_pair_1 = create_key_pair();
        let key_pair_2 = create_key_pair();

        let license_json = create_basic_license(&key_pair_1);

        // Try to validate with wrong key
        let validator = LicenseValidator::new(key_pair_2.public_key());
        let context = ValidationContext::new();

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should return result");

        assert!(!result.is_valid);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::InvalidSignature
        );
    }

    #[test]
    fn test_validate_multiple_failures() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .expires_in(Duration::days(-1)) // Expired
            .allowed_hostname("allowed.example.com")
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());
        let context = ValidationContext::new().with_hostname("other.example.com");

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");

        assert!(!result.is_valid);
        // Should have both expiration and hostname failures
        assert!(result.failures.len() >= 2);
    }

    #[test]
    fn test_is_license_valid_convenience() {
        let key_pair = create_key_pair();
        let public_key_base64 = key_pair.public_key_base64();
        let license_json = create_basic_license(&key_pair);

        assert!(is_license_valid(&license_json, &public_key_base64));
    }

    #[test]
    fn test_is_feature_allowed_convenience() {
        let key_pair = create_key_pair();
        let public_key_base64 = key_pair.public_key_base64();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .allowed_feature("premium")
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

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
    }

    #[test]
    fn test_validation_result_days_remaining() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .expires_in(Duration::days(30))
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());
        let context = ValidationContext::new();

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");

        assert!(result.is_valid);
        let days = result.days_remaining().expect("Should have days remaining");
        assert!(days >= 29 && days <= 30);
    }

    #[test]
    fn test_validation_with_custom_time() {
        let key_pair = create_key_pair();

        let license_json = LicenseBuilder::new()
            .license_id("TEST-001")
            .customer_id("CUST-001")
            .expires_at(Utc::now() + Duration::days(30))
            .build_and_sign_to_json(&key_pair)
            .expect("Should create license");

        let validator = LicenseValidator::new(key_pair.public_key());

        // Validate at a future time (60 days from now)
        let future_time = Utc::now() + Duration::days(60);
        let context = ValidationContext::new().with_time(future_time);

        let result = validator
            .validate_json(&license_json, &context)
            .expect("Should validate");

        assert!(!result.is_valid);
        assert_eq!(
            result.failures[0].failure_type,
            ValidationFailureType::Expired
        );
    }
}
