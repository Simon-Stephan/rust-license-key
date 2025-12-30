//! Error types for the rust-license-key library.
//!
//! This module defines all error types that can occur during license operations,
//! including key generation, license creation, parsing, and validation.
//! All errors are designed to be explicit, informative, and actionable.

use thiserror::Error;

/// The main error type for all rust-license-key operations.
///
/// This enum encompasses all possible errors that can occur when working with
/// licenses, from cryptographic failures to validation issues.
#[derive(Debug, Error)]
pub enum LicenseError {
    // =========================================================================
    // Cryptographic Errors
    // =========================================================================
    /// Failed to generate a cryptographic key pair.
    #[error("failed to generate key pair: {reason}")]
    KeyGenerationFailed {
        /// Detailed reason for the key generation failure.
        reason: String,
    },

    /// The provided private key is invalid or malformed.
    #[error("invalid private key: {reason}")]
    InvalidPrivateKey {
        /// Detailed reason why the private key is invalid.
        reason: String,
    },

    /// The provided public key is invalid or malformed.
    #[error("invalid public key: {reason}")]
    InvalidPublicKey {
        /// Detailed reason why the public key is invalid.
        reason: String,
    },

    /// The cryptographic signature is invalid.
    #[error("invalid signature: the license signature does not match the content")]
    InvalidSignature,

    /// Failed to sign the license data.
    #[error("signing failed: {reason}")]
    SigningFailed {
        /// Detailed reason for the signing failure.
        reason: String,
    },

    // =========================================================================
    // Encoding/Decoding Errors
    // =========================================================================
    /// Failed to encode data to Base64.
    #[error("base64 encoding failed: {reason}")]
    Base64EncodingFailed {
        /// Detailed reason for the encoding failure.
        reason: String,
    },

    /// Failed to decode Base64 data.
    #[error("base64 decoding failed: {reason}")]
    Base64DecodingFailed {
        /// Detailed reason for the decoding failure.
        reason: String,
    },

    /// Failed to serialize data to JSON.
    #[error("JSON serialization failed: {reason}")]
    JsonSerializationFailed {
        /// Detailed reason for the serialization failure.
        reason: String,
    },

    /// Failed to deserialize JSON data.
    #[error("JSON deserialization failed: {reason}")]
    JsonDeserializationFailed {
        /// Detailed reason for the deserialization failure.
        reason: String,
    },

    // =========================================================================
    // License Format Errors
    // =========================================================================
    /// The license format is invalid or corrupted.
    #[error("invalid license format: {reason}")]
    InvalidLicenseFormat {
        /// Detailed reason why the license format is invalid.
        reason: String,
    },

    /// The license version is not supported by this library version.
    #[error("unsupported license version: found {found}, supported versions are {supported}")]
    UnsupportedLicenseVersion {
        /// The version found in the license.
        found: u32,
        /// Description of supported versions.
        supported: String,
    },

    /// A required field is missing from the license.
    #[error("missing required field: {field_name}")]
    MissingRequiredField {
        /// The name of the missing field.
        field_name: String,
    },

    // =========================================================================
    // Validation Errors
    // =========================================================================
    /// The license has expired.
    #[error("license expired: expired on {expiration_date}")]
    LicenseExpired {
        /// The date when the license expired.
        expiration_date: String,
    },

    /// The license is not yet valid (future start date).
    #[error("license not yet valid: becomes valid on {valid_from}")]
    LicenseNotYetValid {
        /// The date when the license becomes valid.
        valid_from: String,
    },

    /// The current software version is not compatible with this license.
    #[error("software version {current} is not compatible: {reason}")]
    IncompatibleSoftwareVersion {
        /// The current software version.
        current: String,
        /// Detailed reason for the incompatibility.
        reason: String,
    },

    /// The requested feature or plugin is not allowed by this license.
    #[error("feature not allowed: '{feature}' is not included in this license")]
    FeatureNotAllowed {
        /// The name of the disallowed feature.
        feature: String,
    },

    /// The current hostname is not allowed by this license.
    #[error("hostname not allowed: '{hostname}' is not in the allowed list")]
    HostnameNotAllowed {
        /// The current hostname that was rejected.
        hostname: String,
    },

    /// The current machine identifier is not allowed by this license.
    #[error("machine identifier not allowed: '{machine_id}' is not in the allowed list")]
    MachineIdNotAllowed {
        /// The current machine identifier that was rejected.
        machine_id: String,
    },

    /// The maximum number of concurrent connections has been exceeded.
    #[error("connection limit exceeded: maximum {max_allowed} connections allowed")]
    ConnectionLimitExceeded {
        /// The maximum number of connections allowed.
        max_allowed: u32,
    },

    /// A custom constraint validation failed.
    #[error("constraint validation failed: {constraint_name} - {reason}")]
    ConstraintValidationFailed {
        /// The name of the constraint that failed.
        constraint_name: String,
        /// Detailed reason for the failure.
        reason: String,
    },

    // =========================================================================
    // Builder Errors
    // =========================================================================
    /// The license builder is missing required fields.
    #[error("license builder incomplete: {missing_fields}")]
    BuilderIncomplete {
        /// Comma-separated list of missing required fields.
        missing_fields: String,
    },

    /// An invalid value was provided to the builder.
    #[error("invalid builder value for '{field}': {reason}")]
    InvalidBuilderValue {
        /// The field with the invalid value.
        field: String,
        /// Detailed reason why the value is invalid.
        reason: String,
    },
}

/// A specialized Result type for license operations.
pub type Result<T> = std::result::Result<T, LicenseError>;

/// Detailed information about a validation failure.
///
/// This struct provides comprehensive information about why a license
/// validation failed, useful for logging, debugging, and user feedback.
#[derive(Debug, Clone)]
pub struct ValidationFailure {
    /// The type of validation that failed.
    pub failure_type: ValidationFailureType,
    /// Human-readable message describing the failure.
    pub message: String,
    /// Optional additional context about the failure.
    pub context: Option<String>,
}

impl ValidationFailure {
    /// Creates a new validation failure with the given type and message.
    pub fn new(failure_type: ValidationFailureType, message: impl Into<String>) -> Self {
        Self {
            failure_type,
            message: message.into(),
            context: None,
        }
    }

    /// Adds context information to this validation failure.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

/// Categorizes the type of validation failure.
///
/// This enum helps applications handle different failure types appropriately,
/// for example, showing different messages for expired vs. invalid licenses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationFailureType {
    /// The cryptographic signature is invalid.
    InvalidSignature,
    /// The license has expired.
    Expired,
    /// The license is not yet valid.
    NotYetValid,
    /// The license version is not supported.
    UnsupportedVersion,
    /// A feature constraint was not satisfied.
    FeatureConstraint,
    /// A hostname constraint was not satisfied.
    HostnameConstraint,
    /// A machine identifier constraint was not satisfied.
    MachineIdConstraint,
    /// A software version constraint was not satisfied.
    VersionConstraint,
    /// A connection limit was exceeded.
    ConnectionLimit,
    /// The license format is malformed.
    MalformedLicense,
    /// A custom constraint was not satisfied.
    CustomConstraint,
}

impl std::fmt::Display for ValidationFailureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid_signature"),
            Self::Expired => write!(f, "expired"),
            Self::NotYetValid => write!(f, "not_yet_valid"),
            Self::UnsupportedVersion => write!(f, "unsupported_version"),
            Self::FeatureConstraint => write!(f, "feature_constraint"),
            Self::HostnameConstraint => write!(f, "hostname_constraint"),
            Self::MachineIdConstraint => write!(f, "machine_id_constraint"),
            Self::VersionConstraint => write!(f, "version_constraint"),
            Self::ConnectionLimit => write!(f, "connection_limit"),
            Self::MalformedLicense => write!(f, "malformed_license"),
            Self::CustomConstraint => write!(f, "custom_constraint"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        let error = LicenseError::LicenseExpired {
            expiration_date: "2024-01-01".to_string(),
        };
        assert!(error.to_string().contains("2024-01-01"));

        let error = LicenseError::FeatureNotAllowed {
            feature: "premium".to_string(),
        };
        assert!(error.to_string().contains("premium"));
    }

    #[test]
    fn test_validation_failure_with_context() {
        let failure = ValidationFailure::new(ValidationFailureType::Expired, "License expired")
            .with_context("Expired 30 days ago");

        assert_eq!(failure.failure_type, ValidationFailureType::Expired);
        assert!(failure.context.is_some());
    }
}
