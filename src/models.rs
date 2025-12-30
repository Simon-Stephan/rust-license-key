//! Data models for license representation and constraints.
//!
//! This module defines the core data structures used to represent licenses,
//! their constraints, and validation results. All structures are designed
//! to be serializable, versioned, and extensible.

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// =============================================================================
// License Format Version
// =============================================================================

/// Current version of the license format.
///
/// This version number is embedded in every license and used to ensure
/// compatibility between license files and library versions.
/// Increment this when making breaking changes to the license format.
pub const LICENSE_FORMAT_VERSION: u32 = 1;

/// Minimum supported license format version.
///
/// Licenses with versions below this will be rejected during parsing.
pub const MIN_SUPPORTED_LICENSE_VERSION: u32 = 1;

/// Maximum supported license format version.
///
/// Licenses with versions above this will be rejected during parsing.
pub const MAX_SUPPORTED_LICENSE_VERSION: u32 = 1;

// =============================================================================
// License Payload
// =============================================================================

/// The core license payload containing all license information.
///
/// This structure holds all the data that defines a license, including
/// identification, temporal constraints, and feature restrictions.
/// It is serialized to JSON and then signed by the publisher.
///
/// # Security Note
///
/// The payload itself is not encrypted, only signed. Anyone with access
/// to the license file can read its contents. Do not store secrets in
/// the license payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicensePayload {
    /// Version of the license format for forward compatibility.
    /// This allows the library to reject incompatible future formats.
    #[serde(rename = "v")]
    pub format_version: u32,

    /// Unique identifier for this specific license.
    /// Should be a UUID or similar unique identifier.
    #[serde(rename = "id")]
    pub license_id: String,

    /// Identifier for the customer or organization this license is issued to.
    #[serde(rename = "customer")]
    pub customer_id: String,

    /// Human-readable name of the customer or organization.
    #[serde(rename = "customer_name", skip_serializing_if = "Option::is_none")]
    pub customer_name: Option<String>,

    /// Timestamp when this license was issued.
    #[serde(rename = "issued_at")]
    pub issued_at: DateTime<Utc>,

    /// All constraints and restrictions applied to this license.
    #[serde(rename = "constraints")]
    pub constraints: LicenseConstraints,

    /// Optional additional metadata as key-value pairs.
    /// Useful for application-specific data that doesn't fit standard fields.
    #[serde(rename = "metadata", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl LicensePayload {
    /// Returns the license ID as a string slice.
    pub fn id(&self) -> &str {
        &self.license_id
    }

    /// Returns the customer ID as a string slice.
    pub fn customer(&self) -> &str {
        &self.customer_id
    }

    /// Checks if the license format version is supported by this library.
    pub fn is_version_supported(&self) -> bool {
        self.format_version >= MIN_SUPPORTED_LICENSE_VERSION
            && self.format_version <= MAX_SUPPORTED_LICENSE_VERSION
    }

    // =========================================================================
    // Custom Key/Value Getters
    // =========================================================================

    /// Gets a custom value from the license metadata by key.
    ///
    /// Returns `None` if the key doesn't exist or if no metadata is present.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // if let Some(value) = payload.get_value("max_users") {
    /// //     println!("Max users: {}", value);
    /// // }
    /// ```
    pub fn get_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.as_ref().and_then(|m| m.get(key))
    }

    /// Gets a custom value from the license metadata, or returns a default value.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    /// use serde_json::json;
    ///
    /// // After validating a license:
    /// // let max_users = payload.get_value_or("max_users", &json!(10));
    /// ```
    pub fn get_value_or<'a>(&'a self, key: &str, default: &'a serde_json::Value) -> &'a serde_json::Value {
        self.get_value(key).unwrap_or(default)
    }

    /// Gets a string value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not a string.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // if let Some(tier) = payload.get_string("tier") {
    /// //     println!("License tier: {}", tier);
    /// // }
    /// ```
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.get_value(key).and_then(|v| v.as_str())
    }

    /// Gets a string value from the license metadata, or returns a default.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // let tier = payload.get_string_or("tier", "basic");
    /// ```
    pub fn get_string_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_string(key).unwrap_or(default)
    }

    /// Gets an i64 value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not a number.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // if let Some(max_users) = payload.get_i64("max_users") {
    /// //     println!("Max users: {}", max_users);
    /// // }
    /// ```
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get_value(key).and_then(|v| v.as_i64())
    }

    /// Gets an i64 value from the license metadata, or returns a default.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // let max_users = payload.get_i64_or("max_users", 10);
    /// ```
    pub fn get_i64_or(&self, key: &str, default: i64) -> i64 {
        self.get_i64(key).unwrap_or(default)
    }

    /// Gets a u64 value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not a positive number.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get_value(key).and_then(|v| v.as_u64())
    }

    /// Gets a u64 value from the license metadata, or returns a default.
    pub fn get_u64_or(&self, key: &str, default: u64) -> u64 {
        self.get_u64(key).unwrap_or(default)
    }

    /// Gets an f64 value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not a number.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get_value(key).and_then(|v| v.as_f64())
    }

    /// Gets an f64 value from the license metadata, or returns a default.
    pub fn get_f64_or(&self, key: &str, default: f64) -> f64 {
        self.get_f64(key).unwrap_or(default)
    }

    /// Gets a boolean value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not a boolean.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get_value(key).and_then(|v| v.as_bool())
    }

    /// Gets a boolean value from the license metadata, or returns a default.
    pub fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    /// Gets an array value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not an array.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // if let Some(modules) = payload.get_array("allowed_modules") {
    /// //     for module in modules {
    /// //         println!("Module: {}", module);
    /// //     }
    /// // }
    /// ```
    pub fn get_array(&self, key: &str) -> Option<&Vec<serde_json::Value>> {
        self.get_value(key).and_then(|v| v.as_array())
    }

    /// Gets a string array from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not an array.
    /// Non-string elements in the array are filtered out.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // if let Some(modules) = payload.get_string_array("allowed_modules") {
    /// //     for module in modules {
    /// //         println!("Module: {}", module);
    /// //     }
    /// // }
    /// ```
    pub fn get_string_array(&self, key: &str) -> Option<Vec<&str>> {
        self.get_array(key).map(|arr| {
            arr.iter().filter_map(|v| v.as_str()).collect()
        })
    }

    /// Gets an object value from the license metadata.
    ///
    /// Returns `None` if the key doesn't exist or the value is not an object.
    pub fn get_object(&self, key: &str) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.get_value(key).and_then(|v| v.as_object())
    }

    /// Checks if a key exists in the license metadata.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating a license:
    /// // if payload.has_key("enterprise_features") {
    /// //     // Enable enterprise features
    /// // }
    /// ```
    pub fn has_key(&self, key: &str) -> bool {
        self.metadata.as_ref().map(|m| m.contains_key(key)).unwrap_or(false)
    }

    /// Returns all metadata keys.
    ///
    /// Returns an empty iterator if no metadata is present.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.metadata.iter().flat_map(|m| m.keys())
    }
}

// =============================================================================
// License Constraints
// =============================================================================

/// All constraints and restrictions that can be applied to a license.
///
/// Each field is optional, allowing flexible license configurations.
/// An absent constraint means "no restriction" for that aspect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LicenseConstraints {
    /// Date and time when this license expires.
    /// If `None`, the license never expires.
    #[serde(rename = "expires_at", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    /// Date and time when this license becomes valid.
    /// If `None`, the license is immediately valid upon issuance.
    #[serde(rename = "valid_from", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// Set of features or plugins that are explicitly allowed.
    /// If `None`, no feature restrictions apply (all features allowed).
    /// If `Some(empty_set)`, no features are allowed.
    #[serde(rename = "allowed_features", skip_serializing_if = "Option::is_none")]
    pub allowed_features: Option<HashSet<String>>,

    /// Set of features or plugins that are explicitly denied.
    /// Takes precedence over `allowed_features` if both are specified.
    #[serde(rename = "denied_features", skip_serializing_if = "Option::is_none")]
    pub denied_features: Option<HashSet<String>>,

    /// Maximum number of concurrent connections or seats allowed.
    /// If `None`, no connection limit applies.
    #[serde(rename = "max_connections", skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,

    /// Set of hostnames where this license can be used.
    /// If `None`, no hostname restrictions apply.
    #[serde(rename = "allowed_hostnames", skip_serializing_if = "Option::is_none")]
    pub allowed_hostnames: Option<HashSet<String>>,

    /// Set of machine identifiers where this license can be used.
    /// Machine identifiers can be hardware IDs, container IDs, etc.
    /// If `None`, no machine restrictions apply.
    #[serde(
        rename = "allowed_machine_ids",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_machine_ids: Option<HashSet<String>>,

    /// Minimum software version required to use this license.
    /// If `None`, no minimum version requirement.
    #[serde(rename = "min_version", skip_serializing_if = "Option::is_none")]
    pub minimum_software_version: Option<Version>,

    /// Maximum software version allowed to use this license.
    /// Useful for deprecating old licenses with newer software versions.
    /// If `None`, no maximum version requirement.
    #[serde(rename = "max_version", skip_serializing_if = "Option::is_none")]
    pub maximum_software_version: Option<Version>,

    /// Custom key-value constraints for application-specific validation.
    /// The application is responsible for interpreting these constraints.
    #[serde(rename = "custom", skip_serializing_if = "Option::is_none")]
    pub custom_constraints: Option<HashMap<String, serde_json::Value>>,
}

impl LicenseConstraints {
    /// Creates a new empty constraints object with no restrictions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if a feature is allowed by this license.
    ///
    /// # Logic
    ///
    /// 1. If the feature is in `denied_features`, it is not allowed.
    /// 2. If `allowed_features` is `None`, the feature is allowed.
    /// 3. If `allowed_features` is `Some`, the feature must be in the set.
    pub fn is_feature_allowed(&self, feature: &str) -> bool {
        // Check denied list first (takes precedence)
        if let Some(ref denied) = self.denied_features {
            if denied.contains(feature) {
                return false;
            }
        }

        // Check allowed list
        match &self.allowed_features {
            None => true, // No restrictions
            Some(allowed) => allowed.contains(feature),
        }
    }

    /// Checks if a hostname is allowed by this license.
    ///
    /// Returns `true` if no hostname restrictions exist or if the hostname
    /// is in the allowed set.
    pub fn is_hostname_allowed(&self, hostname: &str) -> bool {
        match &self.allowed_hostnames {
            None => true,
            Some(allowed) => allowed.contains(hostname),
        }
    }

    /// Checks if a machine identifier is allowed by this license.
    ///
    /// Returns `true` if no machine ID restrictions exist or if the machine ID
    /// is in the allowed set.
    pub fn is_machine_id_allowed(&self, machine_id: &str) -> bool {
        match &self.allowed_machine_ids {
            None => true,
            Some(allowed) => allowed.contains(machine_id),
        }
    }

    /// Checks if a software version is compatible with this license.
    ///
    /// Returns `Ok(())` if the version is within the allowed range,
    /// or `Err` with a description of why it's incompatible.
    pub fn check_version_compatibility(&self, version: &Version) -> Result<(), String> {
        if let Some(ref min_version) = self.minimum_software_version {
            if version < min_version {
                return Err(format!(
                    "version {} is below minimum required version {}",
                    version, min_version
                ));
            }
        }

        if let Some(ref max_version) = self.maximum_software_version {
            if version > max_version {
                return Err(format!(
                    "version {} exceeds maximum allowed version {}",
                    version, max_version
                ));
            }
        }

        Ok(())
    }
}

// =============================================================================
// Signed License Container
// =============================================================================

/// A complete signed license ready for distribution.
///
/// This structure contains the license payload along with its cryptographic
/// signature. It is what gets serialized and distributed to customers.
///
/// # Format
///
/// When serialized for distribution, this becomes a JSON object with:
/// - `payload`: The base64-encoded JSON payload
/// - `signature`: The base64-encoded Ed25519 signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    /// The license payload, base64-encoded JSON.
    #[serde(rename = "payload")]
    pub encoded_payload: String,

    /// The Ed25519 signature of the payload, base64-encoded.
    #[serde(rename = "signature")]
    pub encoded_signature: String,
}

impl SignedLicense {
    /// Creates a new signed license from encoded components.
    ///
    /// # Arguments
    ///
    /// * `encoded_payload` - Base64-encoded JSON payload
    /// * `encoded_signature` - Base64-encoded signature bytes
    pub fn new(encoded_payload: String, encoded_signature: String) -> Self {
        Self {
            encoded_payload,
            encoded_signature,
        }
    }

    /// Serializes this signed license to a JSON string for distribution.
    ///
    /// This is the format that should be saved to a file or transmitted
    /// to the customer.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a signed license from a JSON string.
    ///
    /// This is how license files are loaded for validation.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// =============================================================================
// Validation Context
// =============================================================================

/// Context information provided during license validation.
///
/// This structure contains all the runtime information needed to validate
/// a license against the current execution environment.
#[derive(Debug, Clone, Default)]
pub struct ValidationContext {
    /// The current date and time to check against temporal constraints.
    /// If `None`, uses the system's current time.
    pub current_time: Option<DateTime<Utc>>,

    /// The current hostname to check against hostname constraints.
    pub current_hostname: Option<String>,

    /// The current machine identifier to check against machine ID constraints.
    pub current_machine_id: Option<String>,

    /// The current software version to check against version constraints.
    pub current_software_version: Option<Version>,

    /// The current number of connections to check against connection limits.
    pub current_connection_count: Option<u32>,

    /// Features being requested for this validation.
    /// Each feature will be checked against the license constraints.
    pub requested_features: Vec<String>,

    /// Custom values to check against custom constraints.
    pub custom_values: HashMap<String, serde_json::Value>,
}

impl ValidationContext {
    /// Creates a new empty validation context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the current time for validation.
    pub fn with_time(mut self, time: DateTime<Utc>) -> Self {
        self.current_time = Some(time);
        self
    }

    /// Sets the current hostname for validation.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.current_hostname = Some(hostname.into());
        self
    }

    /// Sets the current machine identifier for validation.
    pub fn with_machine_id(mut self, machine_id: impl Into<String>) -> Self {
        self.current_machine_id = Some(machine_id.into());
        self
    }

    /// Sets the current software version for validation.
    pub fn with_software_version(mut self, version: Version) -> Self {
        self.current_software_version = Some(version);
        self
    }

    /// Sets the current connection count for validation.
    pub fn with_connection_count(mut self, count: u32) -> Self {
        self.current_connection_count = Some(count);
        self
    }

    /// Adds a requested feature to check against the license.
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.requested_features.push(feature.into());
        self
    }

    /// Adds multiple requested features to check against the license.
    pub fn with_features(mut self, features: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.requested_features
            .extend(features.into_iter().map(Into::into));
        self
    }

    /// Adds a custom value for constraint checking.
    pub fn with_custom_value(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.custom_values.insert(key.into(), value);
        self
    }
}

// =============================================================================
// Validation Result
// =============================================================================

/// The result of validating a license.
///
/// This structure provides comprehensive information about the validation
/// outcome, including whether it succeeded and detailed status information.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the license is valid.
    pub is_valid: bool,

    /// The validated license payload (only present if signature was valid).
    pub payload: Option<LicensePayload>,

    /// List of validation failures encountered.
    /// Empty if validation succeeded.
    pub failures: Vec<crate::error::ValidationFailure>,

    /// Time remaining until the license expires.
    /// `None` if the license never expires or is already expired.
    pub time_remaining: Option<chrono::Duration>,

    /// List of features that are allowed by this license.
    /// Only populated if validation succeeded.
    pub allowed_features: Option<HashSet<String>>,

    /// List of features that are denied by this license.
    /// Only populated if validation succeeded.
    pub denied_features: Option<HashSet<String>>,
}

impl ValidationResult {
    /// Creates a successful validation result.
    pub fn success(payload: LicensePayload) -> Self {
        let time_remaining = payload
            .constraints
            .expiration_date
            .map(|exp| exp.signed_duration_since(Utc::now()));

        let allowed_features = payload.constraints.allowed_features.clone();
        let denied_features = payload.constraints.denied_features.clone();

        Self {
            is_valid: true,
            payload: Some(payload),
            failures: Vec::new(),
            time_remaining,
            allowed_features,
            denied_features,
        }
    }

    /// Creates a failed validation result with the given failures.
    pub fn failure(failures: Vec<crate::error::ValidationFailure>) -> Self {
        Self {
            is_valid: false,
            payload: None,
            failures,
            time_remaining: None,
            allowed_features: None,
            denied_features: None,
        }
    }

    /// Adds a failure to the result and marks it as invalid.
    pub fn add_failure(&mut self, failure: crate::error::ValidationFailure) {
        self.is_valid = false;
        self.failures.push(failure);
    }

    /// Returns true if the license is valid and not expired.
    pub fn is_active(&self) -> bool {
        self.is_valid
            && self
                .time_remaining
                .map(|d| d.num_seconds() > 0)
                .unwrap_or(true)
    }

    /// Returns the number of days remaining until expiration.
    /// Returns `None` if the license never expires.
    pub fn days_remaining(&self) -> Option<i64> {
        self.time_remaining.map(|d| d.num_days())
    }

    /// Checks if a specific feature is allowed by the validated license.
    pub fn is_feature_allowed(&self, feature: &str) -> bool {
        if !self.is_valid {
            return false;
        }

        // Check denied list first
        if let Some(ref denied) = self.denied_features {
            if denied.contains(feature) {
                return false;
            }
        }

        // Check allowed list
        match &self.allowed_features {
            None => true,
            Some(allowed) => allowed.contains(feature),
        }
    }

    // =========================================================================
    // Custom Key/Value Getters (delegates to payload)
    // =========================================================================

    /// Gets a custom value from the license metadata by key.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or if no metadata is present.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// // After validating:
    /// // if let Some(value) = result.get_value("max_users") {
    /// //     println!("Max users: {}", value);
    /// // }
    /// ```
    pub fn get_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.payload.as_ref().and_then(|p| p.get_value(key))
    }

    /// Gets a custom value from the license metadata, or returns a default value.
    pub fn get_value_or<'a>(&'a self, key: &str, default: &'a serde_json::Value) -> &'a serde_json::Value {
        self.get_value(key).unwrap_or(default)
    }

    /// Gets a string value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not a string.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.payload.as_ref().and_then(|p| p.get_string(key))
    }

    /// Gets a string value from the license metadata, or returns a default.
    pub fn get_string_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_string(key).unwrap_or(default)
    }

    /// Gets an i64 value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not a number.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.payload.as_ref().and_then(|p| p.get_i64(key))
    }

    /// Gets an i64 value from the license metadata, or returns a default.
    pub fn get_i64_or(&self, key: &str, default: i64) -> i64 {
        self.get_i64(key).unwrap_or(default)
    }

    /// Gets a u64 value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not a positive number.
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.payload.as_ref().and_then(|p| p.get_u64(key))
    }

    /// Gets a u64 value from the license metadata, or returns a default.
    pub fn get_u64_or(&self, key: &str, default: u64) -> u64 {
        self.get_u64(key).unwrap_or(default)
    }

    /// Gets an f64 value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not a number.
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.payload.as_ref().and_then(|p| p.get_f64(key))
    }

    /// Gets an f64 value from the license metadata, or returns a default.
    pub fn get_f64_or(&self, key: &str, default: f64) -> f64 {
        self.get_f64(key).unwrap_or(default)
    }

    /// Gets a boolean value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not a boolean.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.payload.as_ref().and_then(|p| p.get_bool(key))
    }

    /// Gets a boolean value from the license metadata, or returns a default.
    pub fn get_bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    /// Gets an array value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not an array.
    pub fn get_array(&self, key: &str) -> Option<&Vec<serde_json::Value>> {
        self.payload.as_ref().and_then(|p| p.get_array(key))
    }

    /// Gets a string array from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not an array.
    pub fn get_string_array(&self, key: &str) -> Option<Vec<&str>> {
        self.payload.as_ref().and_then(|p| p.get_string_array(key))
    }

    /// Gets an object value from the license metadata.
    ///
    /// Returns `None` if validation failed, the key doesn't exist,
    /// or the value is not an object.
    pub fn get_object(&self, key: &str) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.payload.as_ref().and_then(|p| p.get_object(key))
    }

    /// Checks if a key exists in the license metadata.
    ///
    /// Returns `false` if validation failed or no metadata is present.
    pub fn has_key(&self, key: &str) -> bool {
        self.payload.as_ref().map(|p| p.has_key(key)).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_constraints_feature_allowed() {
        let mut constraints = LicenseConstraints::new();

        // No restrictions - all features allowed
        assert!(constraints.is_feature_allowed("any_feature"));

        // With allowed list
        constraints.allowed_features = Some(HashSet::from([
            "feature_a".to_string(),
            "feature_b".to_string(),
        ]));
        assert!(constraints.is_feature_allowed("feature_a"));
        assert!(!constraints.is_feature_allowed("feature_c"));

        // Denied list takes precedence
        constraints.denied_features = Some(HashSet::from(["feature_a".to_string()]));
        assert!(!constraints.is_feature_allowed("feature_a"));
        assert!(constraints.is_feature_allowed("feature_b"));
    }

    #[test]
    fn test_license_constraints_version_compatibility() {
        let mut constraints = LicenseConstraints::new();
        constraints.minimum_software_version = Some(Version::new(1, 0, 0));
        constraints.maximum_software_version = Some(Version::new(2, 0, 0));

        assert!(constraints
            .check_version_compatibility(&Version::new(1, 5, 0))
            .is_ok());
        assert!(constraints
            .check_version_compatibility(&Version::new(0, 9, 0))
            .is_err());
        assert!(constraints
            .check_version_compatibility(&Version::new(2, 1, 0))
            .is_err());
    }

    #[test]
    fn test_validation_context_builder() {
        let context = ValidationContext::new()
            .with_hostname("server.example.com")
            .with_software_version(Version::new(1, 2, 3))
            .with_feature("premium")
            .with_features(vec!["analytics", "reports"]);

        assert_eq!(
            context.current_hostname.as_deref(),
            Some("server.example.com")
        );
        assert_eq!(
            context.current_software_version,
            Some(Version::new(1, 2, 3))
        );
        assert_eq!(context.requested_features.len(), 3);
    }

    #[test]
    fn test_license_payload_version_check() {
        let payload = LicensePayload {
            format_version: LICENSE_FORMAT_VERSION,
            license_id: "test".to_string(),
            customer_id: "customer".to_string(),
            customer_name: None,
            issued_at: Utc::now(),
            constraints: LicenseConstraints::new(),
            metadata: None,
        };

        assert!(payload.is_version_supported());
    }

    #[test]
    fn test_signed_license_json_roundtrip() {
        let license = SignedLicense::new(
            "encoded_payload".to_string(),
            "encoded_signature".to_string(),
        );

        let json = license.to_json().unwrap();
        let parsed = SignedLicense::from_json(&json).unwrap();

        assert_eq!(license.encoded_payload, parsed.encoded_payload);
        assert_eq!(license.encoded_signature, parsed.encoded_signature);
    }

    #[test]
    fn test_license_payload_get_value() {
        let mut metadata = HashMap::new();
        metadata.insert("tier".to_string(), serde_json::json!("enterprise"));
        metadata.insert("max_users".to_string(), serde_json::json!(100));
        metadata.insert("is_beta".to_string(), serde_json::json!(true));
        metadata.insert("modules".to_string(), serde_json::json!(["core", "analytics"]));

        let payload = LicensePayload {
            format_version: LICENSE_FORMAT_VERSION,
            license_id: "test".to_string(),
            customer_id: "customer".to_string(),
            customer_name: None,
            issued_at: Utc::now(),
            constraints: LicenseConstraints::new(),
            metadata: Some(metadata),
        };

        // Test get_value
        assert!(payload.get_value("tier").is_some());
        assert!(payload.get_value("nonexistent").is_none());

        // Test get_string
        assert_eq!(payload.get_string("tier"), Some("enterprise"));
        assert_eq!(payload.get_string("max_users"), None); // Not a string
        assert_eq!(payload.get_string_or("tier", "basic"), "enterprise");
        assert_eq!(payload.get_string_or("nonexistent", "default"), "default");

        // Test get_i64
        assert_eq!(payload.get_i64("max_users"), Some(100));
        assert_eq!(payload.get_i64("tier"), None); // Not a number
        assert_eq!(payload.get_i64_or("max_users", 50), 100);
        assert_eq!(payload.get_i64_or("nonexistent", 50), 50);

        // Test get_bool
        assert_eq!(payload.get_bool("is_beta"), Some(true));
        assert_eq!(payload.get_bool("tier"), None); // Not a bool
        assert_eq!(payload.get_bool_or("is_beta", false), true);
        assert_eq!(payload.get_bool_or("nonexistent", false), false);

        // Test get_array
        assert!(payload.get_array("modules").is_some());
        assert_eq!(payload.get_array("modules").unwrap().len(), 2);

        // Test get_string_array
        let modules = payload.get_string_array("modules").unwrap();
        assert_eq!(modules, vec!["core", "analytics"]);

        // Test has_key
        assert!(payload.has_key("tier"));
        assert!(!payload.has_key("nonexistent"));

        // Test keys
        let keys: Vec<_> = payload.keys().collect();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn test_license_payload_get_value_no_metadata() {
        let payload = LicensePayload {
            format_version: LICENSE_FORMAT_VERSION,
            license_id: "test".to_string(),
            customer_id: "customer".to_string(),
            customer_name: None,
            issued_at: Utc::now(),
            constraints: LicenseConstraints::new(),
            metadata: None,
        };

        assert!(payload.get_value("any").is_none());
        assert_eq!(payload.get_string_or("any", "default"), "default");
        assert_eq!(payload.get_i64_or("any", 42), 42);
        assert!(!payload.has_key("any"));
        assert_eq!(payload.keys().count(), 0);
    }

    #[test]
    fn test_validation_result_get_value() {
        let mut metadata = HashMap::new();
        metadata.insert("tier".to_string(), serde_json::json!("premium"));
        metadata.insert("limit".to_string(), serde_json::json!(500));

        let payload = LicensePayload {
            format_version: LICENSE_FORMAT_VERSION,
            license_id: "test".to_string(),
            customer_id: "customer".to_string(),
            customer_name: None,
            issued_at: Utc::now(),
            constraints: LicenseConstraints::new(),
            metadata: Some(metadata),
        };

        let result = ValidationResult::success(payload);

        // Test getters on ValidationResult
        assert_eq!(result.get_string("tier"), Some("premium"));
        assert_eq!(result.get_string_or("tier", "basic"), "premium");
        assert_eq!(result.get_i64("limit"), Some(500));
        assert_eq!(result.get_i64_or("limit", 100), 500);
        assert!(result.has_key("tier"));
        assert!(!result.has_key("nonexistent"));
    }

    #[test]
    fn test_validation_result_get_value_failure() {
        let result = ValidationResult::failure(vec![]);

        // All getters should return None/default for failed validation
        assert!(result.get_value("any").is_none());
        assert_eq!(result.get_string_or("any", "default"), "default");
        assert_eq!(result.get_i64_or("any", 42), 42);
        assert!(!result.has_key("any"));
    }
}
