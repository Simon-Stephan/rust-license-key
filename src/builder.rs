//! License builder for creating and signing licenses.
//!
//! This module provides a fluent builder API for constructing license payloads
//! and signing them with Ed25519 keys. The builder validates required fields
//! before allowing license creation.
//!
//! # Publisher-Side Only
//!
//! This module should only be used by the software publisher to create licenses.
//! Client applications should only use the parser and validator modules.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use semver::Version;
use std::collections::{HashMap, HashSet};

use crate::crypto::KeyPair;
use crate::error::{LicenseError, Result};
use crate::models::{LicenseConstraints, LicensePayload, SignedLicense, LICENSE_FORMAT_VERSION};

// =============================================================================
// License Builder
// =============================================================================

/// A builder for creating signed licenses.
///
/// The builder provides a fluent API for setting license properties and
/// constraints. Required fields are validated before the license can be built.
///
/// # Required Fields
///
/// - `license_id` - A unique identifier for this license.
/// - `customer_id` - The identifier of the customer receiving this license.
///
/// # Example
///
/// ```
/// use rust_license_key::builder::LicenseBuilder;
/// use rust_license_key::crypto::KeyPair;
/// use chrono::{Utc, Duration};
///
/// let key_pair = KeyPair::generate().expect("Key generation failed");
///
/// let signed_license = LicenseBuilder::new()
///     .license_id("LIC-2024-001")
///     .customer_id("CUST-12345")
///     .customer_name("Acme Corporation")
///     .expires_in(Duration::days(365))
///     .allowed_feature("premium")
///     .allowed_feature("analytics")
///     .max_connections(100)
///     .build_and_sign(&key_pair)
///     .expect("License creation failed");
/// ```
#[derive(Debug, Clone, Default)]
pub struct LicenseBuilder {
    /// Unique license identifier.
    license_id: Option<String>,

    /// Customer identifier.
    customer_id: Option<String>,

    /// Optional customer name.
    customer_name: Option<String>,

    /// License issuance time. Defaults to current time if not set.
    issued_at: Option<DateTime<Utc>>,

    /// Constraints to apply to the license.
    constraints: LicenseConstraints,

    /// Additional metadata as key-value pairs.
    metadata: Option<HashMap<String, serde_json::Value>>,
}

impl LicenseBuilder {
    /// Creates a new empty license builder.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Required Fields
    // =========================================================================

    /// Sets the unique license identifier.
    ///
    /// This should be a unique string like a UUID or a formatted ID.
    /// It is used to identify and potentially revoke specific licenses.
    pub fn license_id(mut self, id: impl Into<String>) -> Self {
        self.license_id = Some(id.into());
        self
    }

    /// Sets the customer identifier.
    ///
    /// This identifies who the license is issued to. It could be a customer ID,
    /// email address, or organization identifier.
    pub fn customer_id(mut self, id: impl Into<String>) -> Self {
        self.customer_id = Some(id.into());
        self
    }

    // =========================================================================
    // Optional Fields
    // =========================================================================

    /// Sets the human-readable customer name.
    pub fn customer_name(mut self, name: impl Into<String>) -> Self {
        self.customer_name = Some(name.into());
        self
    }

    /// Sets the issuance timestamp.
    ///
    /// If not set, the current time will be used when building the license.
    pub fn issued_at(mut self, time: DateTime<Utc>) -> Self {
        self.issued_at = Some(time);
        self
    }

    // =========================================================================
    // Temporal Constraints
    // =========================================================================

    /// Sets the expiration date for the license.
    ///
    /// After this date, the license will no longer be valid.
    pub fn expires_at(mut self, expiration: DateTime<Utc>) -> Self {
        self.constraints.expiration_date = Some(expiration);
        self
    }

    /// Sets the license to expire after the given duration from now.
    ///
    /// This is a convenience method for setting expiration relative to
    /// the current time.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.constraints.expiration_date = Some(Utc::now() + duration);
        self
    }

    /// Sets the date when the license becomes valid.
    ///
    /// Before this date, the license will not be accepted.
    /// Useful for scheduling license activation.
    pub fn valid_from(mut self, valid_from: DateTime<Utc>) -> Self {
        self.constraints.valid_from = Some(valid_from);
        self
    }

    /// Sets the license to become valid after the given duration from now.
    pub fn valid_after(mut self, duration: Duration) -> Self {
        self.constraints.valid_from = Some(Utc::now() + duration);
        self
    }

    // =========================================================================
    // Feature Constraints
    // =========================================================================

    /// Adds a single allowed feature to the license.
    ///
    /// When allowed features are specified, only those features will be
    /// usable with this license.
    pub fn allowed_feature(mut self, feature: impl Into<String>) -> Self {
        self.constraints
            .allowed_features
            .get_or_insert_with(HashSet::new)
            .insert(feature.into());
        self
    }

    /// Adds multiple allowed features to the license.
    pub fn allowed_features(
        mut self,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let allowed = self
            .constraints
            .allowed_features
            .get_or_insert_with(HashSet::new);
        for feature in features {
            allowed.insert(feature.into());
        }
        self
    }

    /// Adds a denied feature to the license.
    ///
    /// Denied features take precedence over allowed features.
    pub fn denied_feature(mut self, feature: impl Into<String>) -> Self {
        self.constraints
            .denied_features
            .get_or_insert_with(HashSet::new)
            .insert(feature.into());
        self
    }

    /// Adds multiple denied features to the license.
    pub fn denied_features(
        mut self,
        features: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let denied = self
            .constraints
            .denied_features
            .get_or_insert_with(HashSet::new);
        for feature in features {
            denied.insert(feature.into());
        }
        self
    }

    // =========================================================================
    // Connection Constraints
    // =========================================================================

    /// Sets the maximum number of concurrent connections allowed.
    pub fn max_connections(mut self, max: u32) -> Self {
        self.constraints.max_connections = Some(max);
        self
    }

    // =========================================================================
    // Host and Machine Constraints
    // =========================================================================

    /// Adds an allowed hostname where this license can be used.
    pub fn allowed_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.constraints
            .allowed_hostnames
            .get_or_insert_with(HashSet::new)
            .insert(hostname.into());
        self
    }

    /// Adds multiple allowed hostnames.
    pub fn allowed_hostnames(
        mut self,
        hostnames: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let allowed = self
            .constraints
            .allowed_hostnames
            .get_or_insert_with(HashSet::new);
        for hostname in hostnames {
            allowed.insert(hostname.into());
        }
        self
    }

    /// Adds an allowed machine identifier.
    pub fn allowed_machine_id(mut self, machine_id: impl Into<String>) -> Self {
        self.constraints
            .allowed_machine_ids
            .get_or_insert_with(HashSet::new)
            .insert(machine_id.into());
        self
    }

    /// Adds multiple allowed machine identifiers.
    pub fn allowed_machine_ids(
        mut self,
        machine_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let allowed = self
            .constraints
            .allowed_machine_ids
            .get_or_insert_with(HashSet::new);
        for machine_id in machine_ids {
            allowed.insert(machine_id.into());
        }
        self
    }

    // =========================================================================
    // Version Constraints
    // =========================================================================

    /// Sets the minimum software version required for this license.
    pub fn minimum_version(mut self, version: Version) -> Self {
        self.constraints.minimum_software_version = Some(version);
        self
    }

    /// Sets the minimum software version from a string (e.g., "1.0.0").
    pub fn minimum_version_str(self, version: &str) -> Result<Self> {
        let parsed = Version::parse(version).map_err(|e| LicenseError::InvalidBuilderValue {
            field: "minimum_version".to_string(),
            reason: format!("invalid semver: {}", e),
        })?;
        Ok(self.minimum_version(parsed))
    }

    /// Sets the maximum software version allowed for this license.
    pub fn maximum_version(mut self, version: Version) -> Self {
        self.constraints.maximum_software_version = Some(version);
        self
    }

    /// Sets the maximum software version from a string (e.g., "2.0.0").
    pub fn maximum_version_str(self, version: &str) -> Result<Self> {
        let parsed = Version::parse(version).map_err(|e| LicenseError::InvalidBuilderValue {
            field: "maximum_version".to_string(),
            reason: format!("invalid semver: {}", e),
        })?;
        Ok(self.maximum_version(parsed))
    }

    // =========================================================================
    // Custom Constraints and Metadata
    // =========================================================================

    /// Adds a custom constraint for application-specific validation.
    pub fn custom_constraint(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.constraints
            .custom_constraints
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value);
        self
    }

    /// Adds metadata to the license.
    ///
    /// Metadata is not used for validation but can store additional
    /// information about the license.
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value);
        self
    }

    /// Adds a custom key-value pair to the license metadata.
    ///
    /// This is a convenient method for storing arbitrary data in the license
    /// that can be retrieved using the `get_*` methods on `LicensePayload`
    /// or `ValidationResult`.
    ///
    /// # Type Support
    ///
    /// This method accepts any value that can be converted to a JSON value,
    /// including:
    /// - Strings (`&str`, `String`)
    /// - Numbers (`i64`, `u64`, `f64`, etc.)
    /// - Booleans
    /// - Arrays (using `serde_json::json!([...])`)
    /// - Objects (using `serde_json::json!({...})`)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    /// use serde_json::json;
    ///
    /// let key_pair = KeyPair::generate().expect("Key generation failed");
    ///
    /// let license = LicenseBuilder::new()
    ///     .license_id("LIC-001")
    ///     .customer_id("CUST-001")
    ///     // String value
    ///     .add_key_value("tier", "enterprise")
    ///     // Integer value
    ///     .add_key_value("max_users", 100i64)
    ///     // Boolean value
    ///     .add_key_value("beta_features", true)
    ///     // Array value
    ///     .add_key_value("allowed_modules", json!(["core", "analytics", "reporting"]))
    ///     // Object value
    ///     .add_key_value("limits", json!({
    ///         "storage_gb": 500,
    ///         "bandwidth_tb": 10
    ///     }))
    ///     .build_and_sign(&key_pair)
    ///     .expect("License creation failed");
    /// ```
    ///
    /// # Retrieving Values
    ///
    /// Values can be retrieved after validation using the typed getters:
    ///
    /// ```ignore
    /// let result = validate_license(&license_json, PUBLIC_KEY, &context)?;
    ///
    /// // Get string value
    /// let tier = result.get_string_or("tier", "basic");
    ///
    /// // Get integer value
    /// let max_users = result.get_i64_or("max_users", 10);
    ///
    /// // Get boolean value
    /// let beta = result.get_bool_or("beta_features", false);
    ///
    /// // Get array value
    /// if let Some(modules) = result.get_string_array("allowed_modules") {
    ///     for module in modules {
    ///         println!("Module: {}", module);
    ///     }
    /// }
    /// ```
    pub fn add_key_value<V>(mut self, key: impl Into<String>, value: V) -> Self
    where
        V: Into<serde_json::Value>,
    {
        self.metadata
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value.into());
        self
    }

    /// Adds a string key-value pair to the license metadata.
    ///
    /// This is a convenience method equivalent to `add_key_value(key, value)`.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// let key_pair = KeyPair::generate().expect("Key generation failed");
    ///
    /// let license = LicenseBuilder::new()
    ///     .license_id("LIC-001")
    ///     .customer_id("CUST-001")
    ///     .add_string("company_tier", "enterprise")
    ///     .add_string("region", "EU")
    ///     .build_and_sign(&key_pair)
    ///     .expect("License creation failed");
    /// ```
    pub fn add_string(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_key_value(key, serde_json::Value::String(value.into()))
    }

    /// Adds an integer key-value pair to the license metadata.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// let key_pair = KeyPair::generate().expect("Key generation failed");
    ///
    /// let license = LicenseBuilder::new()
    ///     .license_id("LIC-001")
    ///     .customer_id("CUST-001")
    ///     .add_i64("max_users", 100)
    ///     .add_i64("max_projects", 50)
    ///     .build_and_sign(&key_pair)
    ///     .expect("License creation failed");
    /// ```
    pub fn add_i64(self, key: impl Into<String>, value: i64) -> Self {
        self.add_key_value(key, value)
    }

    /// Adds a boolean key-value pair to the license metadata.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// let key_pair = KeyPair::generate().expect("Key generation failed");
    ///
    /// let license = LicenseBuilder::new()
    ///     .license_id("LIC-001")
    ///     .customer_id("CUST-001")
    ///     .add_bool("allow_api_access", true)
    ///     .add_bool("is_trial", false)
    ///     .build_and_sign(&key_pair)
    ///     .expect("License creation failed");
    /// ```
    pub fn add_bool(self, key: impl Into<String>, value: bool) -> Self {
        self.add_key_value(key, value)
    }

    /// Adds a string array key-value pair to the license metadata.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_license_key::prelude::*;
    ///
    /// let key_pair = KeyPair::generate().expect("Key generation failed");
    ///
    /// let license = LicenseBuilder::new()
    ///     .license_id("LIC-001")
    ///     .customer_id("CUST-001")
    ///     .add_string_array("plugins", vec!["core", "analytics", "export"])
    ///     .build_and_sign(&key_pair)
    ///     .expect("License creation failed");
    /// ```
    pub fn add_string_array(
        self,
        key: impl Into<String>,
        values: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let array: Vec<serde_json::Value> = values
            .into_iter()
            .map(|s| serde_json::Value::String(s.into()))
            .collect();
        self.add_key_value(key, array)
    }

    /// Sets the constraints directly (replaces all existing constraints).
    pub fn with_constraints(mut self, constraints: LicenseConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    // =========================================================================
    // Build Methods
    // =========================================================================

    /// Validates the builder and returns any missing required fields.
    fn validate(&self) -> Vec<String> {
        let mut missing = Vec::new();

        if self.license_id.is_none() {
            missing.push("license_id".to_string());
        }

        if self.customer_id.is_none() {
            missing.push("customer_id".to_string());
        }

        missing
    }

    /// Builds the license payload without signing.
    ///
    /// This creates the payload structure that would be signed.
    /// Useful for inspection or testing.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing.
    pub fn build_payload(&self) -> Result<LicensePayload> {
        let missing = self.validate();
        if !missing.is_empty() {
            return Err(LicenseError::BuilderIncomplete {
                missing_fields: missing.join(", "),
            });
        }

        // Safe to unwrap because we validated above
        let license_id = self.license_id.clone().unwrap();
        let customer_id = self.customer_id.clone().unwrap();

        Ok(LicensePayload {
            format_version: LICENSE_FORMAT_VERSION,
            license_id,
            customer_id,
            customer_name: self.customer_name.clone(),
            issued_at: self.issued_at.unwrap_or_else(Utc::now),
            constraints: self.constraints.clone(),
            metadata: self.metadata.clone(),
        })
    }

    /// Builds and signs the license with the given key pair.
    ///
    /// This creates a complete signed license ready for distribution.
    ///
    /// # Arguments
    ///
    /// * `key_pair` - The publisher's key pair used to sign the license.
    ///
    /// # Returns
    ///
    /// A `SignedLicense` that can be serialized and distributed to the customer.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or signing fails.
    pub fn build_and_sign(&self, key_pair: &KeyPair) -> Result<SignedLicense> {
        let payload = self.build_payload()?;

        // Serialize payload to JSON
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| LicenseError::JsonSerializationFailed {
                reason: e.to_string(),
            })?;

        // Encode payload as base64
        let encoded_payload = BASE64_STANDARD.encode(payload_json.as_bytes());

        // Sign the encoded payload (we sign the base64 representation for consistency)
        let signature_base64 = key_pair.sign_base64(encoded_payload.as_bytes());

        Ok(SignedLicense::new(encoded_payload, signature_base64))
    }

    /// Builds, signs, and returns the license as a JSON string.
    ///
    /// This is a convenience method that combines building, signing,
    /// and serialization into a single call.
    ///
    /// # Arguments
    ///
    /// * `key_pair` - The publisher's key pair used to sign the license.
    ///
    /// # Returns
    ///
    /// A JSON string containing the signed license, ready to be saved to a file.
    pub fn build_and_sign_to_json(&self, key_pair: &KeyPair) -> Result<String> {
        let signed_license = self.build_and_sign(key_pair)?;
        signed_license
            .to_json()
            .map_err(|e| LicenseError::JsonSerializationFailed {
                reason: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key_pair() -> KeyPair {
        KeyPair::generate().expect("Key generation should succeed")
    }

    #[test]
    fn test_builder_required_fields() {
        let key_pair = create_test_key_pair();

        // Missing all required fields
        let result = LicenseBuilder::new().build_and_sign(&key_pair);
        assert!(result.is_err());

        // Missing customer_id
        let result = LicenseBuilder::new()
            .license_id("LIC-001")
            .build_and_sign(&key_pair);
        assert!(result.is_err());

        // All required fields present
        let result = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .build_and_sign(&key_pair);
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_with_expiration() {
        let key_pair = create_test_key_pair();

        let signed = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .expires_in(Duration::days(30))
            .build_and_sign(&key_pair)
            .expect("Should build license");

        assert!(!signed.encoded_payload.is_empty());
        assert!(!signed.encoded_signature.is_empty());
    }

    #[test]
    fn test_builder_with_features() {
        let _key_pair = create_test_key_pair();

        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .allowed_feature("premium")
            .allowed_features(vec!["analytics", "reports"])
            .denied_feature("admin")
            .build_payload()
            .expect("Should build payload");

        let allowed = license.constraints.allowed_features.as_ref().unwrap();
        assert!(allowed.contains("premium"));
        assert!(allowed.contains("analytics"));
        assert!(allowed.contains("reports"));

        let denied = license.constraints.denied_features.as_ref().unwrap();
        assert!(denied.contains("admin"));
    }

    #[test]
    fn test_builder_with_version_constraints() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .minimum_version_str("1.0.0")
            .expect("Valid version")
            .maximum_version_str("2.0.0")
            .expect("Valid version")
            .build_payload()
            .expect("Should build payload");

        assert_eq!(
            license.constraints.minimum_software_version,
            Some(Version::new(1, 0, 0))
        );
        assert_eq!(
            license.constraints.maximum_software_version,
            Some(Version::new(2, 0, 0))
        );
    }

    #[test]
    fn test_builder_with_hostnames() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .allowed_hostname("server1.example.com")
            .allowed_hostnames(vec!["server2.example.com", "server3.example.com"])
            .build_payload()
            .expect("Should build payload");

        let allowed = license.constraints.allowed_hostnames.as_ref().unwrap();
        assert_eq!(allowed.len(), 3);
        assert!(allowed.contains("server1.example.com"));
    }

    #[test]
    fn test_builder_with_metadata() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .customer_name("Acme Corp")
            .metadata("contract_id", serde_json::json!("CONTRACT-2024"))
            .metadata("sales_rep", serde_json::json!("John Doe"))
            .build_payload()
            .expect("Should build payload");

        assert_eq!(license.customer_name.as_deref(), Some("Acme Corp"));

        let metadata = license.metadata.as_ref().unwrap();
        assert_eq!(metadata["contract_id"], serde_json::json!("CONTRACT-2024"));
    }

    #[test]
    fn test_build_and_sign_to_json() {
        let key_pair = create_test_key_pair();

        let json = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .build_and_sign_to_json(&key_pair)
            .expect("Should build license JSON");

        // Verify it's valid JSON
        let parsed: SignedLicense =
            serde_json::from_str(&json).expect("Should parse as SignedLicense");
        assert!(!parsed.encoded_payload.is_empty());
    }

    #[test]
    fn test_invalid_version_string() {
        let result = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .minimum_version_str("not-a-version");

        assert!(result.is_err());
    }

    #[test]
    fn test_valid_from_constraint() {
        let future_time = Utc::now() + Duration::days(7);

        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .valid_from(future_time)
            .build_payload()
            .expect("Should build payload");

        assert!(license.constraints.valid_from.is_some());
    }

    #[test]
    fn test_max_connections() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .max_connections(50)
            .build_payload()
            .expect("Should build payload");

        assert_eq!(license.constraints.max_connections, Some(50));
    }

    #[test]
    fn test_custom_constraints() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .custom_constraint("max_storage_gb", serde_json::json!(100))
            .custom_constraint("tier", serde_json::json!("enterprise"))
            .build_payload()
            .expect("Should build payload");

        let custom = license.constraints.custom_constraints.as_ref().unwrap();
        assert_eq!(custom["max_storage_gb"], serde_json::json!(100));
        assert_eq!(custom["tier"], serde_json::json!("enterprise"));
    }

    #[test]
    fn test_add_key_value_string() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_key_value("tier", "enterprise")
            .add_string("region", "EU")
            .build_payload()
            .expect("Should build payload");

        assert_eq!(license.get_string("tier"), Some("enterprise"));
        assert_eq!(license.get_string("region"), Some("EU"));
    }

    #[test]
    fn test_add_key_value_integer() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_key_value("max_users", 100i64)
            .add_i64("max_projects", 50)
            .build_payload()
            .expect("Should build payload");

        assert_eq!(license.get_i64("max_users"), Some(100));
        assert_eq!(license.get_i64("max_projects"), Some(50));
    }

    #[test]
    fn test_add_key_value_boolean() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_key_value("is_trial", false)
            .add_bool("allow_api", true)
            .build_payload()
            .expect("Should build payload");

        assert_eq!(license.get_bool("is_trial"), Some(false));
        assert_eq!(license.get_bool("allow_api"), Some(true));
    }

    #[test]
    fn test_add_key_value_array() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_key_value("modules", serde_json::json!(["core", "analytics", "export"]))
            .add_string_array("plugins", vec!["plugin1", "plugin2"])
            .build_payload()
            .expect("Should build payload");

        let modules = license.get_string_array("modules").unwrap();
        assert_eq!(modules, vec!["core", "analytics", "export"]);

        let plugins = license.get_string_array("plugins").unwrap();
        assert_eq!(plugins, vec!["plugin1", "plugin2"]);
    }

    #[test]
    fn test_add_key_value_object() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_key_value("limits", serde_json::json!({
                "storage_gb": 500,
                "bandwidth_tb": 10
            }))
            .build_payload()
            .expect("Should build payload");

        let limits = license.get_object("limits").unwrap();
        assert_eq!(limits["storage_gb"], serde_json::json!(500));
        assert_eq!(limits["bandwidth_tb"], serde_json::json!(10));
    }

    #[test]
    fn test_add_key_value_mixed_types() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_string("company", "Acme Corp")
            .add_i64("employees", 500)
            .add_bool("enterprise", true)
            .add_string_array("regions", vec!["US", "EU", "APAC"])
            .add_key_value("config", serde_json::json!({
                "theme": "dark",
                "notifications": true
            }))
            .build_payload()
            .expect("Should build payload");

        assert_eq!(license.get_string("company"), Some("Acme Corp"));
        assert_eq!(license.get_i64("employees"), Some(500));
        assert_eq!(license.get_bool("enterprise"), Some(true));

        let regions = license.get_string_array("regions").unwrap();
        assert_eq!(regions.len(), 3);

        let config = license.get_object("config").unwrap();
        assert_eq!(config["theme"], serde_json::json!("dark"));
    }

    #[test]
    fn test_add_key_value_with_defaults() {
        let license = LicenseBuilder::new()
            .license_id("LIC-001")
            .customer_id("CUST-001")
            .add_i64("limit", 100)
            .build_payload()
            .expect("Should build payload");

        // Existing key returns value
        assert_eq!(license.get_i64_or("limit", 50), 100);

        // Missing key returns default
        assert_eq!(license.get_i64_or("nonexistent", 50), 50);
        assert_eq!(license.get_string_or("missing", "default"), "default");
        assert_eq!(license.get_bool_or("missing", true), true);
    }
}
