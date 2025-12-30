# API Reference

Complete reference for all public types, functions, and modules in rust-license-key.

## Table of Contents

- [Module: `crypto`](#module-crypto)
- [Module: `builder`](#module-builder)
- [Module: `parser`](#module-parser)
- [Module: `validator`](#module-validator)
- [Module: `models`](#module-models)
- [Module: `error`](#module-error)
- [Module: `prelude`](#module-prelude)

---

## Module: `crypto`

Cryptographic operations for license signing and verification.

### `KeyPair`

Ed25519 key pair for signing licenses.

```rust
pub struct KeyPair { /* private fields */ }
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `generate` | `fn generate() -> Result<Self>` | Generate a new random key pair |
| `from_private_key_base64` | `fn from_private_key_base64(key: &str) -> Result<Self>` | Create from base64-encoded private key |
| `from_private_key_bytes` | `fn from_private_key_bytes(bytes: &[u8]) -> Result<Self>` | Create from raw private key bytes |
| `public_key` | `fn public_key(&self) -> PublicKey` | Get the associated public key |
| `private_key_bytes` | `fn private_key_bytes(&self) -> [u8; 32]` | Get raw private key bytes |
| `private_key_base64` | `fn private_key_base64(&self) -> String` | Get base64-encoded private key |
| `public_key_base64` | `fn public_key_base64(&self) -> String` | Get base64-encoded public key |
| `sign` | `fn sign(&self, data: &[u8]) -> [u8; 64]` | Sign data, return raw signature |
| `sign_base64` | `fn sign_base64(&self, data: &[u8]) -> String` | Sign data, return base64 signature |

### `PublicKey`

Ed25519 public key for verification.

```rust
pub struct PublicKey { /* private fields */ }
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `from_base64` | `fn from_base64(key: &str) -> Result<Self>` | Create from base64 string |
| `from_bytes` | `fn from_bytes(bytes: &[u8]) -> Result<Self>` | Create from raw bytes |
| `to_bytes` | `fn to_bytes(&self) -> [u8; 32]` | Get raw bytes |
| `to_base64` | `fn to_base64(&self) -> String` | Get base64 encoding |
| `verify` | `fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()>` | Verify raw signature |
| `verify_base64` | `fn verify_base64(&self, data: &[u8], sig: &str) -> Result<()>` | Verify base64 signature |

### Functions

```rust
/// Generate key pair and return as (private_base64, public_base64)
pub fn generate_key_pair_base64() -> Result<(String, String)>
```

---

## Module: `builder`

License creation and signing.

### `LicenseBuilder`

Fluent builder for creating licenses.

```rust
pub struct LicenseBuilder { /* private fields */ }
```

#### Constructor

```rust
pub fn new() -> Self
```

#### Required Fields

| Method | Signature | Description |
|--------|-----------|-------------|
| `license_id` | `fn license_id(self, id: impl Into<String>) -> Self` | Set unique license ID |
| `customer_id` | `fn customer_id(self, id: impl Into<String>) -> Self` | Set customer ID |

#### Optional Fields

| Method | Signature | Description |
|--------|-----------|-------------|
| `customer_name` | `fn customer_name(self, name: impl Into<String>) -> Self` | Set customer name |
| `issued_at` | `fn issued_at(self, time: DateTime<Utc>) -> Self` | Set issuance time |

#### Temporal Constraints

| Method | Signature | Description |
|--------|-----------|-------------|
| `expires_at` | `fn expires_at(self, time: DateTime<Utc>) -> Self` | Set expiration date |
| `expires_in` | `fn expires_in(self, duration: Duration) -> Self` | Set expiration relative to now |
| `valid_from` | `fn valid_from(self, time: DateTime<Utc>) -> Self` | Set activation date |
| `valid_after` | `fn valid_after(self, duration: Duration) -> Self` | Set activation relative to now |

#### Feature Constraints

| Method | Signature | Description |
|--------|-----------|-------------|
| `allowed_feature` | `fn allowed_feature(self, feature: impl Into<String>) -> Self` | Add one allowed feature |
| `allowed_features` | `fn allowed_features(self, features: impl IntoIterator<...>) -> Self` | Add multiple allowed features |
| `denied_feature` | `fn denied_feature(self, feature: impl Into<String>) -> Self` | Add one denied feature |
| `denied_features` | `fn denied_features(self, features: impl IntoIterator<...>) -> Self` | Add multiple denied features |

#### Other Constraints

| Method | Signature | Description |
|--------|-----------|-------------|
| `max_connections` | `fn max_connections(self, max: u32) -> Self` | Set connection limit |
| `allowed_hostname` | `fn allowed_hostname(self, host: impl Into<String>) -> Self` | Add allowed hostname |
| `allowed_hostnames` | `fn allowed_hostnames(self, hosts: impl IntoIterator<...>) -> Self` | Add multiple hostnames |
| `allowed_machine_id` | `fn allowed_machine_id(self, id: impl Into<String>) -> Self` | Add allowed machine ID |
| `allowed_machine_ids` | `fn allowed_machine_ids(self, ids: impl IntoIterator<...>) -> Self` | Add multiple machine IDs |
| `minimum_version` | `fn minimum_version(self, version: Version) -> Self` | Set minimum software version |
| `minimum_version_str` | `fn minimum_version_str(self, version: &str) -> Result<Self>` | Set minimum version from string |
| `maximum_version` | `fn maximum_version(self, version: Version) -> Self` | Set maximum software version |
| `maximum_version_str` | `fn maximum_version_str(self, version: &str) -> Result<Self>` | Set maximum version from string |

#### Custom Data

| Method | Signature | Description |
|--------|-----------|-------------|
| `custom_constraint` | `fn custom_constraint(self, key: impl Into<String>, value: Value) -> Self` | Add custom constraint |
| `metadata` | `fn metadata(self, key: impl Into<String>, value: Value) -> Self` | Add metadata |
| `add_key_value` | `fn add_key_value<V: Into<Value>>(self, key: impl Into<String>, value: V) -> Self` | Add any key-value pair |
| `add_string` | `fn add_string(self, key: impl Into<String>, value: impl Into<String>) -> Self` | Add string value |
| `add_i64` | `fn add_i64(self, key: impl Into<String>, value: i64) -> Self` | Add integer value |
| `add_bool` | `fn add_bool(self, key: impl Into<String>, value: bool) -> Self` | Add boolean value |
| `add_string_array` | `fn add_string_array(self, key: impl Into<String>, values: impl IntoIterator<...>) -> Self` | Add string array |
| `with_constraints` | `fn with_constraints(self, constraints: LicenseConstraints) -> Self` | Set all constraints |

#### Build Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `build_payload` | `fn build_payload(&self) -> Result<LicensePayload>` | Build payload without signing |
| `build_and_sign` | `fn build_and_sign(&self, key_pair: &KeyPair) -> Result<SignedLicense>` | Build and sign |
| `build_and_sign_to_json` | `fn build_and_sign_to_json(&self, key_pair: &KeyPair) -> Result<String>` | Build, sign, and serialize |

---

## Module: `parser`

License loading and signature verification.

### `LicenseParser`

Parser for verifying and decoding licenses.

```rust
pub struct LicenseParser { /* private fields */ }
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new(public_key: PublicKey) -> Self` | Create with public key |
| `from_public_key_base64` | `fn from_public_key_base64(key: &str) -> Result<Self>` | Create from base64 key |
| `parse_json` | `fn parse_json(&self, json: &str) -> Result<LicensePayload>` | Parse and verify license |
| `parse_signed_license` | `fn parse_signed_license(&self, license: &SignedLicense) -> Result<LicensePayload>` | Parse SignedLicense struct |
| `decode_unverified` | `fn decode_unverified(&self, json: &str) -> Result<(LicensePayload, bool)>` | Decode without failing on invalid signature |
| `public_key` | `fn public_key(&self) -> &PublicKey` | Get reference to public key |

### Functions

```rust
/// Parse license with one-shot validation
pub fn parse_license(license_json: &str, public_key_base64: &str) -> Result<LicensePayload>

/// Extract payload without verification (for debugging only)
pub fn extract_payload_unverified(license_json: &str) -> Result<String>
```

---

## Module: `validator`

License validation against runtime context.

### `LicenseValidator`

Full license validation with constraint checking.

```rust
pub struct LicenseValidator { /* private fields */ }
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new(public_key: PublicKey) -> Self` | Create with public key |
| `from_public_key_base64` | `fn from_public_key_base64(key: &str) -> Result<Self>` | Create from base64 key |
| `validate_json` | `fn validate_json(&self, json: &str, context: &ValidationContext) -> Result<ValidationResult>` | Full validation |
| `validate_payload` | `fn validate_payload(&self, payload: &LicensePayload, context: &ValidationContext) -> ValidationResult` | Validate already-parsed payload |
| `parser` | `fn parser(&self) -> &LicenseParser` | Get reference to internal parser |

### Functions

```rust
/// One-shot license validation
pub fn validate_license(
    license_json: &str,
    public_key_base64: &str,
    context: &ValidationContext
) -> Result<ValidationResult>

/// Quick validity check
pub fn is_license_valid(license_json: &str, public_key_base64: &str) -> bool

/// Check if feature is allowed
pub fn is_feature_allowed(license_json: &str, public_key_base64: &str, feature: &str) -> bool
```

---

## Module: `models`

Data structures for licenses and validation.

### `LicensePayload`

The core license data structure.

```rust
pub struct LicensePayload {
    pub format_version: u32,
    pub license_id: String,
    pub customer_id: String,
    pub customer_name: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub constraints: LicenseConstraints,
    pub metadata: Option<HashMap<String, Value>>,
}
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `id` | `fn id(&self) -> &str` | Get license ID |
| `customer` | `fn customer(&self) -> &str` | Get customer ID |
| `is_version_supported` | `fn is_version_supported(&self) -> bool` | Check version compatibility |

#### Key-Value Getter Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `get_value` | `fn get_value(&self, key: &str) -> Option<&Value>` | Get raw JSON value |
| `get_value_or` | `fn get_value_or(&self, key: &str, default: &Value) -> &Value` | Get value or default |
| `get_string` | `fn get_string(&self, key: &str) -> Option<&str>` | Get string value |
| `get_string_or` | `fn get_string_or(&self, key: &str, default: &str) -> &str` | Get string or default |
| `get_i64` | `fn get_i64(&self, key: &str) -> Option<i64>` | Get i64 value |
| `get_i64_or` | `fn get_i64_or(&self, key: &str, default: i64) -> i64` | Get i64 or default |
| `get_u64` | `fn get_u64(&self, key: &str) -> Option<u64>` | Get u64 value |
| `get_u64_or` | `fn get_u64_or(&self, key: &str, default: u64) -> u64` | Get u64 or default |
| `get_f64` | `fn get_f64(&self, key: &str) -> Option<f64>` | Get f64 value |
| `get_f64_or` | `fn get_f64_or(&self, key: &str, default: f64) -> f64` | Get f64 or default |
| `get_bool` | `fn get_bool(&self, key: &str) -> Option<bool>` | Get boolean value |
| `get_bool_or` | `fn get_bool_or(&self, key: &str, default: bool) -> bool` | Get boolean or default |
| `get_array` | `fn get_array(&self, key: &str) -> Option<&Vec<Value>>` | Get array value |
| `get_string_array` | `fn get_string_array(&self, key: &str) -> Option<Vec<&str>>` | Get string array |
| `get_object` | `fn get_object(&self, key: &str) -> Option<&Map<String, Value>>` | Get object value |
| `has_key` | `fn has_key(&self, key: &str) -> bool` | Check if key exists |
| `keys` | `fn keys(&self) -> impl Iterator<Item = &String>` | Get all keys |

### `LicenseConstraints`

All optional constraints.

```rust
pub struct LicenseConstraints {
    pub expiration_date: Option<DateTime<Utc>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub allowed_features: Option<HashSet<String>>,
    pub denied_features: Option<HashSet<String>>,
    pub max_connections: Option<u32>,
    pub allowed_hostnames: Option<HashSet<String>>,
    pub allowed_machine_ids: Option<HashSet<String>>,
    pub minimum_software_version: Option<Version>,
    pub maximum_software_version: Option<Version>,
    pub custom_constraints: Option<HashMap<String, Value>>,
}
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new() -> Self` | Create empty constraints |
| `is_feature_allowed` | `fn is_feature_allowed(&self, feature: &str) -> bool` | Check feature |
| `is_hostname_allowed` | `fn is_hostname_allowed(&self, hostname: &str) -> bool` | Check hostname |
| `is_machine_id_allowed` | `fn is_machine_id_allowed(&self, id: &str) -> bool` | Check machine ID |
| `check_version_compatibility` | `fn check_version_compatibility(&self, version: &Version) -> Result<(), String>` | Check version |

### `SignedLicense`

Container for signed license data.

```rust
pub struct SignedLicense {
    pub encoded_payload: String,    // Base64-encoded JSON payload
    pub encoded_signature: String,  // Base64-encoded signature
}
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new(payload: String, signature: String) -> Self` | Create from components |
| `to_json` | `fn to_json(&self) -> Result<String, serde_json::Error>` | Serialize to JSON |
| `from_json` | `fn from_json(json: &str) -> Result<Self, serde_json::Error>` | Deserialize from JSON |

### `ValidationContext`

Runtime context for validation.

```rust
pub struct ValidationContext {
    pub current_time: Option<DateTime<Utc>>,
    pub current_hostname: Option<String>,
    pub current_machine_id: Option<String>,
    pub current_software_version: Option<Version>,
    pub current_connection_count: Option<u32>,
    pub requested_features: Vec<String>,
    pub custom_values: HashMap<String, Value>,
}
```

#### Builder Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new() -> Self` | Create empty context |
| `with_time` | `fn with_time(self, time: DateTime<Utc>) -> Self` | Set current time |
| `with_hostname` | `fn with_hostname(self, hostname: impl Into<String>) -> Self` | Set hostname |
| `with_machine_id` | `fn with_machine_id(self, id: impl Into<String>) -> Self` | Set machine ID |
| `with_software_version` | `fn with_software_version(self, version: Version) -> Self` | Set version |
| `with_connection_count` | `fn with_connection_count(self, count: u32) -> Self` | Set connection count |
| `with_feature` | `fn with_feature(self, feature: impl Into<String>) -> Self` | Add feature to check |
| `with_features` | `fn with_features(self, features: impl IntoIterator<...>) -> Self` | Add multiple features |
| `with_custom_value` | `fn with_custom_value(self, key: impl Into<String>, value: Value) -> Self` | Add custom value |

### `ValidationResult`

Result of license validation.

```rust
pub struct ValidationResult {
    pub is_valid: bool,
    pub payload: Option<LicensePayload>,
    pub failures: Vec<ValidationFailure>,
    pub time_remaining: Option<Duration>,
    pub allowed_features: Option<HashSet<String>>,
    pub denied_features: Option<HashSet<String>>,
}
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `success` | `fn success(payload: LicensePayload) -> Self` | Create success result |
| `failure` | `fn failure(failures: Vec<ValidationFailure>) -> Self` | Create failure result |
| `add_failure` | `fn add_failure(&mut self, failure: ValidationFailure)` | Add a failure |
| `is_active` | `fn is_active(&self) -> bool` | Check valid and not expired |
| `days_remaining` | `fn days_remaining(&self) -> Option<i64>` | Get days until expiration |
| `is_feature_allowed` | `fn is_feature_allowed(&self, feature: &str) -> bool` | Check feature |

#### Key-Value Getter Methods (delegated to payload)

| Method | Signature | Description |
|--------|-----------|-------------|
| `get_value` | `fn get_value(&self, key: &str) -> Option<&Value>` | Get raw JSON value |
| `get_value_or` | `fn get_value_or(&self, key: &str, default: &Value) -> &Value` | Get value or default |
| `get_string` | `fn get_string(&self, key: &str) -> Option<&str>` | Get string value |
| `get_string_or` | `fn get_string_or(&self, key: &str, default: &str) -> &str` | Get string or default |
| `get_i64` | `fn get_i64(&self, key: &str) -> Option<i64>` | Get i64 value |
| `get_i64_or` | `fn get_i64_or(&self, key: &str, default: i64) -> i64` | Get i64 or default |
| `get_u64` | `fn get_u64(&self, key: &str) -> Option<u64>` | Get u64 value |
| `get_u64_or` | `fn get_u64_or(&self, key: &str, default: u64) -> u64` | Get u64 or default |
| `get_f64` | `fn get_f64(&self, key: &str) -> Option<f64>` | Get f64 value |
| `get_f64_or` | `fn get_f64_or(&self, key: &str, default: f64) -> f64` | Get f64 or default |
| `get_bool` | `fn get_bool(&self, key: &str) -> Option<bool>` | Get boolean value |
| `get_bool_or` | `fn get_bool_or(&self, key: &str, default: bool) -> bool` | Get boolean or default |
| `get_array` | `fn get_array(&self, key: &str) -> Option<&Vec<Value>>` | Get array value |
| `get_string_array` | `fn get_string_array(&self, key: &str) -> Option<Vec<&str>>` | Get string array |
| `get_object` | `fn get_object(&self, key: &str) -> Option<&Map<String, Value>>` | Get object value |
| `has_key` | `fn has_key(&self, key: &str) -> bool` | Check if key exists |

**Note:** These methods return `None`/default if validation failed or if no payload is available.

### Constants

```rust
pub const LICENSE_FORMAT_VERSION: u32 = 1;
pub const MIN_SUPPORTED_LICENSE_VERSION: u32 = 1;
pub const MAX_SUPPORTED_LICENSE_VERSION: u32 = 1;
```

---

## Module: `error`

Error types and validation failures.

### `LicenseError`

Main error enum.

```rust
pub enum LicenseError {
    // Cryptographic
    KeyGenerationFailed { reason: String },
    InvalidPrivateKey { reason: String },
    InvalidPublicKey { reason: String },
    InvalidSignature,
    SigningFailed { reason: String },

    // Encoding
    Base64EncodingFailed { reason: String },
    Base64DecodingFailed { reason: String },
    JsonSerializationFailed { reason: String },
    JsonDeserializationFailed { reason: String },

    // Format
    InvalidLicenseFormat { reason: String },
    UnsupportedLicenseVersion { found: u32, supported: String },
    MissingRequiredField { field_name: String },

    // Validation
    LicenseExpired { expiration_date: String },
    LicenseNotYetValid { valid_from: String },
    IncompatibleSoftwareVersion { current: String, reason: String },
    FeatureNotAllowed { feature: String },
    HostnameNotAllowed { hostname: String },
    MachineIdNotAllowed { machine_id: String },
    ConnectionLimitExceeded { max_allowed: u32 },
    ConstraintValidationFailed { constraint_name: String, reason: String },

    // Builder
    BuilderIncomplete { missing_fields: String },
    InvalidBuilderValue { field: String, reason: String },
}
```

### `ValidationFailure`

Detailed failure information.

```rust
pub struct ValidationFailure {
    pub failure_type: ValidationFailureType,
    pub message: String,
    pub context: Option<String>,
}
```

### `ValidationFailureType`

Categorized failure types.

```rust
pub enum ValidationFailureType {
    InvalidSignature,
    Expired,
    NotYetValid,
    UnsupportedVersion,
    FeatureConstraint,
    HostnameConstraint,
    MachineIdConstraint,
    VersionConstraint,
    ConnectionLimit,
    MalformedLicense,
    CustomConstraint,
}
```

### Type Alias

```rust
pub type Result<T> = std::result::Result<T, LicenseError>;
```

---

## Module: `prelude`

Convenient re-exports for common usage.

```rust
pub use crate::crypto::{generate_key_pair_base64, KeyPair, PublicKey};
pub use crate::builder::LicenseBuilder;
pub use crate::parser::{parse_license, LicenseParser};
pub use crate::validator::{is_feature_allowed, is_license_valid, validate_license, LicenseValidator};
pub use crate::models::{
    LicenseConstraints, LicensePayload, SignedLicense,
    ValidationContext, ValidationResult, LICENSE_FORMAT_VERSION,
};
pub use crate::error::{LicenseError, Result, ValidationFailure, ValidationFailureType};
```

**Usage:**
```rust
use rust_license_key::prelude::*;
```

---

**Previous:** [User Guide](./user-guide.md) | **Next:** [Security Best Practices](./security.md)
