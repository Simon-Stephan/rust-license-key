# User Guide

This comprehensive guide covers all aspects of using rust-license-key for creating and validating software licenses.

## Table of Contents

1. [Key Management](#key-management)
2. [Building Licenses](#building-licenses)
3. [License Constraints](#license-constraints)
4. [Validating Licenses](#validating-licenses)
5. [Validation Context](#validation-context)
6. [Working with Results](#working-with-results)
7. [Error Handling](#error-handling)

---

## Key Management

### Generating Key Pairs

Key pairs should be generated once and stored securely. The private key is used to sign licenses; the public key is embedded in your application.

```rust
use rust_license_key::crypto::KeyPair;

// Generate a new random key pair
let key_pair = KeyPair::generate()?;

// Export keys for storage
let private_key_base64 = key_pair.private_key_base64();
let public_key_base64 = key_pair.public_key_base64();
```

### Loading Existing Keys

To load a previously generated private key:

```rust
use rust_license_key::crypto::KeyPair;

// Load from base64 string
let key_pair = KeyPair::from_private_key_base64(
    "your-base64-encoded-private-key"
)?;

// The public key is automatically derived
let public_key = key_pair.public_key();
```

### Working with Public Keys

On the client side, you only need the public key:

```rust
use rust_license_key::crypto::PublicKey;

// Load public key from base64
let public_key = PublicKey::from_base64(
    "your-base64-encoded-public-key"
)?;

// Or from raw bytes
let public_key = PublicKey::from_bytes(&key_bytes)?;
```

### Key Storage Best Practices

| Key Type | Storage Location | Access Control |
|----------|-----------------|----------------|
| Private Key | Secure server, HSM, or encrypted vault | Minimal access, audit logging |
| Public Key | Embedded in application binary | Public access is safe |

---

## Building Licenses

The `LicenseBuilder` provides a fluent API for creating licenses.

### Required Fields

Every license must have:

```rust
use rust_license_key::builder::LicenseBuilder;

let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")     // Unique identifier
    .customer_id("CUST-12345")      // Customer identifier
    .build_and_sign(&key_pair)?;
```

### Optional Customer Information

```rust
let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")
    .customer_id("CUST-12345")
    .customer_name("Acme Corporation")  // Human-readable name
    .issued_at(Utc::now())              // Custom issuance time
    .build_and_sign(&key_pair)?;
```

### Adding Metadata

Store arbitrary data that doesn't affect validation:

```rust
use serde_json::json;

let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")
    .customer_id("CUST-12345")
    .metadata("contract_id", json!("CNT-2024-001"))
    .metadata("sales_rep", json!("John Doe"))
    .metadata("tier", json!("enterprise"))
    .build_and_sign(&key_pair)?;
```

### Adding Custom Key-Value Pairs

The `add_key_value` method provides a user-friendly way to store typed data:

```rust
use serde_json::json;

let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")
    .customer_id("CUST-12345")
    // String value
    .add_key_value("tier", "enterprise")
    // Integer value
    .add_key_value("max_users", 100i64)
    // Boolean value
    .add_key_value("beta_features", true)
    // Array value
    .add_key_value("allowed_modules", json!(["core", "analytics", "reporting"]))
    // Object value
    .add_key_value("limits", json!({
        "storage_gb": 500,
        "bandwidth_tb": 10
    }))
    .build_and_sign(&key_pair)?;
```

#### Type-Specific Builder Methods

For convenience, there are also typed methods:

```rust
let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")
    .customer_id("CUST-12345")
    .add_string("company_name", "Acme Corp")      // String values
    .add_i64("employee_count", 500)               // Integer values
    .add_bool("is_enterprise", true)              // Boolean values
    .add_string_array("regions", vec!["US", "EU", "APAC"])  // String arrays
    .build_and_sign(&key_pair)?;
```

### Output Formats

```rust
// Get SignedLicense struct
let signed = builder.build_and_sign(&key_pair)?;

// Get JSON string directly
let json_string = builder.build_and_sign_to_json(&key_pair)?;

// Get just the payload (without signing)
let payload = builder.build_payload()?;
```

---

## License Constraints

Constraints define the conditions under which a license is valid.

### Temporal Constraints

#### Expiration Date

```rust
use chrono::{Duration, Utc};

// Expire at a specific date
let builder = LicenseBuilder::new()
    .expires_at(Utc::now() + Duration::days(365));

// Expire after a duration from now
let builder = LicenseBuilder::new()
    .expires_in(Duration::days(30));

// No expiration (perpetual license)
let builder = LicenseBuilder::new();  // Just don't set expiration
```

#### Delayed Activation

```rust
// License becomes valid in the future
let builder = LicenseBuilder::new()
    .valid_from(Utc::now() + Duration::days(7));

// Or using duration
let builder = LicenseBuilder::new()
    .valid_after(Duration::hours(24));
```

### Feature Constraints

Control which features/plugins are accessible:

```rust
// Allow specific features only
let builder = LicenseBuilder::new()
    .allowed_feature("basic")
    .allowed_feature("premium");

// Or add multiple at once
let builder = LicenseBuilder::new()
    .allowed_features(vec!["basic", "premium", "analytics"]);

// Deny specific features (takes precedence over allowed)
let builder = LicenseBuilder::new()
    .allowed_features(vec!["basic", "premium", "admin"])
    .denied_feature("admin");  // Admin explicitly denied
```

**Feature Logic:**
1. If `denied_features` contains the feature → **DENIED**
2. If `allowed_features` is `None` → **ALLOWED** (no restrictions)
3. If `allowed_features` contains the feature → **ALLOWED**
4. Otherwise → **DENIED**

### Connection/Seat Limits

```rust
// Limit concurrent connections or seats
let builder = LicenseBuilder::new()
    .max_connections(50);
```

### Host Restrictions

Restrict which machines can use the license:

```rust
// By hostname
let builder = LicenseBuilder::new()
    .allowed_hostname("prod.example.com")
    .allowed_hostnames(vec!["staging.example.com", "dev.example.com"]);

// By machine identifier (hardware ID, container ID, etc.)
let builder = LicenseBuilder::new()
    .allowed_machine_id("ABC123-DEF456")
    .allowed_machine_ids(vec!["machine-1", "machine-2"]);
```

### Version Constraints

Restrict which software versions can use the license:

```rust
use semver::Version;

// Minimum version required
let builder = LicenseBuilder::new()
    .minimum_version(Version::new(1, 0, 0));

// Maximum version allowed
let builder = LicenseBuilder::new()
    .maximum_version(Version::new(2, 0, 0));

// Version range
let builder = LicenseBuilder::new()
    .minimum_version(Version::new(1, 0, 0))
    .maximum_version(Version::new(2, 0, 0));

// Using string parsing
let builder = LicenseBuilder::new()
    .minimum_version_str("1.0.0")?
    .maximum_version_str("2.0.0")?;
```

### Custom Constraints

Add application-specific constraints:

```rust
use serde_json::json;

let builder = LicenseBuilder::new()
    .custom_constraint("max_storage_gb", json!(100))
    .custom_constraint("max_users", json!(50))
    .custom_constraint("allowed_regions", json!(["US", "EU"]));
```

**Note:** Custom constraints are stored but not automatically validated. Your application must check them manually.

---

## Validating Licenses

### Using the Validator

```rust
use rust_license_key::validator::LicenseValidator;
use rust_license_key::models::ValidationContext;

// Create validator with public key
let validator = LicenseValidator::from_public_key_base64(PUBLIC_KEY)?;

// Or from PublicKey object
let validator = LicenseValidator::new(public_key);

// Validate
let result = validator.validate_json(&license_json, &context)?;
```

### Using Convenience Functions

For simple validation:

```rust
use rust_license_key::validator::{validate_license, is_license_valid, is_feature_allowed};

// Full validation
let result = validate_license(&license_json, PUBLIC_KEY, &context)?;

// Quick validity check
if is_license_valid(&license_json, PUBLIC_KEY) {
    // License is valid
}

// Check specific feature
if is_feature_allowed(&license_json, PUBLIC_KEY, "premium") {
    // Feature is allowed
}
```

### Parsing Without Full Validation

```rust
use rust_license_key::parser::{LicenseParser, parse_license};

// Parse and verify signature only
let parser = LicenseParser::from_public_key_base64(PUBLIC_KEY)?;
let payload = parser.parse_json(&license_json)?;

// Convenience function
let payload = parse_license(&license_json, PUBLIC_KEY)?;
```

### Inspecting Unverified Licenses

For debugging or inspection (NOT for access control):

```rust
use rust_license_key::parser::extract_payload_unverified;

// Get raw payload without signature verification
let payload_json = extract_payload_unverified(&license_json)?;

// Or check if signature is valid without failing
let (payload, is_signature_valid) = parser.decode_unverified(&license_json)?;
```

---

## Validation Context

The `ValidationContext` provides runtime information for constraint checking.

### Building a Context

```rust
use rust_license_key::models::ValidationContext;
use semver::Version;
use chrono::Utc;

let context = ValidationContext::new()
    // Current time (defaults to now if not set)
    .with_time(Utc::now())

    // Current hostname
    .with_hostname("server.example.com")

    // Current machine ID
    .with_machine_id("ABC123")

    // Current software version
    .with_software_version(Version::new(2, 1, 0))

    // Current connection count
    .with_connection_count(25)

    // Features being requested
    .with_feature("premium")
    .with_features(vec!["analytics", "reporting"])

    // Custom values
    .with_custom_value("region", json!("US"));
```

### Context Behavior

| Context Field | Constraint | Behavior |
|--------------|------------|----------|
| `current_time` | `expiration_date`, `valid_from` | Checked if context or constraint is set |
| `current_hostname` | `allowed_hostnames` | Checked only if **both** are set |
| `current_machine_id` | `allowed_machine_ids` | Checked only if **both** are set |
| `current_software_version` | `min_version`, `max_version` | Checked only if **both** are set |
| `current_connection_count` | `max_connections` | Checked only if **both** are set |
| `requested_features` | `allowed_features`, `denied_features` | Each requested feature is checked |

---

## Working with Results

The `ValidationResult` provides comprehensive validation information.

### Checking Validity

```rust
let result = validate_license(&license_json, PUBLIC_KEY, &context)?;

// Basic validity check
if result.is_valid {
    println!("License is valid");
}

// Check if valid AND not expired
if result.is_active() {
    println!("License is active");
}
```

### Accessing License Data

```rust
if result.is_valid {
    let payload = result.payload.as_ref().unwrap();

    println!("License ID: {}", payload.license_id);
    println!("Customer: {}", payload.customer_id);
    println!("Issued: {}", payload.issued_at);

    if let Some(name) = &payload.customer_name {
        println!("Customer Name: {}", name);
    }
}
```

### Time Remaining

```rust
// Get remaining time as Duration
if let Some(duration) = result.time_remaining {
    println!("Time remaining: {} seconds", duration.num_seconds());
}

// Get remaining days (convenience method)
if let Some(days) = result.days_remaining() {
    println!("Days remaining: {}", days);
}

// None means no expiration
if result.days_remaining().is_none() {
    println!("License never expires");
}
```

### Checking Features

```rust
// Check specific feature
if result.is_feature_allowed("premium") {
    // Enable premium features
}

// Get all allowed features
if let Some(features) = &result.allowed_features {
    for feature in features {
        println!("Allowed: {}", feature);
    }
}

// Get denied features
if let Some(denied) = &result.denied_features {
    for feature in denied {
        println!("Denied: {}", feature);
    }
}
```

### Retrieving Custom Values

Access custom key-value pairs stored in the license using typed getters:

```rust
// Get string value
let tier = result.get_string("tier");
if let Some(t) = tier {
    println!("License tier: {}", t);
}

// Get string with default
let tier = result.get_string_or("tier", "basic");

// Get integer value
let max_users = result.get_i64("max_users");
if let Some(limit) = max_users {
    println!("Max users: {}", limit);
}

// Get integer with default
let max_users = result.get_i64_or("max_users", 10);

// Get boolean value
let beta_enabled = result.get_bool_or("beta_features", false);

// Get array value
if let Some(modules) = result.get_string_array("allowed_modules") {
    for module in modules {
        println!("Module: {}", module);
    }
}

// Get object value
if let Some(limits) = result.get_object("limits") {
    if let Some(storage) = limits.get("storage_gb") {
        println!("Storage limit: {} GB", storage);
    }
}

// Check if key exists
if result.has_key("enterprise_features") {
    // Enable enterprise mode
}
```

#### Available Getter Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `get_value(key)` | `Option<&Value>` | Raw JSON value |
| `get_value_or(key, default)` | `&Value` | With default |
| `get_string(key)` | `Option<&str>` | String value |
| `get_string_or(key, default)` | `&str` | With default |
| `get_i64(key)` | `Option<i64>` | Integer value |
| `get_i64_or(key, default)` | `i64` | With default |
| `get_u64(key)` | `Option<u64>` | Unsigned integer |
| `get_u64_or(key, default)` | `u64` | With default |
| `get_f64(key)` | `Option<f64>` | Float value |
| `get_f64_or(key, default)` | `f64` | With default |
| `get_bool(key)` | `Option<bool>` | Boolean value |
| `get_bool_or(key, default)` | `bool` | With default |
| `get_array(key)` | `Option<&Vec<Value>>` | Array value |
| `get_string_array(key)` | `Option<Vec<&str>>` | String array |
| `get_object(key)` | `Option<&Map>` | Object value |
| `has_key(key)` | `bool` | Check existence |

**Note:** These methods are available on both `ValidationResult` and `LicensePayload`.

### Handling Failures

```rust
if !result.is_valid {
    for failure in &result.failures {
        // Failure type for programmatic handling
        match failure.failure_type {
            ValidationFailureType::Expired => {
                println!("License has expired");
            }
            ValidationFailureType::FeatureConstraint => {
                println!("Feature not allowed");
            }
            ValidationFailureType::InvalidSignature => {
                println!("License has been tampered with");
            }
            _ => {
                println!("Validation failed: {}", failure.message);
            }
        }

        // Additional context if available
        if let Some(context) = &failure.context {
            println!("  Details: {}", context);
        }
    }
}
```

---

## Error Handling

All operations return `Result<T, LicenseError>`.

### Error Types

```rust
use rust_license_key::error::LicenseError;

match result {
    Ok(license) => { /* success */ }
    Err(LicenseError::InvalidSignature) => {
        println!("License signature is invalid");
    }
    Err(LicenseError::LicenseExpired { expiration_date }) => {
        println!("License expired on {}", expiration_date);
    }
    Err(LicenseError::UnsupportedLicenseVersion { found, supported }) => {
        println!("Version {} not supported ({})", found, supported);
    }
    Err(LicenseError::InvalidPublicKey { reason }) => {
        println!("Invalid public key: {}", reason);
    }
    Err(e) => {
        println!("Error: {}", e);
    }
}
```

### Common Error Scenarios

| Error | Cause | Solution |
|-------|-------|----------|
| `InvalidSignature` | Wrong key or tampered license | Verify correct public key |
| `InvalidPublicKey` | Malformed key data | Check base64 encoding |
| `UnsupportedLicenseVersion` | Future license format | Update library version |
| `JsonDeserializationFailed` | Corrupted license file | Verify file integrity |
| `BuilderIncomplete` | Missing required fields | Add `license_id` and `customer_id` |

---

**Previous:** [Getting Started](./getting-started.md) | **Next:** [API Reference](./api-reference.md)
