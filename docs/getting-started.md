# Getting Started

This guide will help you get up and running with rust-license-key in just a few minutes.

## Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

## Installation

Add rust-license-key to your project's `Cargo.toml`:

```toml
[dependencies]
rust-license-key = "0.1"
chrono = "0.4"  # For date/time handling
```

## Understanding the Two-Phase Model

rust-license-key uses an asymmetric cryptographic model with two distinct phases:

```
┌─────────────────────────────────────────────────────────────────┐
│                      PUBLISHER SIDE                              │
│  (Your license generation server/tool)                          │
│                                                                  │
│  ┌──────────────┐    ┌─────────────────┐    ┌────────────────┐  │
│  │  Private Key │ -> │ License Builder │ -> │ Signed License │  │
│  │  (SECRET!)   │    │                 │    │    (JSON)      │  │
│  └──────────────┘    └─────────────────┘    └────────────────┘  │
│                                                      │           │
└──────────────────────────────────────────────────────│───────────┘
                                                       │
                                              (distribute to customer)
                                                       │
                                                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                       CLIENT SIDE                                │
│  (Your distributed application)                                  │
│                                                                  │
│  ┌─────────────┐    ┌───────────────┐    ┌──────────────────┐   │
│  │ Public Key  │ -> │   Validator   │ -> │ ValidationResult │   │
│  │ (embedded)  │    │               │    │                  │   │
│  └─────────────┘    └───────────────┘    └──────────────────┘   │
│                             ▲                                    │
│                             │                                    │
│                    ┌────────────────┐                           │
│                    │ Signed License │                           │
│                    │   (from file)  │                           │
│                    └────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

**Key principle:** The private key NEVER leaves your secure environment. Only the public key is distributed with your application.

## Step 1: Generate a Key Pair

First, generate an Ed25519 key pair. This should be done **once** and stored securely:

```rust
use rust_license_key::prelude::*;

fn main() -> Result<(), LicenseError> {
    // Generate a new key pair
    let key_pair = KeyPair::generate()?;

    // Get the keys as base64 strings
    let private_key = key_pair.private_key_base64();
    let public_key = key_pair.public_key_base64();

    println!("=== PRIVATE KEY (KEEP SECRET!) ===");
    println!("{}", private_key);
    println!();
    println!("=== PUBLIC KEY (embed in your app) ===");
    println!("{}", public_key);

    Ok(())
}
```

**Output example:**
```
=== PRIVATE KEY (KEEP SECRET!) ===
m3K8xQz7vN2pL5yR9tH4wE6jA1cF0gI3kM8nO2qS5uX=

=== PUBLIC KEY (embed in your app) ===
Bp7Y2xK9mN4vL8qR3tH6wE5jA0cF2gI1kM7nO9qS4uX=
```

## Step 2: Create a License (Publisher Side)

Use the `LicenseBuilder` to create and sign licenses:

```rust
use rust_license_key::prelude::*;
use chrono::Duration;

fn create_license(private_key_base64: &str) -> Result<String, LicenseError> {
    // Load the private key
    let key_pair = KeyPair::from_private_key_base64(private_key_base64)?;

    // Build and sign the license
    let license_json = LicenseBuilder::new()
        // Required fields
        .license_id("LIC-2024-001")
        .customer_id("CUSTOMER-123")

        // Optional fields
        .customer_name("Acme Corporation")
        .expires_in(Duration::days(365))
        .allowed_features(vec!["basic", "premium"])
        .max_connections(50)

        // Sign and serialize
        .build_and_sign_to_json(&key_pair)?;

    Ok(license_json)
}
```

**Output example (formatted for readability):**
```json
{
  "payload": "eyJ2IjoxLCJpZCI6IkxJQy0yMDI0LTAwMSIsImN1c3RvbWVyIjoi...",
  "signature": "dGhpcyBpcyBhIHNhbXBsZSBzaWduYXR1cmU..."
}
```

## Step 3: Validate a License (Client Side)

In your client application, validate licenses using only the public key:

```rust
use rust_license_key::prelude::*;

// Embed the public key in your application
const PUBLIC_KEY: &str = "Bp7Y2xK9mN4vL8qR3tH6wE5jA0cF2gI1kM7nO9qS4uX=";

fn validate_customer_license(license_json: &str) -> Result<(), LicenseError> {
    // Create validation context (optional runtime checks)
    let context = ValidationContext::new();

    // Validate the license
    let result = validate_license(license_json, PUBLIC_KEY, &context)?;

    if result.is_valid {
        let payload = result.payload.as_ref().unwrap();
        println!("License valid!");
        println!("Customer: {}", payload.customer_id);
        println!("License ID: {}", payload.license_id);

        if let Some(days) = result.days_remaining() {
            println!("Days remaining: {}", days);
        }
    } else {
        println!("License invalid!");
        for failure in &result.failures {
            println!("  - {}: {}", failure.failure_type, failure.message);
        }
    }

    Ok(())
}
```

## Step 4: Add Runtime Validation (Optional)

For more advanced validation, use the `ValidationContext`:

```rust
use rust_license_key::prelude::*;
use semver::Version;

fn validate_with_context(license_json: &str) -> Result<bool, LicenseError> {
    let context = ValidationContext::new()
        // Check against current hostname
        .with_hostname("production.myapp.com")

        // Check against current software version
        .with_software_version(Version::new(2, 1, 0))

        // Check if specific features are allowed
        .with_feature("premium")
        .with_feature("analytics")

        // Check connection limits
        .with_connection_count(25);

    let result = validate_license(license_json, PUBLIC_KEY, &context)?;

    Ok(result.is_valid)
}
```

## Quick Validation Helpers

For simple checks, use the convenience functions:

```rust
use rust_license_key::prelude::*;

// Quick check if license is valid
if is_license_valid(&license_json, PUBLIC_KEY) {
    println!("License is valid!");
}

// Check if a specific feature is allowed
if is_feature_allowed(&license_json, PUBLIC_KEY, "premium") {
    println!("Premium features enabled!");
}
```

## Complete Example

Here's a complete working example:

```rust
use rust_license_key::prelude::*;
use chrono::Duration;

fn main() -> Result<(), LicenseError> {
    // === PUBLISHER SIDE ===

    // Generate key pair (do this once, store securely)
    let key_pair = KeyPair::generate()?;
    let public_key = key_pair.public_key_base64();

    // Create a license
    let license_json = LicenseBuilder::new()
        .license_id("DEMO-001")
        .customer_id("DEMO-CUSTOMER")
        .expires_in(Duration::days(30))
        .allowed_features(vec!["demo", "trial"])
        .build_and_sign_to_json(&key_pair)?;

    println!("Created license:\n{}\n", license_json);

    // === CLIENT SIDE ===

    // Validate the license
    let context = ValidationContext::new()
        .with_feature("demo");

    let result = validate_license(&license_json, &public_key, &context)?;

    if result.is_valid {
        println!("License is valid!");
        println!("Days remaining: {:?}", result.days_remaining());
        println!("Demo feature allowed: {}", result.is_feature_allowed("demo"));
        println!("Premium feature allowed: {}", result.is_feature_allowed("premium"));
    } else {
        println!("License is invalid:");
        for failure in &result.failures {
            println!("  - {}", failure.message);
        }
    }

    Ok(())
}
```

## Next Steps

- Read the [User Guide](./user-guide.md) for detailed constraint configuration
- See [Examples](./examples.md) for common use cases
- Review [Security Best Practices](./security.md) for production deployment

---

**Previous:** [Documentation Home](./README.md) | **Next:** [User Guide](./user-guide.md)
