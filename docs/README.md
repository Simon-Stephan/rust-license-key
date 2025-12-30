# rust-license-key Documentation

Welcome to the official documentation for **rust-license-key**, a production-grade Rust library for creating and validating offline software licenses using Ed25519 cryptography.

## Table of Contents

### For Users

- [Getting Started](./getting-started.md) - Quick installation and first steps
- [User Guide](./user-guide.md) - Complete guide to using the library
- [Examples](./examples.md) - Practical code examples for common scenarios
- [Security Best Practices](./security.md) - Security considerations and recommendations

### For Developers

- [API Reference](./api-reference.md) - Complete API documentation
- [Architecture](./architecture.md) - Technical architecture and design decisions
- [Contributing](./contributing.md) - How to contribute to the project

## What is rust-license-key?

rust-license-key is a Rust library that enables software publishers to create cryptographically signed licenses that can be verified offline by client applications. It uses Ed25519 digital signatures to ensure that:

- **Only the publisher can create valid licenses** - The private signing key never leaves the publisher's secure environment
- **Licenses cannot be forged or tampered with** - Any modification invalidates the signature
- **Verification requires no network access** - Clients only need the embedded public key
- **License contents are human-readable** - JSON format makes debugging easy

## Key Features

| Feature                 | Description                                           |
|-------------------------|-------------------------------------------------------|
| **Ed25519 Signatures**  | Industry-standard 128-bit security level              |
| **Offline Validation**  | No network calls required for verification            |
| **Rich Constraints**    | Expiration, features, hostnames, versions, and more   |
| **Fluent Builder API**  | Intuitive license creation with method chaining       |
| **Detailed Validation** | Comprehensive error reporting and status information  |
| **Versioned Format**    | Forward-compatible license format                     |
| **No Panics**           | All functions return `Result` for safe error handling |

## Quick Example

**Publisher side** - Creating a license:

```rust
use rust_license_key::prelude::*;
use chrono::Duration;

// Generate a key pair (store securely!)
let key_pair = KeyPair::generate()?;

// Create and sign a license
let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")
    .customer_id("ACME-CORP")
    .expires_in(Duration::days(365))
    .allowed_features(vec!["basic", "premium"])
    .build_and_sign_to_json(&key_pair)?;
```

**Client side** - Validating a license:

```rust
use rust_license_key::prelude::*;

// Public key embedded in your application
const PUBLIC_KEY: &str = "base64-encoded-public-key";

// Validate the license
let result = validate_license(&license_json, PUBLIC_KEY, &ValidationContext::new())?;

if result.is_valid {
    println!("License valid for {} more days", result.days_remaining().unwrap_or(i64::MAX));
}
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-license-key = "0.1"
```

## License

This project is dual-licensed under MIT and Apache 2.0. See the LICENSE files for details.

## Support

- [GitHub Issues](https://github.com/Simon-Stephan/rust-license-key/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/Simon-Stephan/rust-license-key/discussions) - Questions and community support

---

**Next:** [Getting Started](./getting-started.md)
