# rust-license-key

[![Crates.io](https://img.shields.io/crates/v/rust-license-key.svg)](https://crates.io/crates/rust-license-key)
[![Documentation](https://docs.rs/rust-license-key/badge.svg)](https://docs.rs/rust-license-key)
[![License](https://img.shields.io/crates/l/rust-license-key.svg)](LICENSE)

A production-grade Rust library for creating and validating offline software licenses using Ed25519 cryptography.

## Features

- **Asymmetric Cryptography** - Licenses signed with Ed25519; clients only need the public key
- **Offline Validation** - No network calls required for license verification
- **Rich Constraints** - Expiration, features, hostnames, versions, connection limits, and custom data
- **Tamper-Proof** - Any modification invalidates the cryptographic signature
- **Human-Readable** - JSON-based format for easy debugging
- **Type-Safe** - Strongly typed API with comprehensive error handling
- **No Panics** - All operations return `Result` for safe error handling

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-license-key = "0.1"
chrono = "0.4"
```

## Quick Start

### Generate a Key Pair

```rust
use rust_license_key::prelude::*;

let key_pair = KeyPair::generate()?;

// Store the private key securely (publisher only)
println!("Private: {}", key_pair.private_key_base64());

// Embed the public key in your application
println!("Public: {}", key_pair.public_key_base64());
```

### Create a License (Publisher Side)

```rust
use rust_license_key::prelude::*;
use chrono::Duration;

let key_pair = KeyPair::from_private_key_base64("your-private-key")?;

let license = LicenseBuilder::new()
    .license_id("LIC-2024-001")
    .customer_id("ACME-CORP")
    .customer_name("Acme Corporation")
    .expires_in(Duration::days(365))
    .allowed_features(vec!["basic", "premium", "api"])
    .max_connections(100)
    .build_and_sign_to_json(&key_pair)?;

// Send `license` to your customer
```

### Validate a License (Client Side)

```rust
use rust_license_key::prelude::*;

// Public key embedded in your application
const PUBLIC_KEY: &str = "your-public-key";

let result = validate_license(&license_json, PUBLIC_KEY, &ValidationContext::new())?;

if result.is_valid {
    println!("License valid! Days remaining: {:?}", result.days_remaining());

    if result.is_feature_allowed("premium") {
        println!("Premium features enabled!");
    }
} else {
    for failure in &result.failures {
        println!("Error: {}", failure.message);
    }
}
```

### Quick Validation Helpers

```rust
use rust_license_key::prelude::*;

// Simple validity check
if is_license_valid(&license_json, PUBLIC_KEY) {
    // License is valid
}

// Check specific feature
if is_feature_allowed(&license_json, PUBLIC_KEY, "premium") {
    // Feature is allowed
}
```

## License Constraints

| Constraint | Description |
|------------|-------------|
| `expires_at` / `expires_in` | License expiration date |
| `valid_from` / `valid_after` | Delayed activation date |
| `allowed_features` | Whitelist of permitted features |
| `denied_features` | Blacklist of forbidden features |
| `max_connections` | Maximum concurrent connections/seats |
| `allowed_hostnames` | Permitted server hostnames |
| `allowed_machine_ids` | Permitted machine identifiers |
| `minimum_version` | Minimum software version required |
| `maximum_version` | Maximum software version allowed |
| `custom_constraints` | Application-specific key-value data |

## Validation Context

Validate against runtime environment:

```rust
use rust_license_key::prelude::*;
use semver::Version;

let context = ValidationContext::new()
    .with_hostname("server.example.com")
    .with_machine_id("ABC123")
    .with_software_version(Version::new(2, 1, 0))
    .with_connection_count(50)
    .with_feature("premium");

let result = validate_license(&license_json, PUBLIC_KEY, &context)?;
```

## Security Model

```
┌─────────────────────────────────────┐
│         PUBLISHER (Secure)          │
│  Private Key → Sign → License       │
└──────────────────┬──────────────────┘
                   │ (distribute license)
                   ▼
┌─────────────────────────────────────┐
│         CLIENT (Untrusted)          │
│  Public Key → Verify → Valid/Invalid│
└─────────────────────────────────────┘
```

- **Private key**: Never leaves your secure environment
- **Public key**: Safely embedded in distributed applications
- **Signatures**: Ed25519 with 128-bit security level
- **No encryption**: Payload is readable but tamper-proof

## Documentation

- [Getting Started](./docs/getting-started.md) - Installation and first steps
- [User Guide](./docs/user-guide.md) - Complete usage documentation
- [API Reference](./docs/api-reference.md) - Full API documentation
- [Examples](./docs/examples.md) - Practical code examples
- [Security Guide](./docs/security.md) - Security best practices
- [Architecture](./docs/architecture.md) - Technical design documentation
- [Contributing](./docs/contributing.md) - Contribution guidelines

## Example License Output

```json
{
  "payload": "eyJ2IjoxLCJpZCI6IkxJQy0yMDI0LTAwMSIsImN1c3RvbWVyIjoiQUNNRS...",
  "signature": "dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHNpZ25hdHVyZQ..."
}
```

Decoded payload:
```json
{
  "v": 1,
  "id": "LIC-2024-001",
  "customer": "ACME-CORP",
  "customer_name": "Acme Corporation",
  "issued_at": "2024-01-15T10:30:00Z",
  "constraints": {
    "expires_at": "2025-01-15T10:30:00Z",
    "allowed_features": ["basic", "premium", "api"],
    "max_connections": 100
  }
}
```

## Minimum Rust Version

Rust 1.70 or later.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./docs/contributing.md) before submitting a PR.

## Acknowledgments

Built with:
- [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) - Ed25519 signatures
- [serde](https://serde.rs/) - Serialization framework
- [chrono](https://github.com/chronotope/chrono) - Date and time handling
