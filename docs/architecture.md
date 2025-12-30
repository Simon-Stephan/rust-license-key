# Architecture

Technical architecture documentation for developers contributing to or extending rust-license-key.

## Table of Contents

1. [Design Principles](#design-principles)
2. [Module Structure](#module-structure)
3. [Data Flow](#data-flow)
4. [Type System Design](#type-system-design)
5. [Error Handling Strategy](#error-handling-strategy)
6. [Cryptographic Design](#cryptographic-design)
7. [Serialization Format](#serialization-format)
8. [Extension Points](#extension-points)
9. [Testing Strategy](#testing-strategy)

---

## Design Principles

### Core Principles

1. **Security First**: All design decisions prioritize security over convenience
2. **Explicit Over Implicit**: No hidden behavior; all operations are explicit
3. **Fail Safely**: Invalid input produces clear errors, never undefined behavior
4. **No Panics**: All fallible operations return `Result`
5. **Minimal Dependencies**: Only essential, well-audited crates
6. **Pure Functions**: Core logic is side-effect free (no I/O, no network)

### API Design Principles

1. **Hard to Misuse**: The API makes incorrect usage difficult
2. **Separation of Concerns**: Publisher and client code paths are distinct
3. **Builder Pattern**: Complex object construction uses builders
4. **Fluent Interfaces**: Method chaining for ergonomic configuration
5. **Progressive Disclosure**: Simple cases are simple; complex cases are possible

---

## Module Structure

```
src/
├── lib.rs           # Crate root: public API, re-exports, documentation
├── error.rs         # Error types: LicenseError, ValidationFailure
├── models.rs        # Data structures: payloads, constraints, results
├── crypto.rs        # Cryptography: key generation, signing, verification
├── builder.rs       # License creation: LicenseBuilder
├── parser.rs        # License loading: LicenseParser
└── validator.rs     # Validation logic: LicenseValidator
```

### Module Dependency Graph

```
                    ┌─────────────┐
                    │   lib.rs    │
                    │ (re-exports)│
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  builder.rs   │  │  parser.rs    │  │ validator.rs  │
│ (creation)    │  │ (loading)     │  │ (checking)    │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                           ▼
                   ┌───────────────┐
                   │  crypto.rs    │
                   │ (Ed25519)     │
                   └───────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  models.rs    │  │  error.rs     │  │ (external)    │
│ (data types)  │  │ (errors)      │  │ ed25519-dalek │
└───────────────┘  └───────────────┘  └───────────────┘
```

### Module Responsibilities

| Module | Responsibility | Publisher | Client |
|--------|---------------|-----------|--------|
| `crypto` | Key management, signing, verification | ✓ | ✓ |
| `builder` | License construction and signing | ✓ | - |
| `parser` | License loading and signature verification | - | ✓ |
| `validator` | Constraint checking | - | ✓ |
| `models` | Shared data structures | ✓ | ✓ |
| `error` | Error definitions | ✓ | ✓ |

---

## Data Flow

### License Creation Flow (Publisher)

```
                    User Input
                        │
                        ▼
              ┌─────────────────┐
              │ LicenseBuilder  │
              │                 │
              │ • license_id()  │
              │ • customer_id() │
              │ • expires_in()  │
              │ • ...           │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ build_payload() │
              │                 │
              │ Validates       │
              │ required fields │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ LicensePayload  │
              │                 │
              │ • format_version│
              │ • license_id    │
              │ • constraints   │
              │ • ...           │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ JSON serialize  │
              │ (serde_json)    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Base64 encode   │
              │ (base64)        │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Ed25519 sign    │
              │ (ed25519-dalek) │
              │                 │
              │ Signs base64    │
              │ payload         │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ SignedLicense   │
              │                 │
              │ • payload (b64) │
              │ • signature(b64)│
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ JSON output     │
              └─────────────────┘
```

### License Validation Flow (Client)

```
              License JSON File
                       │
                       ▼
              ┌─────────────────┐
              │ JSON parse      │
              │                 │
              │ → SignedLicense │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Verify Signature│
              │                 │
              │ public_key      │
              │   .verify()     │
              └────────┬────────┘
                       │
               ┌───────┴───────┐
               │               │
          INVALID           VALID
               │               │
               ▼               ▼
        ┌──────────┐   ┌─────────────────┐
        │ Return   │   │ Base64 decode   │
        │ failure  │   │ payload         │
        └──────────┘   └────────┬────────┘
                               │
                               ▼
                       ┌─────────────────┐
                       │ JSON parse      │
                       │                 │
                       │ → LicensePayload│
                       └────────┬────────┘
                               │
                               ▼
                       ┌─────────────────┐
                       │ Check version   │
                       │ compatibility   │
                       └────────┬────────┘
                               │
                               ▼
                       ┌─────────────────┐
                       │ Validate        │
                       │ constraints     │
                       │                 │
                       │ • expiration    │
                       │ • valid_from    │
                       │ • features      │
                       │ • hostname      │
                       │ • version       │
                       │ • connections   │
                       └────────┬────────┘
                               │
                               ▼
                       ┌─────────────────┐
                       │ ValidationResult│
                       │                 │
                       │ • is_valid      │
                       │ • failures[]    │
                       │ • payload       │
                       └─────────────────┘
```

---

## Type System Design

### Ownership and Lifetimes

The library uses owned types throughout the public API for simplicity:

```rust
// Owned strings in payload
pub struct LicensePayload {
    pub license_id: String,      // Owned
    pub customer_id: String,     // Owned
    // ...
}

// Builder consumes self for method chaining
impl LicenseBuilder {
    pub fn license_id(mut self, id: impl Into<String>) -> Self {
        self.license_id = Some(id.into());
        self
    }
}
```

### Generic Bounds

Flexible input types with `Into<String>`:

```rust
// Accepts &str, String, Cow<str>, etc.
pub fn license_id(self, id: impl Into<String>) -> Self

// Accepts any iterator of string-like items
pub fn allowed_features(self, features: impl IntoIterator<Item = impl Into<String>>) -> Self
```

### Optional vs Required Fields

```rust
// Required at build time (validated in build_payload)
license_id: Option<String>,    // Must be set
customer_id: Option<String>,   // Must be set

// Optional constraints (None means no restriction)
pub struct LicenseConstraints {
    pub expiration_date: Option<DateTime<Utc>>,
    pub allowed_features: Option<HashSet<String>>,
    // ...
}
```

### Newtype Patterns

Keys are wrapped in newtypes for type safety:

```rust
pub struct KeyPair {
    signing_key: SigningKey,  // Private, wrapped
}

pub struct PublicKey {
    verifying_key: VerifyingKey,  // Private, wrapped
}
```

---

## Error Handling Strategy

### Error Type Hierarchy

```rust
// Main error type with structured variants
pub enum LicenseError {
    // Cryptographic errors
    KeyGenerationFailed { reason: String },
    InvalidPrivateKey { reason: String },
    InvalidSignature,

    // Encoding errors
    Base64DecodingFailed { reason: String },
    JsonDeserializationFailed { reason: String },

    // Validation errors
    LicenseExpired { expiration_date: String },
    FeatureNotAllowed { feature: String },
    // ...
}

// Validation failures (not errors, but expected outcomes)
pub struct ValidationFailure {
    pub failure_type: ValidationFailureType,
    pub message: String,
    pub context: Option<String>,
}
```

### Error vs Failure

| Concept | Type | Meaning |
|---------|------|---------|
| Error | `LicenseError` | Unexpected condition, operation cannot proceed |
| Failure | `ValidationFailure` | Expected condition, license is invalid |

```rust
// Error: Cannot proceed
fn parse_json(&self, json: &str) -> Result<LicensePayload, LicenseError>

// Success with failures: Operation succeeded, license is invalid
fn validate_json(&self, json: &str, ctx: &ValidationContext) -> Result<ValidationResult, LicenseError>
```

### Error Context

Errors include context for debugging:

```rust
LicenseError::InvalidPublicKey {
    reason: format!("invalid key length: expected {} bytes, got {}",
                    PUBLIC_KEY_LENGTH, bytes.len())
}
```

---

## Cryptographic Design

### Algorithm Choice: Ed25519

| Property | Value | Rationale |
|----------|-------|-----------|
| Algorithm | Ed25519 | Fast, secure, widely audited |
| Library | ed25519-dalek | Pure Rust, well-maintained |
| Key Size | 32 bytes | Compact, easy to embed |
| Signature Size | 64 bytes | Compact |
| Security Level | 128-bit | Sufficient for licensing |

### Signing Process

```rust
// What gets signed
let payload_json = serde_json::to_string(&payload)?;
let encoded_payload = base64::encode(&payload_json);

// Signature is over the base64-encoded payload
// This ensures consistency across JSON formatting variations
let signature = signing_key.sign(encoded_payload.as_bytes());
```

### Verification Process

```rust
// Reconstruct what was signed
let encoded_payload = &signed_license.encoded_payload;

// Verify signature
verifying_key.verify(
    encoded_payload.as_bytes(),
    &signature
)?;
```

### Key Derivation

```rust
// Public key is deterministically derived from private key
let signing_key = SigningKey::from_bytes(&private_key_bytes);
let verifying_key = signing_key.verifying_key();
```

---

## Serialization Format

### License JSON Structure

```json
{
  "payload": "<base64-encoded-json>",
  "signature": "<base64-encoded-signature>"
}
```

### Payload JSON Structure

```json
{
  "v": 1,
  "id": "LIC-2024-001",
  "customer": "CUST-123",
  "customer_name": "Acme Corp",
  "issued_at": "2024-01-15T10:30:00Z",
  "constraints": {
    "expires_at": "2025-01-15T10:30:00Z",
    "allowed_features": ["basic", "premium"],
    "max_connections": 100
  },
  "metadata": {
    "custom_key": "custom_value"
  }
}
```

### Field Naming Convention

Compact JSON field names for smaller licenses:

```rust
#[serde(rename = "v")]
pub format_version: u32,

#[serde(rename = "id")]
pub license_id: String,

#[serde(rename = "expires_at", skip_serializing_if = "Option::is_none")]
pub expiration_date: Option<DateTime<Utc>>,
```

### Version Compatibility

```rust
pub const LICENSE_FORMAT_VERSION: u32 = 1;
pub const MIN_SUPPORTED_LICENSE_VERSION: u32 = 1;
pub const MAX_SUPPORTED_LICENSE_VERSION: u32 = 1;
```

Future versions will increment `LICENSE_FORMAT_VERSION` and extend the supported range.

---

## Extension Points

### Custom Constraints

Users can add application-specific constraints:

```rust
// In license
.custom_constraint("max_storage_gb", json!(100))

// In validation
let storage_limit = payload.constraints.custom_constraints
    .as_ref()
    .and_then(|c| c.get("max_storage_gb"))
    .and_then(|v| v.as_u64());
```

### Custom Validation

Applications can extend validation:

```rust
fn validate_with_custom_checks(
    license_json: &str,
    public_key: &str,
) -> Result<ValidationResult, LicenseError> {
    let mut result = validate_license(license_json, public_key, &ValidationContext::new())?;

    // Add custom validation
    if let Some(payload) = &result.payload {
        if let Some(custom) = &payload.constraints.custom_constraints {
            if let Some(region) = custom.get("region") {
                if region != "US" {
                    result.add_failure(ValidationFailure::new(
                        ValidationFailureType::CustomConstraint,
                        "Region not supported",
                    ));
                }
            }
        }
    }

    Ok(result)
}
```

### Custom Metadata

Metadata is stored but not validated:

```rust
// Store anything in metadata
.metadata("internal_id", json!("INT-123"))
.metadata("signed_by", json!("sales@company.com"))
.metadata("contract", json!({
    "id": "CNT-2024",
    "terms": "annual"
}))
```

---

## Testing Strategy

### Test Organization

```
src/
├── *.rs              # Unit tests in each module (#[cfg(test)] mod tests)
tests/
└── integration_tests.rs   # Integration tests
```

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit Tests | `src/*.rs` | Test individual functions/methods |
| Integration Tests | `tests/` | Test complete workflows |
| Doc Tests | Rustdoc comments | Verify documentation examples |

### Test Patterns

```rust
// Unit test pattern
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key_pair() -> KeyPair {
        KeyPair::generate().expect("Key generation should succeed")
    }

    #[test]
    fn test_feature_name() {
        // Arrange
        let key_pair = create_test_key_pair();

        // Act
        let result = some_operation(&key_pair);

        // Assert
        assert!(result.is_ok());
    }
}
```

### Test Coverage Goals

| Area | Target Coverage |
|------|-----------------|
| Crypto operations | 100% of public API |
| Builder methods | All constraint types |
| Parser | Valid, invalid, and edge cases |
| Validator | All constraint types and combinations |
| Error paths | All error variants |

### Property-Based Testing (Future)

```rust
// Consider adding proptest for property-based tests
#[test]
fn prop_sign_verify_roundtrip(data: Vec<u8>) {
    let key_pair = KeyPair::generate().unwrap();
    let signature = key_pair.sign(&data);
    assert!(key_pair.public_key().verify(&data, &signature).is_ok());
}
```

---

**Previous:** [Examples](./examples.md) | **Next:** [Contributing](./contributing.md)
