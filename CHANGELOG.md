# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-12-30

### Added

- Initial release of rust-license-key
- **Cryptography**: Ed25519 key pair generation, signing, and verification
  - `KeyPair` for managing private/public key pairs
  - `PublicKey` for client-side verification
  - Base64 encoding/decoding support
- **License Builder**: Fluent API for creating licenses
  - Required fields: `license_id`, `customer_id`
  - Optional: `customer_name`, `issued_at`
  - Temporal constraints: `expires_at`, `expires_in`, `valid_from`, `valid_after`
  - Feature constraints: `allowed_feature(s)`, `denied_feature(s)`
  - Host constraints: `allowed_hostname(s)`, `allowed_machine_id(s)`
  - Version constraints: `minimum_version`, `maximum_version`
  - Connection limits: `max_connections`
  - Custom data: `add_key_value`, `add_string`, `add_i64`, `add_bool`, `add_string_array`
  - Metadata: `metadata`, `custom_constraint`
- **License Parser**: Parse and verify signed licenses
  - Signature verification with Ed25519
  - JSON deserialization
  - Unverified payload extraction for debugging
- **License Validator**: Full constraint validation
  - Temporal validation (expiration, activation date)
  - Feature validation (allowed/denied lists)
  - Host validation (hostname, machine ID)
  - Version validation (min/max software version)
  - Connection limit validation
  - Custom time override for testing
- **Validation Result**: Comprehensive validation outcomes
  - Success/failure status
  - Detailed failure messages with types
  - Time remaining calculation
  - Feature access checking
  - Custom value getters: `get_string`, `get_i64`, `get_bool`, `get_array`, etc.
- **Error Handling**: Rich error types with context
  - `LicenseError` enum for all error cases
  - `ValidationFailure` for validation-specific failures
  - No panics in library code
- **Documentation**
  - Complete rustdoc documentation
  - User guide
  - API reference
  - Security best practices
  - Architecture documentation
  - Code examples

### Security

- Ed25519 signatures (128-bit security level)
- Asymmetric cryptography (public key safe to distribute)
- No encryption (payload is readable but tamper-proof)
- Constant-time signature verification

[Unreleased]: https://github.com/Simon-Stephan/rust-license-key/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Simon-Stephan/rust-license-key/releases/tag/v0.1.0
