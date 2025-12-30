//! Comprehensive integration tests for the rust-license-key library.
//!
//! These tests cover realistic usage scenarios including:
//! - Valid license creation and validation
//! - Expired licenses
//! - Tampered or corrupted licenses
//! - Invalid signatures
//! - Unsupported license versions
//! - Feature restrictions
//! - Hostname mismatches
//! - Version mismatches
//! - Connection limits
//! - Multiple constraint violations

use chrono::{Duration, Utc};
use rust_license_key::prelude::*;
use semver::Version;

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates a fresh key pair for testing.
fn create_key_pair() -> KeyPair {
    KeyPair::generate().expect("Key generation should succeed")
}

/// Creates a basic valid license with sensible defaults.
fn create_basic_license(key_pair: &KeyPair) -> String {
    LicenseBuilder::new()
        .license_id("TEST-LICENSE-001")
        .customer_id("TEST-CUSTOMER")
        .customer_name("Test Customer Inc.")
        .expires_in(Duration::days(365))
        .build_and_sign_to_json(key_pair)
        .expect("License creation should succeed")
}

// =============================================================================
// Valid License Tests
// =============================================================================

#[test]
fn test_valid_license_basic() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(result.is_valid);
    assert!(result.is_active());
    assert!(result.failures.is_empty());

    let payload = result.payload.expect("Should have payload");
    assert_eq!(payload.license_id, "TEST-LICENSE-001");
    assert_eq!(payload.customer_id, "TEST-CUSTOMER");
}

#[test]
fn test_valid_license_with_all_constraints() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("FULL-FEATURED-001")
        .customer_id("ENTERPRISE-CUSTOMER")
        .customer_name("Enterprise Corp")
        .issued_at(Utc::now())
        .expires_in(Duration::days(30))
        .valid_from(Utc::now() - Duration::hours(1)) // Valid from 1 hour ago
        .allowed_features(vec!["basic", "premium", "analytics", "reporting"])
        .denied_feature("beta")
        .max_connections(100)
        .allowed_hostnames(vec!["prod.example.com", "staging.example.com"])
        .allowed_machine_ids(vec!["machine-001", "machine-002"])
        .minimum_version(Version::new(1, 0, 0))
        .maximum_version(Version::new(3, 0, 0))
        .custom_constraint("max_storage_gb", serde_json::json!(500))
        .metadata("contract_number", serde_json::json!("CNT-2024-001"))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new()
        .with_hostname("prod.example.com")
        .with_machine_id("machine-001")
        .with_software_version(Version::new(2, 5, 0))
        .with_connection_count(50)
        .with_feature("premium")
        .with_feature("analytics");

    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
    assert!(result.is_active());

    // Verify feature access
    assert!(result.is_feature_allowed("basic"));
    assert!(result.is_feature_allowed("premium"));
    assert!(!result.is_feature_allowed("beta")); // Denied
    assert!(!result.is_feature_allowed("unknown")); // Not in allowed list
}

#[test]
fn test_license_without_expiration() {
    let key_pair = create_key_pair();

    // License with no expiration date (perpetual)
    let license_json = LicenseBuilder::new()
        .license_id("PERPETUAL-001")
        .customer_id("LIFETIME-CUSTOMER")
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(result.is_valid);
    assert!(result.days_remaining().is_none()); // No expiration
}

// =============================================================================
// Expired License Tests
// =============================================================================

#[test]
fn test_expired_license() {
    let key_pair = create_key_pair();

    // License that expired yesterday
    let license_json = LicenseBuilder::new()
        .license_id("EXPIRED-001")
        .customer_id("EXPIRED-CUSTOMER")
        .expires_at(Utc::now() - Duration::days(1))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::Expired
    );
}

#[test]
fn test_license_expired_one_minute_ago() {
    let key_pair = create_key_pair();

    // License that expired just one minute ago
    let license_json = LicenseBuilder::new()
        .license_id("JUST-EXPIRED-001")
        .customer_id("JUST-EXPIRED-CUSTOMER")
        .expires_at(Utc::now() - Duration::minutes(1))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::Expired
    );
}

#[test]
fn test_license_not_yet_valid() {
    let key_pair = create_key_pair();

    // License that becomes valid in 7 days
    let license_json = LicenseBuilder::new()
        .license_id("FUTURE-001")
        .customer_id("FUTURE-CUSTOMER")
        .valid_from(Utc::now() + Duration::days(7))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::NotYetValid
    );
}

// =============================================================================
// Signature and Tampering Tests
// =============================================================================

#[test]
fn test_invalid_signature_wrong_key() {
    let key_pair_1 = create_key_pair();
    let key_pair_2 = create_key_pair();

    // Create license with key_pair_1
    let license_json = create_basic_license(&key_pair_1);

    // Validate with key_pair_2's public key
    let result = validate_license(
        &license_json,
        &key_pair_2.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::InvalidSignature
    );
}

#[test]
fn test_tampered_payload() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    // Parse and tamper with the payload
    let mut signed: SignedLicense = serde_json::from_str(&license_json).unwrap();

    // Modify the encoded payload (simulating tampering)
    let mut chars: Vec<char> = signed.encoded_payload.chars().collect();
    if chars.len() > 20 {
        chars[20] = if chars[20] == 'X' { 'Y' } else { 'X' };
    }
    signed.encoded_payload = chars.into_iter().collect();

    let tampered_json = serde_json::to_string(&signed).unwrap();

    let result = validate_license(
        &tampered_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
}

#[test]
fn test_tampered_signature() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    // Parse and tamper with the signature
    let mut signed: SignedLicense = serde_json::from_str(&license_json).unwrap();

    // Modify the signature (simulating tampering)
    let mut chars: Vec<char> = signed.encoded_signature.chars().collect();
    if chars.len() > 10 {
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    }
    signed.encoded_signature = chars.into_iter().collect();

    let tampered_json = serde_json::to_string(&signed).unwrap();

    let result = validate_license(
        &tampered_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
}

#[test]
fn test_corrupted_json() {
    let key_pair = create_key_pair();

    let result = validate_license(
        "{ invalid json }",
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    );

    assert!(result.is_err());
}

#[test]
fn test_empty_license() {
    let key_pair = create_key_pair();

    let result = validate_license("", &key_pair.public_key_base64(), &ValidationContext::new());

    assert!(result.is_err());
}

// =============================================================================
// Feature Constraint Tests
// =============================================================================

#[test]
fn test_feature_allowed() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("FEATURE-001")
        .customer_id("FEATURE-CUSTOMER")
        .allowed_features(vec!["basic", "premium"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Request allowed feature
    let context = ValidationContext::new().with_feature("premium");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_feature_not_in_allowed_list() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("FEATURE-002")
        .customer_id("FEATURE-CUSTOMER")
        .allowed_features(vec!["basic"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Request feature not in allowed list
    let context = ValidationContext::new().with_feature("enterprise");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::FeatureConstraint
    );
}

#[test]
fn test_feature_explicitly_denied() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("FEATURE-003")
        .customer_id("FEATURE-CUSTOMER")
        .allowed_features(vec!["basic", "premium", "admin"])
        .denied_feature("admin") // Denied takes precedence
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Request denied feature
    let context = ValidationContext::new().with_feature("admin");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::FeatureConstraint
    );
}

#[test]
fn test_multiple_features_some_denied() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("FEATURE-004")
        .customer_id("FEATURE-CUSTOMER")
        .allowed_features(vec!["basic", "premium"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Request multiple features, some allowed, some not
    let context = ValidationContext::new()
        .with_feature("basic")
        .with_feature("premium")
        .with_feature("enterprise"); // Not allowed

    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(result.failures.len(), 1); // Only enterprise fails
}

// =============================================================================
// Hostname Constraint Tests
// =============================================================================

#[test]
fn test_hostname_allowed() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("HOST-001")
        .customer_id("HOST-CUSTOMER")
        .allowed_hostnames(vec!["server1.example.com", "server2.example.com"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_hostname("server1.example.com");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_hostname_not_allowed() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("HOST-002")
        .customer_id("HOST-CUSTOMER")
        .allowed_hostnames(vec!["server1.example.com"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_hostname("unauthorized.example.com");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::HostnameConstraint
    );
}

#[test]
fn test_no_hostname_constraint_allows_all() {
    let key_pair = create_key_pair();

    // License without hostname restrictions
    let license_json = LicenseBuilder::new()
        .license_id("HOST-003")
        .customer_id("HOST-CUSTOMER")
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_hostname("any-hostname.example.com");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

// =============================================================================
// Machine ID Constraint Tests
// =============================================================================

#[test]
fn test_machine_id_allowed() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("MACHINE-001")
        .customer_id("MACHINE-CUSTOMER")
        .allowed_machine_ids(vec!["ABC123", "DEF456"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_machine_id("ABC123");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_machine_id_not_allowed() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("MACHINE-002")
        .customer_id("MACHINE-CUSTOMER")
        .allowed_machine_ids(vec!["ABC123"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_machine_id("UNAUTHORIZED");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::MachineIdConstraint
    );
}

// =============================================================================
// Version Constraint Tests
// =============================================================================

#[test]
fn test_version_within_range() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("VERSION-001")
        .customer_id("VERSION-CUSTOMER")
        .minimum_version(Version::new(1, 0, 0))
        .maximum_version(Version::new(2, 0, 0))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_software_version(Version::new(1, 5, 3));
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_version_below_minimum() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("VERSION-002")
        .customer_id("VERSION-CUSTOMER")
        .minimum_version(Version::new(2, 0, 0))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_software_version(Version::new(1, 9, 9));
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::VersionConstraint
    );
}

#[test]
fn test_version_above_maximum() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("VERSION-003")
        .customer_id("VERSION-CUSTOMER")
        .maximum_version(Version::new(1, 9, 9))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_software_version(Version::new(2, 0, 0));
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::VersionConstraint
    );
}

#[test]
fn test_version_at_exact_boundary() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("VERSION-004")
        .customer_id("VERSION-CUSTOMER")
        .minimum_version(Version::new(1, 0, 0))
        .maximum_version(Version::new(2, 0, 0))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Test at minimum boundary
    let context = ValidationContext::new().with_software_version(Version::new(1, 0, 0));
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");
    assert!(result.is_valid);

    // Test at maximum boundary
    let context = ValidationContext::new().with_software_version(Version::new(2, 0, 0));
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");
    assert!(result.is_valid);
}

// =============================================================================
// Connection Limit Tests
// =============================================================================

#[test]
fn test_connection_count_under_limit() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("CONN-001")
        .customer_id("CONN-CUSTOMER")
        .max_connections(10)
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_connection_count(5);
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_connection_count_at_limit() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("CONN-002")
        .customer_id("CONN-CUSTOMER")
        .max_connections(10)
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // When we have 10 connections and try to add another
    let context = ValidationContext::new().with_connection_count(10);
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::ConnectionLimit
    );
}

#[test]
fn test_connection_count_over_limit() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("CONN-003")
        .customer_id("CONN-CUSTOMER")
        .max_connections(10)
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_connection_count(15);
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
}

// =============================================================================
// Multiple Constraint Violation Tests
// =============================================================================

#[test]
fn test_multiple_failures() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("MULTI-001")
        .customer_id("MULTI-CUSTOMER")
        .expires_at(Utc::now() - Duration::days(1)) // Expired
        .allowed_hostnames(vec!["allowed.example.com"])
        .allowed_features(vec!["basic"])
        .max_connections(5)
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new()
        .with_hostname("unauthorized.example.com") // Wrong hostname
        .with_feature("premium") // Wrong feature
        .with_connection_count(10); // Over limit

    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    // Should have multiple failures: expired, hostname, feature, connections
    assert!(result.failures.len() >= 4);
}

// =============================================================================
// Convenience Function Tests
// =============================================================================

#[test]
fn test_is_license_valid() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    assert!(is_license_valid(
        &license_json,
        &key_pair.public_key_base64()
    ));
}

#[test]
fn test_is_license_valid_with_expired() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("EXPIRED-CONV")
        .customer_id("EXPIRED-CUSTOMER")
        .expires_at(Utc::now() - Duration::days(1))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    assert!(!is_license_valid(
        &license_json,
        &key_pair.public_key_base64()
    ));
}

#[test]
fn test_is_feature_allowed_function() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("FEATURE-CONV")
        .customer_id("FEATURE-CUSTOMER")
        .allowed_features(vec!["premium", "analytics"])
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    assert!(is_feature_allowed(
        &license_json,
        &key_pair.public_key_base64(),
        "premium"
    ));
    assert!(is_feature_allowed(
        &license_json,
        &key_pair.public_key_base64(),
        "analytics"
    ));
    assert!(!is_feature_allowed(
        &license_json,
        &key_pair.public_key_base64(),
        "enterprise"
    ));
}

#[test]
fn test_parse_license_function() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    let payload =
        parse_license(&license_json, &key_pair.public_key_base64()).expect("Should parse license");

    assert_eq!(payload.license_id, "TEST-LICENSE-001");
    assert_eq!(payload.customer_id, "TEST-CUSTOMER");
}

// =============================================================================
// Key Pair Persistence Tests
// =============================================================================

#[test]
fn test_key_pair_export_import() {
    // Generate original key pair
    let original = create_key_pair();
    let private_key_base64 = original.private_key_base64();
    let public_key_base64 = original.public_key_base64();

    // Create license with original key pair
    let license_json = create_basic_license(&original);

    // Restore key pair from exported keys
    let restored =
        KeyPair::from_private_key_base64(&private_key_base64).expect("Should restore key pair");

    // Verify the public key matches
    assert_eq!(restored.public_key_base64(), public_key_base64);

    // Verify the restored key pair can validate the license
    let result = validate_license(
        &license_json,
        &restored.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_public_key_only_validation() {
    let key_pair = create_key_pair();
    let public_key_base64 = key_pair.public_key_base64();
    let license_json = create_basic_license(&key_pair);

    // Create validator from public key only
    let public_key = PublicKey::from_base64(&public_key_base64).expect("Should create public key");
    let validator = LicenseValidator::new(public_key);

    let result = validator
        .validate_json(&license_json, &ValidationContext::new())
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

// =============================================================================
// Custom Time Validation Tests
// =============================================================================

#[test]
fn test_validation_with_custom_time_in_future() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("TIME-001")
        .customer_id("TIME-CUSTOMER")
        .expires_in(Duration::days(30))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Validate at a time 60 days in the future
    let future_time = Utc::now() + Duration::days(60);
    let context = ValidationContext::new().with_time(future_time);

    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::Expired
    );
}

#[test]
fn test_validation_with_custom_time_before_valid() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("TIME-002")
        .customer_id("TIME-CUSTOMER")
        .valid_from(Utc::now() + Duration::days(7))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Validate at current time (before valid_from)
    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(!result.is_valid);
    assert_eq!(
        result.failures[0].failure_type,
        ValidationFailureType::NotYetValid
    );

    // Validate at a time after valid_from
    let future_time = Utc::now() + Duration::days(10);
    let context = ValidationContext::new().with_time(future_time);

    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

// =============================================================================
// Parser Tests
// =============================================================================

#[test]
fn test_parser_unverified_decode() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    let parser = LicenseParser::new(key_pair.public_key());
    let (payload, signature_valid) = parser
        .decode_unverified(&license_json)
        .expect("Should decode");

    assert!(signature_valid);
    assert_eq!(payload.license_id, "TEST-LICENSE-001");
}

#[test]
fn test_parser_unverified_with_wrong_key() {
    let key_pair_1 = create_key_pair();
    let key_pair_2 = create_key_pair();

    let license_json = create_basic_license(&key_pair_1);

    let parser = LicenseParser::new(key_pair_2.public_key());
    let (payload, signature_valid) = parser
        .decode_unverified(&license_json)
        .expect("Should decode");

    // Signature should be invalid but payload still readable
    assert!(!signature_valid);
    assert_eq!(payload.license_id, "TEST-LICENSE-001");
}

// =============================================================================
// Validation Result Tests
// =============================================================================

#[test]
fn test_validation_result_days_remaining() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("DAYS-001")
        .customer_id("DAYS-CUSTOMER")
        .expires_in(Duration::days(100))
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    let days = result.days_remaining().expect("Should have days remaining");
    assert!(days >= 99 && days <= 100);
}

#[test]
fn test_validation_result_is_active() {
    let key_pair = create_key_pair();
    let license_json = create_basic_license(&key_pair);

    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    assert!(result.is_valid);
    assert!(result.is_active());
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_empty_allowed_features_means_none_allowed() {
    let key_pair = create_key_pair();

    // Empty allowed features set means no features are allowed
    let license_json = LicenseBuilder::new()
        .license_id("EDGE-001")
        .customer_id("EDGE-CUSTOMER")
        .allowed_features(Vec::<String>::new())
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new().with_feature("any");
    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(!result.is_valid);
}

#[test]
fn test_no_features_constraint_allows_all() {
    let key_pair = create_key_pair();

    // No feature constraints means all features allowed
    let license_json = LicenseBuilder::new()
        .license_id("EDGE-002")
        .customer_id("EDGE-CUSTOMER")
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    let context = ValidationContext::new()
        .with_feature("any")
        .with_feature("feature")
        .with_feature("allowed");

    let result = validate_license(&license_json, &key_pair.public_key_base64(), &context)
        .expect("Validation should succeed");

    assert!(result.is_valid);
}

#[test]
fn test_no_context_validation() {
    let key_pair = create_key_pair();

    let license_json = LicenseBuilder::new()
        .license_id("EDGE-003")
        .customer_id("EDGE-CUSTOMER")
        .allowed_hostnames(vec!["restricted.example.com"])
        .max_connections(5)
        .build_and_sign_to_json(&key_pair)
        .expect("License creation should succeed");

    // Validate with empty context - constraints not checked if context doesn't provide values
    let result = validate_license(
        &license_json,
        &key_pair.public_key_base64(),
        &ValidationContext::new(),
    )
    .expect("Validation should succeed");

    // Should be valid because context doesn't specify hostname or connection count
    assert!(result.is_valid);
}
