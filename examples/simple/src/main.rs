use rust_license_key::prelude::*;
use chrono::Duration;

fn main() -> Result<(), LicenseError> {
    println!("=== rust-license-key Basic Workflow Demo ===\n");

    // ========================================
    // STEP 1: Generate Key Pair (done once)
    // ========================================
    println!("1. Generating key pair...");
    let key_pair = KeyPair::generate()?;

    let private_key = key_pair.private_key_base64();
    let public_key = key_pair.public_key_base64();

    println!("   Private key: {}...", &private_key[..20]);
    println!("   Public key:  {}...", &public_key[..20]);

    // ========================================
    // STEP 2: Create License (publisher side)
    // ========================================
    println!("\n2. Creating license...");

    let license_json = LicenseBuilder::new()
        .license_id("DEMO-2024-001")
        .customer_id("CUSTOMER-123")
        .customer_name("Demo Customer Inc.")
        .expires_in(Duration::days(30))
        .allowed_features(vec!["basic", "reporting"])
        .max_connections(10)
        .build_and_sign_to_json(&key_pair)?;

    println!("   License created successfully!");
    println!("   License JSON:\n{}", license_json);

    // ========================================
    // STEP 3: Validate License (client side)
    // ========================================
    println!("\n3. Validating license...");

    let context = ValidationContext::new()
        .with_feature("basic")
        .with_connection_count(5);

    let result = validate_license(&license_json, &public_key, &context)?;

    if result.is_valid {
        let payload = result.payload.as_ref().unwrap();
        println!("   License is VALID!");
        println!("   Customer: {}", payload.customer_id);
        println!("   Days remaining: {:?}", result.days_remaining());
        println!("   'basic' feature: {}", result.is_feature_allowed("basic"));
        println!("   'premium' feature: {}", result.is_feature_allowed("premium"));
    } else {
        println!("   License is INVALID:");
        for failure in &result.failures {
            println!("   - {}", failure.message);
        }
    }

    Ok(())
}