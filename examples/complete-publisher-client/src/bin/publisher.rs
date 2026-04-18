use chrono::Duration;
use rust_license_key::prelude::*;
use std::env;
use std::fs;
use std::path::Path;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("==============================================");
    println!(" Publisher License Generation ");
    println!("==============================================");

    // 1. Generate Publisher Keys
    println!("1. Generating new publisher key pair...");
    let key_pair = KeyPair::generate()?;
    
    // Extract base64 public key to share with the client
    let public_key = key_pair.public_key_base64();
    println!("   Public key generated successfully.");

    // 2. Define License Properties
    let args: Vec<String> = env::args().collect();
    // Allow configurable duration via CLI argument, defaulting to 3 seconds for testing
    let valid_seconds: i64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);

    let license_id = "PRO-2026-001";
    let customer_id = "CUST-XYZ-99";
    let customer_name = "Acme Corp Ltd.";

    println!("\n2. Defining license terms:");
    println!("   - License ID: {}", license_id);
    println!("   - Customer: {} ({})", customer_name, customer_id);
    println!("   - Duration: {} seconds", valid_seconds);
    println!("   - Features: 'premium', 'api_access', 'analytics'");
    println!("   - Max Connections: 250");

    // 3. Build and Sign the License
    println!("\n3. Building and cryptographically signing license...");
    let license_json = LicenseBuilder::new()
        .license_id(license_id)
        .customer_id(customer_id)
        .customer_name(customer_name)
        .expires_in(Duration::seconds(valid_seconds))
        // Add specific feature flags the client is allowed to use
        .allowed_features(vec!["premium", "api_access", "analytics"])
        // Set an operational limit
        .max_connections(250)
        // Sign the payload using our Ed25519 key pair
        .build_and_sign_to_json(&key_pair)?;

    // 4. Export Artifacts for the Client
    println!("\n4. Exporting files for the client...");
    
    let public_key_path = Path::new("public_key.txt");
    fs::write(public_key_path, &public_key)?;
    println!("   - Wrote public key to {:?}", public_key_path);

    let license_path = Path::new("license.json");
    fs::write(license_path, &license_json)?;
    println!("   - Wrote signed license to {:?}", license_path);

    println!("\nSuccess! The client can now use `public_key.txt` and `license.json` to validate their access.");
    Ok(())
}
