use rust_license_key::prelude::*;
use std::fs;
use std::path::Path;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("==============================================");
    println!(" Client License Validation ");
    println!("==============================================");

    let public_key_path = Path::new("public_key.txt");
    let license_path = Path::new("license.json");

    // Ensure the publisher has generated the files first
    if !public_key_path.exists() || !license_path.exists() {
        println!("Error: Missing required files.");
        println!("Please run the `publisher` binary first to generate `public_key.txt` and `license.json`.");
        return Ok(());
    }

    // 1. Load Publisher's Public Key
    // In a real application, this public key string would be hardcoded in your
    // compiled binary, ensuring it cannot be easily swapped out by a user.
    println!("1. Loading public key...");
    let public_key = fs::read_to_string(public_key_path)?;

    // 2. Load the Signed License File
    println!("2. Loading signed license from file...");
    let license_json = fs::read_to_string(license_path)?;

    // 3. Define the Runtime Context
    // The context represents the *actual* state of the client application right now.
    // We want to check if the user is allowed to use "premium" and has 100 active connections.
    println!("3. Setting up client runtime context...");
    let context = ValidationContext::new()
        .with_feature("premium")
        .with_connection_count(100);

    // 4. Validate the License
    println!("4. Cryptographically verifying and validating constraints...");
    let result = validate_license(&license_json, &public_key, &context)?;

    println!("\n=== Validation Results ===");
    
    if result.is_valid {
        let payload = result.payload.as_ref().unwrap();
        println!("✅ License is VALID");
        println!("   Customer: {} ({})", payload.customer_name.as_deref().unwrap_or("Unknown"), payload.customer_id);
        
        if let Some(days) = result.days_remaining() {
            println!("   Days remaining: {}", days);
        }

        println!("\n=== Feature Toggles ===");
        
        // Demonstrate checking feature flags to gate application logic
        let premium_allowed = result.is_feature_allowed("premium");
        let enterprise_allowed = result.is_feature_allowed("enterprise");
        let analytics_allowed = result.is_feature_allowed("analytics");

        println!("   Premium features: {}", if premium_allowed { "ENABLED" } else { "DISABLED" });
        println!("   Analytics module: {}", if analytics_allowed { "ENABLED" } else { "DISABLED" });
        println!("   Enterprise suite: {}", if enterprise_allowed { "ENABLED" } else { "DISABLED" });
        
        if premium_allowed {
            println!("\n🚀 Booting application in Premium Mode!");
        } else {
            println!("\n🚶 Booting application in Basic Mode.");
        }
    } else {
        println!("❌ License is INVALID");
        println!("   Validation failures:");
        for failure in &result.failures {
            println!("   - {}", failure.message);
        }
        println!("\n⛔ Application boot aborted due to licensing errors.");
    }

    Ok(())
}
