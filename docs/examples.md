# Examples

Practical code examples for common licensing scenarios.

## Table of Contents

1. [Basic License Workflow](#basic-license-workflow)
2. [License Generation Tool](#license-generation-tool)
3. [Client Application Integration](#client-application-integration)
4. [Feature-Gated Application](#feature-gated-application)
5. [SaaS Multi-Tenant Licensing](#saas-multi-tenant-licensing)
6. [Trial License System](#trial-license-system)
7. [Version-Locked Licensing](#version-locked-licensing)
8. [Machine-Bound Licensing](#machine-bound-licensing)

---

## Basic License Workflow

Complete end-to-end example showing license creation and validation.

```rust
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
```

---

## License Generation Tool

A command-line tool for generating licenses.

```rust
use rust_license_key::prelude::*;
use chrono::Duration;
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("generate-keys") => generate_keys()?,
        Some("create-license") => create_license(&args[2..])?,
        Some("verify") => verify_license(&args[2..])?,
        _ => print_usage(),
    }

    Ok(())
}

fn print_usage() {
    println!("License Tool Usage:");
    println!("  generate-keys              Generate new key pair");
    println!("  create-license <options>   Create a license");
    println!("  verify <license-file>      Verify a license");
    println!();
    println!("create-license options:");
    println!("  --id <license-id>");
    println!("  --customer <customer-id>");
    println!("  --days <expiration-days>");
    println!("  --features <feature1,feature2,...>");
    println!("  --key <private-key-file>");
    println!("  --output <output-file>");
}

fn generate_keys() -> Result<(), LicenseError> {
    let key_pair = KeyPair::generate()?;

    println!("=== New Key Pair Generated ===");
    println!();
    println!("PRIVATE KEY (keep secret!):");
    println!("{}", key_pair.private_key_base64());
    println!();
    println!("PUBLIC KEY (embed in application):");
    println!("{}", key_pair.public_key_base64());

    Ok(())
}

fn create_license(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut license_id = String::new();
    let mut customer_id = String::new();
    let mut days = 365i64;
    let mut features = Vec::new();
    let mut key_file = String::new();
    let mut output_file = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" => { license_id = args[i + 1].clone(); i += 2; }
            "--customer" => { customer_id = args[i + 1].clone(); i += 2; }
            "--days" => { days = args[i + 1].parse()?; i += 2; }
            "--features" => {
                features = args[i + 1].split(',').map(String::from).collect();
                i += 2;
            }
            "--key" => { key_file = args[i + 1].clone(); i += 2; }
            "--output" => { output_file = args[i + 1].clone(); i += 2; }
            _ => i += 1,
        }
    }

    // Load private key
    let private_key = fs::read_to_string(&key_file)?.trim().to_string();
    let key_pair = KeyPair::from_private_key_base64(&private_key)?;

    // Build license
    let mut builder = LicenseBuilder::new()
        .license_id(&license_id)
        .customer_id(&customer_id)
        .expires_in(Duration::days(days));

    if !features.is_empty() {
        builder = builder.allowed_features(features);
    }

    let license_json = builder.build_and_sign_to_json(&key_pair)?;

    // Output
    if output_file.is_empty() {
        println!("{}", license_json);
    } else {
        fs::write(&output_file, &license_json)?;
        println!("License written to: {}", output_file);
    }

    Ok(())
}

fn verify_license(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let license_file = args.get(0).expect("License file required");
    let public_key = args.get(1).expect("Public key required");

    let license_json = fs::read_to_string(license_file)?;
    let result = validate_license(&license_json, public_key, &ValidationContext::new())?;

    if result.is_valid {
        let payload = result.payload.as_ref().unwrap();
        println!("License VALID");
        println!("  ID: {}", payload.license_id);
        println!("  Customer: {}", payload.customer_id);
        println!("  Issued: {}", payload.issued_at);
        if let Some(days) = result.days_remaining() {
            println!("  Days remaining: {}", days);
        } else {
            println!("  Expiration: Never");
        }
    } else {
        println!("License INVALID");
        for failure in &result.failures {
            println!("  - {}", failure.message);
        }
    }

    Ok(())
}
```

---

## Client Application Integration

Integrating license validation into a typical application.

```rust
use rust_license_key::prelude::*;
use std::sync::OnceLock;

// Embedded public key (from your key generation)
const PUBLIC_KEY: &str = "your-base64-public-key-here";

// Global license state
static LICENSE: OnceLock<Option<LicensePayload>> = OnceLock::new();

/// Initialize the application with license validation
pub fn init_application() -> Result<(), String> {
    // Load license file
    let license_json = match std::fs::read_to_string("license.json") {
        Ok(content) => content,
        Err(_) => return Err("License file not found".to_string()),
    };

    // Validate license
    let context = ValidationContext::new()
        .with_hostname(&get_hostname())
        .with_software_version(get_version());

    let result = validate_license(&license_json, PUBLIC_KEY, &context)
        .map_err(|e| format!("License error: {}", e))?;

    if !result.is_valid {
        let messages: Vec<_> = result.failures.iter()
            .map(|f| f.message.clone())
            .collect();
        return Err(format!("Invalid license: {}", messages.join(", ")));
    }

    // Store license for later use
    LICENSE.set(result.payload).ok();

    Ok(())
}

/// Check if the application is licensed
pub fn is_licensed() -> bool {
    LICENSE.get().map(|l| l.is_some()).unwrap_or(false)
}

/// Get the licensed customer name
pub fn get_customer_name() -> Option<String> {
    LICENSE.get()
        .and_then(|l| l.as_ref())
        .and_then(|p| p.customer_name.clone())
}

/// Check if a feature is available
pub fn has_feature(feature: &str) -> bool {
    LICENSE.get()
        .and_then(|l| l.as_ref())
        .map(|p| p.constraints.is_feature_allowed(feature))
        .unwrap_or(false)
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn get_version() -> semver::Version {
    semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap()
}

// Application usage
fn main() {
    if let Err(e) = init_application() {
        eprintln!("Failed to start: {}", e);
        std::process::exit(1);
    }

    println!("Application started!");
    println!("Customer: {}", get_customer_name().unwrap_or_default());

    if has_feature("premium") {
        println!("Premium features enabled!");
    }
}
```

---

## Feature-Gated Application

Enabling/disabling features based on license.

```rust
use rust_license_key::prelude::*;

struct App {
    license_result: ValidationResult,
}

impl App {
    pub fn new(license_json: &str, public_key: &str) -> Result<Self, LicenseError> {
        let context = ValidationContext::new();
        let license_result = validate_license(license_json, public_key, &context)?;

        if !license_result.is_valid {
            // Could still create app with limited functionality
        }

        Ok(Self { license_result })
    }

    /// Basic feature - always available
    pub fn basic_feature(&self) {
        println!("Executing basic feature...");
    }

    /// Premium feature - requires license
    pub fn premium_feature(&self) -> Result<(), &'static str> {
        if !self.license_result.is_feature_allowed("premium") {
            return Err("Premium license required");
        }
        println!("Executing premium feature...");
        Ok(())
    }

    /// Enterprise feature - requires specific license
    pub fn enterprise_feature(&self) -> Result<(), &'static str> {
        if !self.license_result.is_feature_allowed("enterprise") {
            return Err("Enterprise license required");
        }
        println!("Executing enterprise feature...");
        Ok(())
    }

    /// Analytics with connection limit
    pub fn analytics(&self, current_users: u32) -> Result<(), String> {
        // Re-validate with current connection count
        let context = ValidationContext::new()
            .with_feature("analytics")
            .with_connection_count(current_users);

        // For simplicity, check against stored constraints
        if let Some(payload) = &self.license_result.payload {
            if !payload.constraints.is_feature_allowed("analytics") {
                return Err("Analytics not licensed".to_string());
            }

            if let Some(max) = payload.constraints.max_connections {
                if current_users >= max {
                    return Err(format!("User limit exceeded ({}/{})", current_users, max));
                }
            }
        }

        println!("Running analytics for {} users...", current_users);
        Ok(())
    }

    /// Get available features
    pub fn list_features(&self) -> Vec<String> {
        let mut features = vec!["basic".to_string()]; // Always available

        if self.license_result.is_feature_allowed("premium") {
            features.push("premium".to_string());
        }
        if self.license_result.is_feature_allowed("enterprise") {
            features.push("enterprise".to_string());
        }
        if self.license_result.is_feature_allowed("analytics") {
            features.push("analytics".to_string());
        }

        features
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example with a premium license
    let key_pair = KeyPair::generate()?;
    let license = LicenseBuilder::new()
        .license_id("DEMO-001")
        .customer_id("DEMO")
        .allowed_features(vec!["premium", "analytics"])
        .max_connections(100)
        .build_and_sign_to_json(&key_pair)?;

    let app = App::new(&license, &key_pair.public_key_base64())?;

    println!("Available features: {:?}", app.list_features());
    println!();

    app.basic_feature();

    match app.premium_feature() {
        Ok(_) => println!("Premium: Success"),
        Err(e) => println!("Premium: {}", e),
    }

    match app.enterprise_feature() {
        Ok(_) => println!("Enterprise: Success"),
        Err(e) => println!("Enterprise: {}", e),
    }

    match app.analytics(50) {
        Ok(_) => println!("Analytics: Success"),
        Err(e) => println!("Analytics: {}", e),
    }

    Ok(())
}
```

---

## SaaS Multi-Tenant Licensing

Licensing for SaaS applications with multiple tenants.

```rust
use rust_license_key::prelude::*;
use std::collections::HashMap;
use std::sync::RwLock;

struct TenantLicense {
    payload: LicensePayload,
    max_users: Option<u32>,
    current_users: u32,
}

struct LicenseManager {
    public_key: String,
    tenants: RwLock<HashMap<String, TenantLicense>>,
}

impl LicenseManager {
    pub fn new(public_key: &str) -> Self {
        Self {
            public_key: public_key.to_string(),
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Register a tenant with their license
    pub fn register_tenant(&self, tenant_id: &str, license_json: &str) -> Result<(), String> {
        let result = validate_license(license_json, &self.public_key, &ValidationContext::new())
            .map_err(|e| e.to_string())?;

        if !result.is_valid {
            return Err("Invalid license".to_string());
        }

        let payload = result.payload.unwrap();

        // Verify tenant ID matches license
        if payload.customer_id != tenant_id {
            return Err("Tenant ID mismatch".to_string());
        }

        let tenant_license = TenantLicense {
            max_users: payload.constraints.max_connections,
            payload,
            current_users: 0,
        };

        self.tenants.write().unwrap().insert(tenant_id.to_string(), tenant_license);
        Ok(())
    }

    /// Check if tenant can add a user
    pub fn can_add_user(&self, tenant_id: &str) -> bool {
        let tenants = self.tenants.read().unwrap();
        if let Some(tenant) = tenants.get(tenant_id) {
            if let Some(max) = tenant.max_users {
                return tenant.current_users < max;
            }
            return true; // No limit
        }
        false
    }

    /// Add a user to tenant
    pub fn add_user(&self, tenant_id: &str) -> Result<(), String> {
        let mut tenants = self.tenants.write().unwrap();
        if let Some(tenant) = tenants.get_mut(tenant_id) {
            if let Some(max) = tenant.max_users {
                if tenant.current_users >= max {
                    return Err(format!("User limit reached ({}/{})", tenant.current_users, max));
                }
            }
            tenant.current_users += 1;
            Ok(())
        } else {
            Err("Tenant not found".to_string())
        }
    }

    /// Check if tenant has a feature
    pub fn has_feature(&self, tenant_id: &str, feature: &str) -> bool {
        let tenants = self.tenants.read().unwrap();
        tenants.get(tenant_id)
            .map(|t| t.payload.constraints.is_feature_allowed(feature))
            .unwrap_or(false)
    }

    /// Get tenant's remaining days
    pub fn days_remaining(&self, tenant_id: &str) -> Option<i64> {
        let tenants = self.tenants.read().unwrap();
        tenants.get(tenant_id).and_then(|t| {
            t.payload.constraints.expiration_date.map(|exp| {
                (exp - chrono::Utc::now()).num_days()
            })
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate()?;
    let manager = LicenseManager::new(&key_pair.public_key_base64());

    // Create licenses for different tenants
    let basic_license = LicenseBuilder::new()
        .license_id("LIC-BASIC-001")
        .customer_id("tenant-basic")
        .allowed_features(vec!["core"])
        .max_connections(10)
        .expires_in(chrono::Duration::days(30))
        .build_and_sign_to_json(&key_pair)?;

    let premium_license = LicenseBuilder::new()
        .license_id("LIC-PREMIUM-001")
        .customer_id("tenant-premium")
        .allowed_features(vec!["core", "analytics", "api"])
        .max_connections(100)
        .expires_in(chrono::Duration::days(365))
        .build_and_sign_to_json(&key_pair)?;

    // Register tenants
    manager.register_tenant("tenant-basic", &basic_license)?;
    manager.register_tenant("tenant-premium", &premium_license)?;

    // Usage
    println!("Basic tenant:");
    println!("  Has analytics: {}", manager.has_feature("tenant-basic", "analytics"));
    println!("  Days remaining: {:?}", manager.days_remaining("tenant-basic"));

    println!("\nPremium tenant:");
    println!("  Has analytics: {}", manager.has_feature("tenant-premium", "analytics"));
    println!("  Days remaining: {:?}", manager.days_remaining("tenant-premium"));

    // Add users
    for i in 0..12 {
        match manager.add_user("tenant-basic") {
            Ok(_) => println!("Added user {} to basic tenant", i + 1),
            Err(e) => println!("Cannot add user {}: {}", i + 1, e),
        }
    }

    Ok(())
}
```

---

## Trial License System

Implementing trial and upgrade workflows.

```rust
use rust_license_key::prelude::*;
use chrono::{Duration, Utc};

enum LicenseType {
    Trial,
    Basic,
    Professional,
    Enterprise,
}

impl LicenseType {
    fn features(&self) -> Vec<&'static str> {
        match self {
            LicenseType::Trial => vec!["trial"],
            LicenseType::Basic => vec!["basic"],
            LicenseType::Professional => vec!["basic", "professional", "api"],
            LicenseType::Enterprise => vec!["basic", "professional", "enterprise", "api", "sso"],
        }
    }

    fn duration(&self) -> Duration {
        match self {
            LicenseType::Trial => Duration::days(14),
            _ => Duration::days(365),
        }
    }

    fn max_users(&self) -> Option<u32> {
        match self {
            LicenseType::Trial => Some(3),
            LicenseType::Basic => Some(10),
            LicenseType::Professional => Some(50),
            LicenseType::Enterprise => None, // Unlimited
        }
    }
}

struct LicenseService {
    key_pair: KeyPair,
}

impl LicenseService {
    pub fn new() -> Result<Self, LicenseError> {
        // In production, load from secure storage
        Ok(Self {
            key_pair: KeyPair::generate()?,
        })
    }

    pub fn public_key(&self) -> String {
        self.key_pair.public_key_base64()
    }

    /// Generate a trial license for a new customer
    pub fn create_trial(&self, customer_id: &str, email: &str) -> Result<String, LicenseError> {
        LicenseBuilder::new()
            .license_id(&format!("TRIAL-{}-{}", customer_id, Utc::now().timestamp()))
            .customer_id(customer_id)
            .customer_name(email)
            .expires_in(LicenseType::Trial.duration())
            .allowed_features(LicenseType::Trial.features())
            .max_connections(LicenseType::Trial.max_users().unwrap())
            .metadata("type", serde_json::json!("trial"))
            .metadata("email", serde_json::json!(email))
            .build_and_sign_to_json(&self.key_pair)
    }

    /// Upgrade a customer to a paid license
    pub fn create_paid_license(
        &self,
        customer_id: &str,
        customer_name: &str,
        license_type: LicenseType,
    ) -> Result<String, LicenseError> {
        let mut builder = LicenseBuilder::new()
            .license_id(&format!("LIC-{}-{}", customer_id, Utc::now().timestamp()))
            .customer_id(customer_id)
            .customer_name(customer_name)
            .expires_in(license_type.duration())
            .allowed_features(license_type.features());

        if let Some(max_users) = license_type.max_users() {
            builder = builder.max_connections(max_users);
        }

        builder.build_and_sign_to_json(&self.key_pair)
    }

    /// Check if a license is a trial
    pub fn is_trial(&self, license_json: &str) -> bool {
        if let Ok(payload) = parse_license(license_json, &self.public_key()) {
            if let Some(metadata) = &payload.metadata {
                return metadata.get("type") == Some(&serde_json::json!("trial"));
            }
        }
        false
    }

    /// Get days remaining in trial
    pub fn trial_days_remaining(&self, license_json: &str) -> Option<i64> {
        let result = validate_license(license_json, &self.public_key(), &ValidationContext::new()).ok()?;
        if result.is_valid {
            result.days_remaining()
        } else {
            Some(0)
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = LicenseService::new()?;

    // Create trial license
    let trial = service.create_trial("cust-001", "user@example.com")?;
    println!("Trial License:\n{}\n", trial);

    println!("Is trial: {}", service.is_trial(&trial));
    println!("Days remaining: {:?}", service.trial_days_remaining(&trial));

    // Upgrade to professional
    let professional = service.create_paid_license(
        "cust-001",
        "Acme Corp",
        LicenseType::Professional,
    )?;
    println!("\nProfessional License:\n{}\n", professional);

    println!("Is trial: {}", service.is_trial(&professional));

    Ok(())
}
```

---

## Version-Locked Licensing

Licenses that only work with specific software versions.

```rust
use rust_license_key::prelude::*;
use semver::Version;
use chrono::Duration;

fn create_version_locked_license(
    key_pair: &KeyPair,
    customer_id: &str,
    min_version: &str,
    max_version: &str,
) -> Result<String, LicenseError> {
    LicenseBuilder::new()
        .license_id(&format!("VER-{}", customer_id))
        .customer_id(customer_id)
        .minimum_version_str(min_version)?
        .maximum_version_str(max_version)?
        .expires_in(Duration::days(365))
        .build_and_sign_to_json(key_pair)
}

fn validate_for_version(
    license_json: &str,
    public_key: &str,
    app_version: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let version = Version::parse(app_version)?;

    let context = ValidationContext::new()
        .with_software_version(version);

    let result = validate_license(license_json, public_key, &context)?;

    if !result.is_valid {
        for failure in &result.failures {
            if matches!(failure.failure_type, ValidationFailureType::VersionConstraint) {
                println!("Version error: {}", failure.message);
                if let Some(ctx) = &failure.context {
                    println!("  Details: {}", ctx);
                }
            }
        }
    }

    Ok(result.is_valid)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate()?;
    let public_key = key_pair.public_key_base64();

    // Create license valid for versions 1.x only
    let license = create_version_locked_license(
        &key_pair,
        "CUST-001",
        "1.0.0",
        "1.99.99",
    )?;

    println!("Testing version-locked license:");
    println!("  Version 1.0.0: {}", validate_for_version(&license, &public_key, "1.0.0")?);
    println!("  Version 1.5.0: {}", validate_for_version(&license, &public_key, "1.5.0")?);
    println!("  Version 2.0.0: {}", validate_for_version(&license, &public_key, "2.0.0")?);
    println!("  Version 0.9.0: {}", validate_for_version(&license, &public_key, "0.9.0")?);

    Ok(())
}
```

---

## Machine-Bound Licensing

Licenses bound to specific machines.

```rust
use rust_license_key::prelude::*;
use chrono::Duration;
use std::process::Command;

/// Get a machine identifier (simplified example)
fn get_machine_id() -> String {
    // On Linux, you might use /etc/machine-id
    // On Windows, you might use the Windows Product ID
    // This is a simplified example using hostname + username

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    // Create a simple hash
    format!("{}-{}", hostname, username)
}

/// Get hardware-based machine ID (more reliable)
#[cfg(target_os = "linux")]
fn get_hardware_id() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(not(target_os = "linux"))]
fn get_hardware_id() -> Option<String> {
    // Fallback for other platforms
    Some(get_machine_id())
}

fn create_machine_bound_license(
    key_pair: &KeyPair,
    customer_id: &str,
    machine_ids: Vec<&str>,
) -> Result<String, LicenseError> {
    LicenseBuilder::new()
        .license_id(&format!("MACHINE-{}", customer_id))
        .customer_id(customer_id)
        .allowed_machine_ids(machine_ids)
        .expires_in(Duration::days(365))
        .build_and_sign_to_json(key_pair)
}

fn validate_on_this_machine(
    license_json: &str,
    public_key: &str,
) -> Result<ValidationResult, LicenseError> {
    let machine_id = get_hardware_id().unwrap_or_else(get_machine_id);

    let context = ValidationContext::new()
        .with_machine_id(&machine_id);

    validate_license(license_json, public_key, &context)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate()?;
    let public_key = key_pair.public_key_base64();

    let current_machine = get_hardware_id().unwrap_or_else(get_machine_id);
    println!("Current machine ID: {}", current_machine);

    // Create license for this machine
    let license = create_machine_bound_license(
        &key_pair,
        "CUST-001",
        vec![&current_machine, "backup-server"],
    )?;

    // Validate
    let result = validate_on_this_machine(&license, &public_key)?;

    if result.is_valid {
        println!("License valid for this machine!");
    } else {
        println!("License NOT valid for this machine:");
        for failure in &result.failures {
            println!("  - {}", failure.message);
        }
    }

    Ok(())
}
```

---

**Previous:** [Security Best Practices](./security.md) | **Next:** [Architecture](./architecture.md)
