# Security Best Practices

This guide covers security considerations and best practices for using rust-license-key in production environments.

## Table of Contents

1. [Security Model Overview](#security-model-overview)
2. [Key Management](#key-management)
3. [License Distribution](#license-distribution)
4. [Client-Side Security](#client-side-security)
5. [What This Library Does NOT Protect Against](#what-this-library-does-not-protect-against)
6. [Security Checklist](#security-checklist)

---

## Security Model Overview

### Cryptographic Foundation

rust-license-key uses **Ed25519** digital signatures, which provide:

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 (Curve25519 + SHA-512) |
| Security Level | 128-bit (equivalent to RSA-3072) |
| Key Size | 32 bytes (private), 32 bytes (public) |
| Signature Size | 64 bytes |
| Resistance | Quantum-resistant concerns ongoing |

### Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRUSTED ZONE                                 │
│                (Your secure infrastructure)                      │
│                                                                  │
│  ┌──────────────────┐                                           │
│  │   Private Key    │ ← NEVER leaves this zone                  │
│  │   (32 bytes)     │                                           │
│  └────────┬─────────┘                                           │
│           │                                                      │
│           ▼                                                      │
│  ┌──────────────────┐                                           │
│  │ License Signing  │                                           │
│  │     Server       │                                           │
│  └────────┬─────────┘                                           │
│           │                                                      │
└───────────│─────────────────────────────────────────────────────┘
            │
            ▼ (signed license)
┌─────────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                                │
│            (Customer environment, public internet)               │
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │   Public Key     │    │  Signed License  │                   │
│  │  (embedded)      │    │  (from file)     │                   │
│  └────────┬─────────┘    └────────┬─────────┘                   │
│           │                       │                              │
│           ▼                       ▼                              │
│  ┌────────────────────────────────────────┐                     │
│  │         License Validation             │                     │
│  │   (signature verification + checks)    │                     │
│  └────────────────────────────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Security Guarantees

| Guarantee | Description |
|-----------|-------------|
| **Authenticity** | Only holder of private key can create valid licenses |
| **Integrity** | Any modification to license invalidates signature |
| **Non-repudiation** | Publisher cannot deny creating a valid license |

### What Is NOT Guaranteed

| Aspect | Limitation |
|--------|------------|
| **Confidentiality** | License content is readable by anyone |
| **Copy Protection** | Licenses can be copied between machines |
| **Reverse Engineering** | Public key in binary can be extracted |
| **Runtime Protection** | Validation can be bypassed in memory |

---

## Key Management

### Private Key Security

The private key is the most critical security asset. If compromised, attackers can generate unlimited valid licenses.

#### DO

- Store private keys in a Hardware Security Module (HSM) for high-value products
- Use encrypted storage (e.g., HashiCorp Vault, AWS KMS, Azure Key Vault)
- Restrict access to key material to minimal personnel
- Enable audit logging for all key access
- Use separate keys for development/testing and production
- Rotate keys periodically (with license re-issuance)

#### DON'T

- Store private keys in source control
- Store private keys in plaintext files
- Email or transmit private keys over insecure channels
- Share private keys between team members
- Use the same key for multiple products
- Store private keys on internet-facing servers

### Key Storage Examples

#### Environment Variable (Development Only)

```rust
let private_key = std::env::var("LICENSE_PRIVATE_KEY")
    .expect("LICENSE_PRIVATE_KEY must be set");
let key_pair = KeyPair::from_private_key_base64(&private_key)?;
```

#### File with Restricted Permissions (Simple Production)

```bash
# Create key file with restricted permissions
chmod 600 /etc/myapp/private_key.txt
chown root:root /etc/myapp/private_key.txt
```

```rust
let private_key = std::fs::read_to_string("/etc/myapp/private_key.txt")?;
let key_pair = KeyPair::from_private_key_base64(private_key.trim())?;
```

#### AWS Secrets Manager (Recommended for Cloud)

```rust
use aws_sdk_secretsmanager::Client;

async fn get_key_pair(client: &Client) -> Result<KeyPair, Box<dyn Error>> {
    let response = client
        .get_secret_value()
        .secret_id("myapp/license-private-key")
        .send()
        .await?;

    let private_key = response.secret_string().unwrap();
    Ok(KeyPair::from_private_key_base64(private_key)?)
}
```

### Public Key Distribution

The public key is safe to distribute but should be embedded carefully.

#### Embedding in Rust Binary

```rust
// This key will be compiled into your binary
const PUBLIC_KEY: &str = "your-base64-public-key";

fn validate(license: &str) -> bool {
    is_license_valid(license, PUBLIC_KEY)
}
```

#### Obfuscation (Defense in Depth)

While not a security measure, splitting the key can deter casual inspection:

```rust
fn get_public_key() -> String {
    let parts = [
        "Bp7Y2xK9",
        "mN4vL8qR",
        "3tH6wE5j",
        "A0cF2gI1",
    ];
    parts.join("")
}
```

---

## License Distribution

### License File Security

Licenses are **signed but not encrypted**. Anyone with the file can read its contents.

#### What to Include

- License ID
- Customer ID
- Expiration date
- Allowed features
- Technical constraints

#### What NOT to Include

- Customer passwords or API keys
- Sensitive business information
- Personal identifiable information (PII)
- Payment or financial data

### Secure Delivery

| Method | Security | Recommendation |
|--------|----------|----------------|
| HTTPS download portal | Good | Recommended for most cases |
| Email attachment | Poor | Avoid; email is not secure |
| In-app delivery | Good | Use HTTPS with certificate pinning |
| Physical media | Varies | Acceptable for air-gapped systems |

### License Revocation

rust-license-key operates offline and does not support automatic revocation. Strategies for revocation:

1. **Short-lived licenses**: Issue licenses with shorter expiration periods
2. **Version constraints**: New software versions reject old licenses
3. **Hybrid approach**: Online check at startup with offline fallback

```rust
// Example: Check online revocation list, fall back to offline validation
async fn validate_with_revocation(license: &str) -> bool {
    // Try online check first
    if let Ok(is_revoked) = check_revocation_server(license).await {
        if is_revoked {
            return false;
        }
    }

    // Fall back to offline validation
    is_license_valid(license, PUBLIC_KEY)
}
```

---

## Client-Side Security

### Validation Best Practices

#### Validate Early and Often

```rust
fn main() {
    // Validate at startup
    let license_result = validate_license(&read_license(), PUBLIC_KEY, &context());

    if !license_result.map(|r| r.is_valid).unwrap_or(false) {
        eprintln!("Invalid license. Exiting.");
        std::process::exit(1);
    }

    // Re-validate periodically
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(3600)); // Every hour
            if !is_license_valid(&read_license(), PUBLIC_KEY) {
                eprintln!("License no longer valid");
                // Handle gracefully
            }
        }
    });
}
```

#### Check Features at Point of Use

```rust
fn premium_feature() -> Result<(), &'static str> {
    let result = validate_license(&license, PUBLIC_KEY,
        &ValidationContext::new().with_feature("premium"))?;

    if !result.is_valid {
        return Err("Premium feature not licensed");
    }

    // Execute premium feature
    Ok(())
}
```

### Handling Validation Failures

```rust
fn handle_validation(result: &ValidationResult) {
    if result.is_valid {
        return;
    }

    for failure in &result.failures {
        match failure.failure_type {
            ValidationFailureType::Expired => {
                // Show renewal prompt
                show_renewal_dialog();
            }
            ValidationFailureType::InvalidSignature => {
                // Potential tampering - log and exit
                log_security_event("Invalid license signature detected");
                std::process::exit(1);
            }
            ValidationFailureType::FeatureConstraint => {
                // Disable feature gracefully
                disable_feature(&failure.message);
            }
            _ => {
                show_license_error(&failure.message);
            }
        }
    }
}
```

### Defensive Coding

```rust
// Bad: Trusts any license that parses
fn bad_check(license: &str) -> bool {
    parse_license(license, PUBLIC_KEY).is_ok()
}

// Good: Full validation with context
fn good_check(license: &str) -> bool {
    let context = ValidationContext::new()
        .with_hostname(&get_hostname())
        .with_software_version(get_version());

    validate_license(license, PUBLIC_KEY, &context)
        .map(|r| r.is_valid)
        .unwrap_or(false)
}
```

---

## What This Library Does NOT Protect Against

### Binary Patching

An attacker can modify your compiled binary to:
- Skip license validation entirely
- Replace the embedded public key with their own
- Patch out feature checks

**Mitigation**: Code signing, integrity checks, obfuscation (defense in depth)

### Memory Manipulation

An attacker can modify running process memory to:
- Change validation return values
- Modify license data after parsing

**Mitigation**: Limited; this is a fundamental limitation of offline validation

### Key Extraction

The public key embedded in your binary can be extracted and used to:
- Understand license validation logic
- Create tools that parse your licenses

**Note**: This does NOT allow creating valid licenses (requires private key)

### License Sharing

Customers can share their license files with others.

**Mitigation**:
- Bind licenses to machine IDs or hostnames
- Limit concurrent connections
- Monitor for unusual usage patterns

### Reverse Engineering

Determined attackers can reverse engineer your application to understand and bypass license checks.

**Mitigation**:
- Consider the threat model for your product
- High-value products may need additional protection (hardware dongles, online-only features)
- Accept that perfect protection is impossible for offline software

---

## Security Checklist

### Before Production Deployment

- [ ] Private key stored in HSM or encrypted vault
- [ ] Private key access restricted and audited
- [ ] Separate keys for development and production
- [ ] Public key embedded (not loaded from external file)
- [ ] License validation occurs at startup
- [ ] License validation occurs before feature access
- [ ] Validation failures are logged
- [ ] No sensitive data in license payload
- [ ] Licenses delivered over HTTPS

### Periodic Review

- [ ] Review key access logs
- [ ] Audit license issuance records
- [ ] Test validation with expired/invalid licenses
- [ ] Update library to latest version
- [ ] Review for newly discovered vulnerabilities

### Incident Response

- [ ] Plan for key compromise (re-issue all licenses)
- [ ] Plan for mass license revocation (version update)
- [ ] Monitoring for unusual license patterns
- [ ] Customer communication plan

---

**Previous:** [API Reference](./api-reference.md) | **Next:** [Examples](./examples.md)
