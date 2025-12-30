# Contributing

Thank you for your interest in contributing to rust-license-key! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Making Changes](#making-changes)
5. [Code Style](#code-style)
6. [Testing](#testing)
7. [Documentation](#documentation)
8. [Pull Request Process](#pull-request-process)
9. [Security Issues](#security-issues)

---

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

---

## Getting Started

### Types of Contributions

We welcome various types of contributions:

| Type | Description |
|------|-------------|
| Bug Reports | Report issues with detailed reproduction steps |
| Bug Fixes | Fix reported issues |
| Features | Propose and implement new features |
| Documentation | Improve or expand documentation |
| Tests | Add test coverage |
| Performance | Optimize code without changing behavior |
| Security | Report or fix security vulnerabilities |

### Before You Start

1. **Check existing issues**: Someone may already be working on it
2. **Open an issue first**: For significant changes, discuss before coding
3. **Read the architecture docs**: Understand the codebase design

---

## Development Setup

### Prerequisites

- Rust 1.70 or later
- Git

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/Simon-Stephan/rust-license-key.git
cd rust-license-key

# Build
cargo build

# Run tests
cargo test

# Run clippy
cargo clippy

# Format code
cargo fmt
```

### IDE Setup

**VS Code with rust-analyzer (recommended):**

```json
// .vscode/settings.json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "editor.formatOnSave": true
}
```

---

## Making Changes

### Branch Naming

Use descriptive branch names:

```
feature/add-hostname-wildcards
fix/expired-license-validation
docs/improve-security-guide
test/add-edge-case-coverage
```

### Commit Messages

Follow conventional commit format:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code restructuring
- `perf`: Performance improvement
- `chore`: Maintenance

**Examples:**
```
feat(builder): add wildcard hostname support

Add ability to use wildcards like *.example.com in
allowed_hostnames constraint.

Fixes #42
```

```
fix(validator): correctly handle timezone in expiration check

The expiration check was comparing naive datetimes, which could
cause incorrect validation when server timezone differs from UTC.

Fixes #87
```

---

## Code Style

### Formatting

All code must pass `cargo fmt`:

```bash
cargo fmt --check
```

### Linting

All code must pass `cargo clippy` without warnings:

```bash
cargo clippy -- -D warnings
```

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Types | PascalCase | `LicensePayload` |
| Functions | snake_case | `validate_license` |
| Variables | snake_case | `license_json` |
| Constants | SCREAMING_SNAKE_CASE | `LICENSE_FORMAT_VERSION` |
| Modules | snake_case | `license_builder` |

### Code Organization

```rust
// 1. Module documentation
//! This module provides...

// 2. Imports (grouped and sorted)
use std::collections::HashMap;
use chrono::DateTime;
use serde::{Deserialize, Serialize};

use crate::error::LicenseError;

// 3. Constants
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

// 4. Type definitions
pub struct MyType { ... }

// 5. Implementations
impl MyType {
    // Public methods first
    pub fn new() -> Self { ... }

    // Private methods after
    fn internal_helper(&self) { ... }
}

// 6. Tests
#[cfg(test)]
mod tests { ... }
```

### Documentation

All public items must have rustdoc comments:

```rust
/// Creates a new license builder.
///
/// # Example
///
/// ```
/// use rust_license_key::builder::LicenseBuilder;
///
/// let builder = LicenseBuilder::new()
///     .license_id("LIC-001");
/// ```
pub fn new() -> Self {
    // ...
}
```

### Error Handling

- No `unwrap()` or `expect()` in library code (except tests)
- Return `Result` for all fallible operations
- Provide descriptive error context

```rust
// Bad
let key = BASE64.decode(input).unwrap();

// Good
let key = BASE64.decode(input).map_err(|e| {
    LicenseError::InvalidPublicKey {
        reason: format!("invalid base64 encoding: {}", e),
    }
})?;
```

---

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture

# Only integration tests
cargo test --test integration_tests
```

### Writing Tests

#### Unit Tests

Place in the same file as the code:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specific_behavior() {
        // Arrange
        let input = prepare_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }
}
```

#### Integration Tests

Place in `tests/` directory:

```rust
// tests/my_feature_tests.rs
use rust_license_key::prelude::*;

#[test]
fn test_complete_workflow() {
    // Test end-to-end functionality
}
```

### Test Coverage Requirements

- All new public functions must have tests
- All bug fixes must include a regression test
- Aim for >90% line coverage on critical paths

### Test Naming

```rust
#[test]
fn test_<function>_<scenario>_<expected_outcome>() { }

// Examples
fn test_validate_expired_license_returns_failure() { }
fn test_builder_missing_customer_id_fails() { }
fn test_parse_valid_json_succeeds() { }
```

---

## Documentation

### Types of Documentation

| Location | Purpose |
|----------|---------|
| `src/*.rs` | Rustdoc for API documentation |
| `docs/` | User guides and tutorials |
| `CHANGELOG.md` | Version history |
| `README.md` | Project overview |

### Rustdoc Guidelines

```rust
/// Brief one-line description.
///
/// Longer description with details about behavior,
/// use cases, and important notes.
///
/// # Arguments
///
/// * `param1` - Description of first parameter
/// * `param2` - Description of second parameter
///
/// # Returns
///
/// Description of return value.
///
/// # Errors
///
/// Returns `LicenseError::X` when Y happens.
///
/// # Example
///
/// ```
/// // Working example code
/// ```
///
/// # Panics
///
/// This function never panics. (or describe panic conditions)
///
/// # Security
///
/// Important security considerations.
pub fn function_name(...) { }
```

### Building Documentation

```bash
# Build and open docs
cargo doc --open

# Include private items
cargo doc --document-private-items
```

---

## Pull Request Process

### Before Submitting

1. **Rebase on main**: Ensure your branch is up to date
2. **Run all checks**:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
3. **Update documentation**: If applicable
4. **Add changelog entry**: For user-facing changes

### PR Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Other (describe)

## Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated documentation
- [ ] Added changelog entry

## Related Issues

Fixes #123
```

### Review Process

1. **Automated checks**: CI must pass
2. **Code review**: At least one maintainer approval
3. **Documentation review**: For significant changes
4. **Security review**: For crypto or validation changes

### After Merge

- Delete your branch
- Verify the change in the next release

---

## Security Issues

### Reporting Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Instead, please use GitHub's private vulnerability reporting or contact the maintainer directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Review Process

Security-related PRs require:
1. Review by a maintainer with security experience
2. Verification of cryptographic correctness
3. Consideration of backward compatibility

### Areas of Special Concern

Changes to these areas require extra scrutiny:

- `crypto.rs`: All cryptographic operations
- `parser.rs`: Signature verification logic
- `validator.rs`: Constraint checking logic
- Any changes affecting the license format

---

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Use GitHub's private vulnerability reporting

Thank you for contributing to rust-license-key!

---

**Previous:** [Architecture](./architecture.md) | **Home:** [Documentation](./README.md)
