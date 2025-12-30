# Publishing rust-license-key to crates.io

This guide describes how to publish `rust-license-key` to [crates.io](https://crates.io).

## Prerequisites

### 1. Create a crates.io Account

1. Go to [crates.io](https://crates.io)
2. Click "Log in with GitHub"
3. Authorize crates.io to access your GitHub account

### 2. Generate an API Token

1. Go to [crates.io/settings/tokens](https://crates.io/settings/tokens)
2. Click "New Token"
3. Give it a name (e.g., "rust-license-key-publish")
4. Select scopes: `publish-new` and `publish-update`
5. Click "Create"
6. Copy the token (you won't see it again!)

### 3. Login to Cargo

```bash
cargo login <your-api-token>
```

This stores the token in `~/.cargo/credentials.toml`.

---

## Pre-Publication Checklist

Before publishing, verify the following:

### Required Files

| File | Status | Description |
|------|--------|-------------|
| `Cargo.toml` | Required | Package metadata |
| `README.md` | Required | Displayed on crates.io |
| `LICENSE-MIT` | Required | MIT license text |
| `LICENSE-APACHE` | Required | Apache 2.0 license text |
| `CHANGELOG.md` | Recommended | Version history |
| `src/lib.rs` | Required | Library entry point |

### Cargo.toml Fields

| Field | Value | Required |
|-------|-------|----------|
| `name` | `rust-license-key` | Yes |
| `version` | `0.1.0` | Yes |
| `edition` | `2021` | Yes |
| `description` | Set | Yes |
| `license` | `MIT OR Apache-2.0` | Yes |
| `repository` | GitHub URL | Recommended |
| `documentation` | docs.rs URL | Recommended |
| `readme` | `README.md` | Recommended |
| `keywords` | Array (max 5) | Recommended |
| `categories` | Array | Recommended |

### Code Quality

```bash
# Format code
cargo fmt

# Check for issues
cargo clippy -- -D warnings

# Run all tests
cargo test

# Build documentation
cargo doc --no-deps
```

---

## Make GitHub Repository Public

Before publishing, your GitHub repository must be public (or the links won't work):

1. Go to your repository: https://github.com/Simon-Stephan/rust-license-key
2. Click "Settings"
3. Scroll to "Danger Zone"
4. Click "Change visibility"
5. Select "Make public"
6. Confirm

---

## Verify Package

Before the actual publication, do a dry run:

```bash
cargo publish --dry-run
```

This will:
- Package your crate
- Verify all metadata
- Check for common issues
- NOT upload anything

Review the output and fix any warnings or errors.

### Common Issues

| Issue | Solution |
|-------|----------|
| "crate name already exists" | Choose a different name in Cargo.toml |
| "missing documentation" | Add `#![deny(missing_docs)]` and document all public items |
| "failed to verify" | Run `cargo build` and `cargo test` |

---

## Publish

When ready, publish:

```bash
cargo publish
```

After a successful publish:

1. Your crate will be available at: https://crates.io/crates/rust-license-key
2. Documentation will be generated at: https://docs.rs/rust-license-key
3. Anyone can add it with: `cargo add rust-license-key`

---

## Post-Publication

### Create a Git Tag

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Create a GitHub Release

1. Go to https://github.com/Simon-Stephan/rust-license-key/releases
2. Click "Create a new release"
3. Select the tag `v0.1.0`
4. Title: `v0.1.0`
5. Description: Copy from CHANGELOG.md
6. Click "Publish release"

---

## Publishing Updates

For future versions:

### 1. Update Version

Edit `Cargo.toml`:

```toml
version = "0.2.0"
```

### 2. Update Changelog

Add a new section to `CHANGELOG.md`:

```markdown
## [0.2.0] - YYYY-MM-DD

### Added
- New feature X

### Changed
- Updated Y

### Fixed
- Bug Z
```

### 3. Commit and Tag

```bash
git add .
git commit -m "chore: release v0.2.0"
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main --tags
```

### 4. Publish

```bash
cargo publish
```

---

## Version Numbering (SemVer)

Follow [Semantic Versioning](https://semver.org/):

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Breaking API change | Major | 0.1.0 → 1.0.0 |
| New feature (backwards compatible) | Minor | 0.1.0 → 0.2.0 |
| Bug fix | Patch | 0.1.0 → 0.1.1 |

**Note:** While version is `0.x.y`, minor version bumps may contain breaking changes.

---

## Yanking a Version

If you publish a broken version:

```bash
# Yank version (prevents new installs but existing users can still use it)
cargo yank --version 0.1.0

# Un-yank if it was a mistake
cargo yank --version 0.1.0 --undo
```

---

## Crate Name Availability

The name `rust-license-key` may already be taken. Check at:
https://crates.io/crates/rust-license-key

If taken, consider alternatives:
- `license-rs`
- `offline-license`
- `ed25519-license`
- `sw-license`

Update `Cargo.toml` accordingly:

```toml
[package]
name = "your-chosen-name"

[lib]
name = "your_chosen_name"  # Underscores for Rust module name
```

---

## Quick Commands Reference

```bash
# Login (once)
cargo login <token>

# Verify package
cargo publish --dry-run

# Publish
cargo publish

# Tag release
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

---

## Useful Links

- [crates.io](https://crates.io) - Rust package registry
- [docs.rs](https://docs.rs) - Automatic documentation
- [The Cargo Book - Publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
