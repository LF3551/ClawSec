# Changelog

All notable changes to ClawSec will be documented in this file.

## [2.0.0] - 2025-11-22

### Added
- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation (100,000 iterations)
- Protocol versioning with magic number validation
- Secure random IV generation using OpenSSL
- Memory wiping for sensitive data
- Comprehensive security documentation
- Docker support with Alpine Linux
- Kubernetes deployment manifests
- Systemd service file
- Automatic installation script
- CI/CD with GitHub Actions
- Multi-platform build support

### Changed
- Renamed binary from `cryptcat` to `clawsec`
- Updated all documentation to English
- Improved error messages and user feedback
- Enhanced Makefile with platform-specific targets

### Removed
- Deprecated Twofish encryption
- Hardcoded default password "metallica"
- Legacy Cryptcat documentation
- Obsolete netcat promotional files

### Security
- Fixed direct key usage vulnerability
- Removed weak random number generation
- Added GCM authentication tags
- Implemented secure password-based key derivation
- Added protocol version checking

## [1.x] - Legacy Cryptcat

### Features
- Twofish encryption (deprecated)
- Basic netcat functionality
- Direct key usage (insecure)

---

**Note:** Version 2.0.0 represents a complete cryptographic rewrite and is **not compatible** with legacy Cryptcat versions.
