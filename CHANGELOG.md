# Changelog

All notable changes to ClawSec will be documented in this file.

## [2.3.0] - 2025-11-23

### Changed
- **Complete code rewrite**: Modernized from legacy K&R C to C99/POSIX standards
- Reduced codebase from 1714 to 439 lines (75% reduction)
- Binary size reduced from 72KB to 37KB (48% smaller)
- Removed obsolete `generic.h` compatibility layer (1996 legacy code)
- Improved code architecture with clean function separation
- Enhanced error handling on all system calls
- Thread-safe functions: `localtime_r`, `strerror_r`
- Proper resource cleanup and memory management

### Added
- Chat mode with timestamps and colored output (server-side only)
- File transfer mode with auto-close and statistics
- Robust `write_all()` with EINTR handling
- Non-blocking `connect_with_timeout()` with select
- Signal handling (SIGPIPE ignored)

### Fixed
- Chat mode formatting isolated to server in listen mode
- Reverse shell mode works cleanly without formatting artifacts
- File transfer completes gracefully with `shutdown(SHUT_WR)`

### Removed
- Legacy K&R C code and goto statements
- Global variables and setjmp/longjmp
- Platform-specific compatibility hacks for obsolete systems
- Unused files: `generic.h`, old documentation

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
