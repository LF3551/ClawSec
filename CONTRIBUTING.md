# Contributing to ClawSec

Thank you for your interest in contributing to ClawSec!

## Development Setup

1. Fork the repository
2. Clone your fork
3. Install dependencies (OpenSSL 3.x)
4. Build the project

```bash
cd unix
make clean
make linux
```

## Running Tests

```bash
# Build test suite
make test_aes

# Run encryption tests
./test_aes

# Manual integration test
# Terminal 1:
./clawsec -l -p 12345 -k "TestPassword" -v

# Terminal 2:
echo "Test" | ./clawsec -k "TestPassword" localhost 12345
```

## Code Style

- Follow existing C/C++ code style
- Use meaningful variable names
- Comment security-critical sections
- Keep functions focused and small

## Security Guidelines

- Never commit hardcoded passwords
- Always test encryption/decryption
- Validate all user inputs
- Use secure memory handling
- Document cryptographic changes

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Update documentation
5. Submit pull request with clear description

## Reporting Security Issues

**Do not** open public issues for security vulnerabilities.

Email security concerns privately to maintainers.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
