## Summary

<!-- What changes and why. Link issues with "Fixes #123". -->

## Compatibility

- [ ] Wire-compatible with the current release (no handshake or frame format change)
- [ ] Protocol change (needs a major version, version check updated, both ends must upgrade)

## Checklist

- [ ] `make -C src test` passes (and `make -C src test-asan` for memory-related changes)
- [ ] `make -C src e2e` passes (Linux); `sudo make -C src e2e-vpn` for TUN changes
- [ ] `make -C src werror` builds without warnings
- [ ] New behaviour has tests (unit and/or end-to-end)
- [ ] README / SECURITY.md / man page / completions / CHANGELOG updated where relevant
- [ ] No secrets, passwords or key files in code, tests or logs
