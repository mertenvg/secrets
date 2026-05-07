# TODO

## Security Improvements

### Key Validation
Add key validation with minimum requirements for user-provided keys:
- Validate length: exactly 64 hex characters (32 bytes)
- Check entropy: minimum entropy threshold to detect patterns
- Reject weak keys: all same character (e.g., `0000...` or `ffff...`)
- Show warning when users provide custom keys (vs generated)
- Optionally add `--validate-key` command to check existing keys
- Document minimum key requirements in README

**Priority**: High
**Impact**: Prevents weak key usage for new encryptions
**Backward Compatibility**: No breaking changes
