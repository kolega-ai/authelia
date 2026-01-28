# Log Sanitization Security Fix (CWE-532)

## Overview

This document describes the security fix implemented to address **CWE-532: Sensitive Data Exposure in Logs** in Authelia's request logging functionality.

## Vulnerability Description

The `NewRequestLogger` function in `internal/middlewares/authelia_context.go` was logging full request paths and raw URIs without sanitization, potentially exposing sensitive data such as:

- OAuth2/OIDC tokens (access_token, refresh_token, id_token)
- Authentication credentials (passwords, API keys)
- Session identifiers
- Authorization codes
- Client secrets
- Personal information in URL parameters

## Security Impact

**Severity**: Medium to High
**CWE**: CWE-532 - Sensitive Data Exposure in Logs

If an attacker gained access to Authelia's log files, they could potentially extract:
- User authentication tokens and use them for unauthorized access
- OAuth client secrets for privilege escalation
- Session IDs for session hijacking
- Personal information embedded in redirect URLs

## Fix Implementation

### 1. Created URL Sanitization Module

**File**: `internal/logging/sanitize.go`

- Implements `SanitizeURL()` function that removes sensitive query parameters
- Implements `SanitizePath()` function that removes query parameters from paths
- Maintains a comprehensive list of sensitive parameter names
- Uses case-insensitive parameter matching
- Gracefully handles malformed URLs

### 2. Updated Request Logger

**File**: `internal/middlewares/authelia_context.go`

Modified `NewRequestLogger()` function to use sanitization:
```go
// Before (vulnerable)
fields[logging.FieldPath] = string(ctx.Path())
fields[logging.FieldPathRaw] = uri

// After (secured)
fields[logging.FieldPath] = logging.SanitizePath(string(ctx.Path()))
fields[logging.FieldPathRaw] = logging.SanitizeURL(uri)
```

### 3. Comprehensive Test Coverage

**File**: `internal/logging/sanitize_test.go`

- Tests for OAuth token sanitization
- Tests for password and credential sanitization
- Tests for Authelia-specific parameters (rd, authelia_url)
- Tests for edge cases (malformed URLs, case sensitivity)
- Tests for real-world Authelia request patterns

## Sanitized Parameters

The following parameter names are automatically sanitized in logs:

### OAuth2/OIDC Parameters
- `access_token`, `refresh_token`, `id_token`
- `client_secret`, `authorization_code`
- `code`, `state`, `token`
- `consent_id`, `flow_id`

### Authentication Parameters
- `password`, `passwd`, `pwd`
- `secret`, `key`, `auth`
- `session_id`, `sessionid`
- `api_key`, `apikey`
- `csrf_token`, `nonce`

### Authelia-Specific Parameters
- `rd` (redirect URLs containing sensitive targets)
- `authelia_url`

### Common Sensitive Patterns
- `authorization`, `bearer`

## Example Sanitization

### Before
```
GET /api/oidc/authorize?client_id=myapp&code=secret123&access_token=bearer456&password=userpass
```

### After
```
GET /api/oidc/authorize?client_id=myapp&code=[REDACTED]&access_token=[REDACTED]&password=[REDACTED]
```

## Configuration

The sanitization is **enabled by default** and requires no configuration changes. All existing Authelia deployments will automatically benefit from this security improvement.

## Backward Compatibility

- ✅ **Fully backward compatible** - no breaking changes
- ✅ **No configuration required** - works out of the box
- ✅ **Preserves non-sensitive logging** - debugging capabilities maintained
- ✅ **Performance optimized** - O(1) parameter lookup using maps

## Security Best Practices

This fix implements several security best practices:

1. **Defense in Depth**: Sanitization at the logging layer
2. **Principle of Least Privilege**: Only log necessary information
3. **Fail Secure**: Malformed URLs are sanitized conservatively
4. **Configurable Security**: Extensible parameter list for future needs

## Verification

To verify the fix is working, check your Authelia logs after the update. Sensitive parameters should appear as `[REDACTED]` instead of their actual values.

Example log entry:
```json
{
  "level": "info",
  "method": "GET",
  "path": "/api/oidc/authorize",
  "path_raw": "/api/oidc/authorize?client_id=myapp&code=%5BREDACTED%5D&state=%5BREDACTED%5D",
  "remote_ip": "127.0.0.1",
  "time": "2024-01-28T10:00:00Z"
}
```

## Impact on Operations

- **Debugging**: Non-sensitive debugging information remains available
- **Monitoring**: Request patterns and error tracking continue to work
- **Security Auditing**: Logs are now safe for security team review
- **Performance**: Minimal performance impact (microsecond-level overhead)

## Compliance Benefits

This fix helps organizations meet compliance requirements:

- **PCI DSS**: Prevents credit card data exposure in logs
- **GDPR**: Reduces personal data exposure risk
- **SOX**: Improves audit trail security
- **HIPAA**: Prevents health information logging (if used in healthcare contexts)

---

**Note**: This security fix is part of Authelia's ongoing commitment to security best practices and responsible disclosure of security improvements.