package logging

import (
	"net/url"
	"strings"
)

// sensitiveparameters defines parameter names that should be sanitized in logs.
// This prevents sensitive data exposure in application logs (CWE-532).
var sensitiveparameters = map[string]bool{
	// OAuth2/OIDC parameters
	"access_token":        true,
	"refresh_token":       true,
	"id_token":           true,
	"client_secret":      true,
	"code":               true,
	"authorization_code": true,
	"state":              true, // May contain sensitive nonces
	"token":              true,
	"consent_id":         true,
	"flow_id":            true,

	// Authentication parameters
	"password":    true,
	"passwd":      true,
	"pwd":         true,
	"secret":      true,
	"key":         true,
	"session_id":  true,
	"sessionid":   true,
	"auth":        true,
	"api_key":     true,
	"apikey":      true,
	"csrf_token":  true,
	"nonce":       true,

	// Authelia-specific sensitive parameters
	"rd":           true, // Redirect URLs may contain sensitive targets
	"authelia_url": true,

	// Common sensitive patterns
	"authorization": true,
	"bearer":       true,
}

// SanitizeURL removes or masks sensitive parameters from URLs before logging.
// This prevents sensitive authentication tokens, passwords, and session IDs
// from being exposed in application logs.
func SanitizeURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		// If URL parsing fails, sanitize by removing query parameters entirely
		if idx := strings.Index(rawURL, "?"); idx != -1 {
			return rawURL[:idx] + "?[SANITIZED]"
		}
		return rawURL
	}

	values := parsed.Query()
	sanitized := false

	for param := range values {
		if sensitiveparameters[strings.ToLower(param)] {
			values.Set(param, "[REDACTED]")
			sanitized = true
		}
	}

	if sanitized {
		parsed.RawQuery = values.Encode()
	}

	return parsed.String()
}

// SanitizePath removes query parameters from a path to prevent sensitive
// parameter exposure in logs. Only returns the path component.
func SanitizePath(path string) string {
	if path == "" {
		return path
	}

	// Remove query parameters and fragments from path logging
	if idx := strings.Index(path, "?"); idx != -1 {
		return path[:idx]
	}

	if idx := strings.Index(path, "#"); idx != -1 {
		return path[:idx]
	}

	return path
}

// IsSensitiveParameter checks if a parameter name is considered sensitive.
// This is useful for additional sanitization beyond URL parameters.
func IsSensitiveParameter(param string) bool {
	return sensitiveparameters[strings.ToLower(param)]
}