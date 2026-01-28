package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeURL(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "should sanitize OAuth tokens",
			input:    "https://example.com/oauth/callback?code=secret123&access_token=bearer123&state=nonce456",
			expected: "https://example.com/oauth/callback?access_token=%5BREDACTED%5D&code=%5BREDACTED%5D&state=%5BREDACTED%5D",
		},
		{
			name:     "should sanitize passwords",
			input:    "https://example.com/login?username=user&password=secret123",
			expected: "https://example.com/login?password=%5BREDACTED%5D&username=user",
		},
		{
			name:     "should sanitize session IDs",
			input:    "https://example.com/api/data?session_id=abc123&other=value",
			expected: "https://example.com/api/data?other=value&session_id=%5BREDACTED%5D",
		},
		{
			name:     "should sanitize Authelia-specific parameters",
			input:    "https://example.com/authelia?rd=https://secret.example.com&authelia_url=portal",
			expected: "https://example.com/authelia?authelia_url=%5BREDACTED%5D&rd=%5BREDACTED%5D",
		},
		{
			name:     "should preserve non-sensitive parameters",
			input:    "https://example.com/api?user=john&page=1&limit=10",
			expected: "https://example.com/api?user=john&page=1&limit=10",
		},
		{
			name:     "should handle URLs without query parameters",
			input:    "https://example.com/api/users",
			expected: "https://example.com/api/users",
		},
		{
			name:     "should handle empty URLs",
			input:    "",
			expected: "",
		},
		{
			name:     "should handle case insensitive parameter names",
			input:    "https://example.com/api?ACCESS_TOKEN=secret&Password=secret",
			expected: "https://example.com/api?ACCESS_TOKEN=%5BREDACTED%5D&Password=%5BREDACTED%5D",
		},
		{
			name:     "should handle malformed URLs gracefully",
			input:    "not-a-valid-url?password=secret",
			expected: "not-a-valid-url?[SANITIZED]",
		},
		{
			name:     "should handle URLs with fragments",
			input:    "https://example.com/page?token=secret123#section",
			expected: "https://example.com/page?token=%5BREDACTED%5D#section",
		},
		{
			name:     "should sanitize multiple sensitive parameters",
			input:    "https://example.com/oauth?client_secret=secret&refresh_token=refresh&id_token=id&flow_id=flow123",
			expected: "https://example.com/oauth?client_secret=%5BREDACTED%5D&flow_id=%5BREDACTED%5D&id_token=%5BREDACTED%5D&refresh_token=%5BREDACTED%5D",
		},
		{
			name:     "should handle relative URLs",
			input:    "/api/login?password=secret&username=user",
			expected: "/api/login?password=%5BREDACTED%5D&username=user",
		},
		// Test case that simulates Authelia's real-world usage based on investigation
		{
			name:     "should sanitize real Authelia request paths",
			input:    "/api/oidc/authorize?client_id=myapp&response_type=code&code=auth_code_123&state=csrf_state_456&redirect_uri=https://app.example.com/callback&access_token=bearer_token_789",
			expected: "/api/oidc/authorize?access_token=%5BREDACTED%5D&client_id=myapp&code=%5BREDACTED%5D&redirect_uri=https%3A//app.example.com/callback&response_type=code&state=%5BREDACTED%5D",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeURL(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSanitizePath(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "should remove query parameters from path",
			input:    "/api/users?token=secret123&user=admin",
			expected: "/api/users",
		},
		{
			name:     "should remove fragments from path",
			input:    "/page.html#section?param=value",
			expected: "/page.html",
		},
		{
			name:     "should handle paths without query parameters",
			input:    "/api/users/123",
			expected: "/api/users/123",
		},
		{
			name:     "should handle empty paths",
			input:    "",
			expected: "",
		},
		{
			name:     "should handle root path with query",
			input:    "/?password=secret",
			expected: "/",
		},
		{
			name:     "should handle complex paths with query parameters",
			input:    "/api/v1/oauth/authorize?client_id=app&code=secret123&state=nonce",
			expected: "/api/v1/oauth/authorize",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizePath(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsSensitiveParameter(t *testing.T) {
	testCases := []struct {
		name     string
		param    string
		expected bool
	}{
		{
			name:     "should identify OAuth tokens as sensitive",
			param:    "access_token",
			expected: true,
		},
		{
			name:     "should identify passwords as sensitive",
			param:    "password",
			expected: true,
		},
		{
			name:     "should identify session IDs as sensitive",
			param:    "session_id",
			expected: true,
		},
		{
			name:     "should identify Authelia redirect as sensitive",
			param:    "rd",
			expected: true,
		},
		{
			name:     "should handle case insensitive matching",
			param:    "PASSWORD",
			expected: true,
		},
		{
			name:     "should identify non-sensitive parameters",
			param:    "username",
			expected: false,
		},
		{
			name:     "should identify non-sensitive parameters",
			param:    "page",
			expected: false,
		},
		{
			name:     "should handle empty parameter names",
			param:    "",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsSensitiveParameter(tc.param)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSensitiveParametersMap(t *testing.T) {
	// Test that all expected sensitive parameters are included
	expectedSensitive := []string{
		"access_token", "refresh_token", "id_token", "client_secret", "code",
		"authorization_code", "state", "token", "consent_id", "flow_id",
		"password", "passwd", "pwd", "secret", "key", "session_id",
		"sessionid", "auth", "api_key", "apikey", "csrf_token", "nonce",
		"rd", "authelia_url", "authorization", "bearer",
	}

	for _, param := range expectedSensitive {
		t.Run("should mark "+param+" as sensitive", func(t *testing.T) {
			assert.True(t, sensitiveparameters[param], "Parameter %s should be marked as sensitive", param)
		})
	}

	// Test that some common non-sensitive parameters are not included
	expectedNonSensitive := []string{
		"username", "user", "page", "limit", "offset", "sort", "order",
		"filter", "search", "id", "name", "email", "type", "status",
	}

	for _, param := range expectedNonSensitive {
		t.Run("should not mark "+param+" as sensitive", func(t *testing.T) {
			assert.False(t, sensitiveparameters[param], "Parameter %s should not be marked as sensitive", param)
		})
	}
}