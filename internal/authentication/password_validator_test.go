package authentication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestPasswordValidator_Validate(t *testing.T) {
	// Use default policy for most tests
	policy := schema.DefaultPasswordPolicyConfig
	validator, err := NewPasswordValidator(&policy)
	require.NoError(t, err)

	ctx := ValidationContext{
		Username:    "testuser",
		OldPassword: "oldPassword123",
	}

	testCases := []struct {
		name        string
		password    string
		expectError bool
		description string
	}{
		{
			name:        "ValidPasswordStrong",
			password:    "MySecure123!",
			expectError: false,
			description: "Strong password with all character types",
		},
		{
			name:        "ValidPasswordLong",
			password:    "MyVeryLongSecurePassword2023!",
			expectError: false,
			description: "Long password with good strength",
		},
		{
			name:        "TooShort",
			password:    "Ab1!",
			expectError: true,
			description: "Password too short (4 chars, minimum 8)",
		},
		{
			name:        "NoUppercase",
			password:    "mysecure123!",
			expectError: true,
			description: "Missing uppercase letter",
		},
		{
			name:        "NoLowercase",
			password:    "MYSECURE123!",
			expectError: true,
			description: "Missing lowercase letter",
		},
		{
			name:        "NoNumbers",
			password:    "MySecurePass!",
			expectError: true,
			description: "Missing numbers",
		},
		{
			name:        "CommonPassword",
			password:    "password123",
			expectError: true,
			description: "Common weak password",
		},
		{
			name:        "CommonPassword2",
			password:    "Password123",
			expectError: true,
			description: "Common password (case insensitive check)",
		},
		{
			name:        "SimilarToUsername",
			password:    "testuser123",
			expectError: true,
			description: "Password contains username",
		},
		{
			name:        "SequentialChars",
			password:    "MySecure123abc",
			expectError: true,
			description: "Contains sequential characters",
		},
		{
			name:        "RepeatedChars",
			password:    "MySecure111!",
			expectError: true,
			description: "Contains repeated characters",
		},
		{
			name:        "WeakPattern",
			password:    "MyQwerty1!",
			expectError: true,
			description: "Contains weak pattern (qwerty)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.password, ctx)
			if tc.expectError {
				assert.Error(t, err, "Expected error for: %s", tc.description)
				assert.ErrorIs(t, err, ErrPasswordWeak, "Should return ErrPasswordWeak")
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tc.description)
			}
		})
	}
}

func TestPasswordValidator_CustomPolicy(t *testing.T) {
	// Test with more restrictive policy
	policy := schema.AuthenticationBackendFilePasswordPolicy{
		MinLength:            12,
		MaxLength:            20,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireNumber:        true,
		RequireSpecial:       true,
		MinScore:             5,
		CheckCommonPasswords: true,
	}

	validator, err := NewPasswordValidator(&policy)
	require.NoError(t, err)

	ctx := ValidationContext{
		Username:    "testuser",
		OldPassword: "oldPassword123",
	}

	testCases := []struct {
		name        string
		password    string
		expectError bool
		description string
	}{
		{
			name:        "MeetsRestrictivePolicy",
			password:    "MySecure123!@#",
			expectError: false,
			description: "Meets all restrictive requirements",
		},
		{
			name:        "TooShortForPolicy",
			password:    "MySecur1!",
			expectError: true,
			description: "Too short for restrictive policy (9 chars, need 12)",
		},
		{
			name:        "TooLongForPolicy",
			password:    "MyVeryVeryLongSecurePassword123!@#$",
			expectError: true,
			description: "Too long for policy (34 chars, max 20)",
		},
		{
			name:        "NoSpecialChar",
			password:    "MySecure1234",
			expectError: true,
			description: "Missing special character required by policy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.Validate(tc.password, ctx)
			if tc.expectError {
				assert.Error(t, err, "Expected error for: %s", tc.description)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tc.description)
			}
		})
	}
}

func TestPasswordValidator_PermissivePolicy(t *testing.T) {
	// Test with more permissive policy
	policy := schema.AuthenticationBackendFilePasswordPolicy{
		MinLength:            6,
		MaxLength:            128,
		RequireUppercase:     false,
		RequireLowercase:     false,
		RequireNumber:        false,
		RequireSpecial:       false,
		MinScore:             1,
		CheckCommonPasswords: false,
	}

	validator, err := NewPasswordValidator(&policy)
	require.NoError(t, err)

	ctx := ValidationContext{
		Username:    "testuser",
		OldPassword: "oldPassword123",
	}

	// Even common passwords should be allowed with permissive policy
	err = validator.Validate("password", ctx)
	assert.NoError(t, err, "Should allow common password with permissive policy")

	// But still enforce minimum length
	err = validator.Validate("abc", ctx)
	assert.Error(t, err, "Should still enforce minimum length")
}

func TestPasswordValidator_ScoreCalculation(t *testing.T) {
	validator, err := NewPasswordValidator(&schema.DefaultPasswordPolicyConfig)
	require.NoError(t, err)

	testCases := []struct {
		password     string
		minExpected  int
		description  string
	}{
		{
			password:     "Ab1!",
			minExpected:  4, // 4 char types
			description:  "Short but diverse",
		},
		{
			password:     "AbcDefGhI123!@#",
			minExpected:  7, // Length(2) + CharTypes(4) + Entropy(1+)
			description:  "Long and diverse",
		},
		{
			password:     "aaaaaaaa",
			minExpected:  1, // Length(1) only
			description:  "Long but not diverse",
		},
		{
			password:     "MyVeryLongAndComplexPassword2023!@#$",
			minExpected:  9, // Length(3) + CharTypes(4) + Entropy(2)
			description:  "Very strong password",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			score := validator.calculateStrengthScore(tc.password)
			assert.GreaterOrEqual(t, score, tc.minExpected, 
				"Password '%s' should score at least %d, got %d", 
				tc.password, tc.minExpected, score)
			assert.LessOrEqual(t, score, 10, "Score should not exceed 10")
		})
	}
}

func TestPasswordValidator_CharacterChecks(t *testing.T) {
	validator, err := NewPasswordValidator(&schema.DefaultPasswordPolicyConfig)
	require.NoError(t, err)

	// Test individual character type checks
	assert.True(t, validator.hasUppercase("AbC"))
	assert.False(t, validator.hasUppercase("abc"))

	assert.True(t, validator.hasLowercase("aBc"))
	assert.False(t, validator.hasLowercase("ABC"))

	assert.True(t, validator.hasNumber("abc123"))
	assert.False(t, validator.hasNumber("abcdef"))

	assert.True(t, validator.hasSpecial("abc!@#"))
	assert.False(t, validator.hasSpecial("abc123"))
}

func TestPasswordValidator_WeakPatterns(t *testing.T) {
	validator, err := NewPasswordValidator(&schema.DefaultPasswordPolicyConfig)
	require.NoError(t, err)

	// Test sequential character detection
	assert.True(t, validator.hasWeakPatterns("abc123"))
	assert.True(t, validator.hasWeakPatterns("cba321"))
	assert.True(t, validator.hasWeakPatterns("MyPassword123"))

	// Test repeated character detection
	assert.True(t, validator.hasWeakPatterns("aaa"))
	assert.True(t, validator.hasWeakPatterns("password111"))
	assert.False(t, validator.hasWeakPatterns("password121"))

	// Test keyboard patterns
	assert.True(t, validator.hasWeakPatterns("qwerty"))
	assert.True(t, validator.hasWeakPatterns("MyQwertyPass"))
	assert.False(t, validator.hasWeakPatterns("MySecurePass"))
}

func TestPasswordValidator_UsernameSimilarity(t *testing.T) {
	validator, err := NewPasswordValidator(&schema.DefaultPasswordPolicyConfig)
	require.NoError(t, err)

	// Direct containment
	assert.True(t, validator.isSimilarToUsername("johndoe123", "johndoe"))
	assert.True(t, validator.isSimilarToUsername("123johndoe", "johndoe"))

	// Case insensitive
	assert.True(t, validator.isSimilarToUsername("JohnDoe123", "johndoe"))

	// Clean version contains username
	assert.True(t, validator.isSimilarToUsername("john!@#doe123", "johndoe"))

	// Not similar
	assert.False(t, validator.isSimilarToUsername("MySecurePass123", "johndoe"))
	assert.False(t, validator.isSimilarToUsername("password", ""))
}

func TestPasswordValidator_CommonPasswords(t *testing.T) {
	validator, err := NewPasswordValidator(&schema.DefaultPasswordPolicyConfig)
	require.NoError(t, err)

	commonPasswords := []string{
		"password",
		"123456",
		"password123",
		"admin",
		"qwerty",
		"Password", // Case insensitive
		"PASSWORD", // Case insensitive
	}

	for _, password := range commonPasswords {
		assert.True(t, validator.isCommonPassword(password), 
			"'%s' should be detected as common password", password)
	}

	// Not common passwords
	notCommonPasswords := []string{
		"MySecurePassword2023!",
		"UnlikelyPassword789$",
		"ComplexP@ssw0rd",
	}

	for _, password := range notCommonPasswords {
		assert.False(t, validator.isCommonPassword(password), 
			"'%s' should not be detected as common password", password)
	}
}

func TestPasswordValidator_NilPolicy(t *testing.T) {
	// Test with nil policy - should use defaults
	validator, err := NewPasswordValidator(nil)
	require.NoError(t, err)

	ctx := ValidationContext{
		Username: "testuser",
	}

	// Should use default policy
	err = validator.Validate("MySecure123", ctx)
	assert.NoError(t, err)

	err = validator.Validate("weak", ctx)
	assert.Error(t, err)
}