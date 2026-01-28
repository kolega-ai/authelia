package authentication

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
)

// ValidationContext provides context for password validation.
type ValidationContext struct {
	Username    string
	OldPassword string
}

// PasswordValidator validates passwords according to configured policy.
type PasswordValidator struct {
	policy          *schema.AuthenticationBackendFilePasswordPolicy
	commonPasswords map[string]bool
	weakPatterns    []*regexp.Regexp
}

// NewPasswordValidator creates a new password validator with the given policy.
func NewPasswordValidator(policy *schema.AuthenticationBackendFilePasswordPolicy) (*PasswordValidator, error) {
	if policy == nil {
		policy = &schema.DefaultPasswordPolicyConfig
	}

	validator := &PasswordValidator{
		policy:          policy,
		commonPasswords: loadCommonPasswords(),
		weakPatterns:    compileWeakPatterns(),
	}

	return validator, nil
}

// Validate checks if a password meets the configured policy requirements.
func (v *PasswordValidator) Validate(password string, ctx ValidationContext) error {
	var violations []string

	// Basic length validation
	if len(password) < v.policy.MinLength {
		violations = append(violations, fmt.Sprintf("minimum %d characters required", v.policy.MinLength))
	}

	if len(password) > v.policy.MaxLength {
		violations = append(violations, fmt.Sprintf("maximum %d characters allowed", v.policy.MaxLength))
	}

	// Character class requirements
	if v.policy.RequireUppercase && !v.hasUppercase(password) {
		violations = append(violations, "uppercase letter required")
	}

	if v.policy.RequireLowercase && !v.hasLowercase(password) {
		violations = append(violations, "lowercase letter required")
	}

	if v.policy.RequireNumber && !v.hasNumber(password) {
		violations = append(violations, "number required")
	}

	if v.policy.RequireSpecial && !v.hasSpecial(password) {
		violations = append(violations, "special character required")
	}

	// Check against common passwords
	if v.policy.CheckCommonPasswords && v.isCommonPassword(password) {
		violations = append(violations, "password is too common")
	}

	// Check for weak patterns
	if v.hasWeakPatterns(password) {
		violations = append(violations, "password contains weak patterns")
	}

	// Check similarity to username
	if v.isSimilarToUsername(password, ctx.Username) {
		violations = append(violations, "password too similar to username")
	}

	// Calculate strength score
	score := v.calculateStrengthScore(password)
	if score < v.policy.MinScore {
		violations = append(violations, fmt.Sprintf("password strength insufficient (score: %d, required: %d)", score, v.policy.MinScore))
	}

	// Log detailed violations for debugging (without the actual password)
	if len(violations) > 0 {
		logging.Logger().WithField("username", ctx.Username).WithField("violations", len(violations)).Debug("Password policy violations detected")
		
		// Return generic error to prevent information disclosure
		return ErrPasswordWeak
	}

	return nil
}

// hasUppercase checks if password contains uppercase letters.
func (v *PasswordValidator) hasUppercase(password string) bool {
	for _, r := range password {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// hasLowercase checks if password contains lowercase letters.
func (v *PasswordValidator) hasLowercase(password string) bool {
	for _, r := range password {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

// hasNumber checks if password contains numbers.
func (v *PasswordValidator) hasNumber(password string) bool {
	for _, r := range password {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// hasSpecial checks if password contains special characters.
func (v *PasswordValidator) hasSpecial(password string) bool {
	for _, r := range password {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// isCommonPassword checks if password is in the common passwords list.
func (v *PasswordValidator) isCommonPassword(password string) bool {
	normalized := strings.ToLower(strings.TrimSpace(password))
	return v.commonPasswords[normalized]
}

// hasWeakPatterns checks for common weak password patterns.
func (v *PasswordValidator) hasWeakPatterns(password string) bool {
	lower := strings.ToLower(password)

	// Check for sequential characters (abc, 123, etc.)
	for i := 0; i < len(password)-2; i++ {
		if len(password) > i+2 {
			if password[i]+1 == password[i+1] && password[i+1]+1 == password[i+2] {
				return true
			}
			if password[i]-1 == password[i+1] && password[i+1]-1 == password[i+2] {
				return true
			}
		}
	}

	// Check for repeated characters (aaa, 111, etc.)
	consecutiveCount := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			consecutiveCount++
			if consecutiveCount >= 3 {
				return true
			}
		} else {
			consecutiveCount = 1
		}
	}

	// Check against compiled weak patterns
	for _, pattern := range v.weakPatterns {
		if pattern.MatchString(lower) {
			return true
		}
	}

	return false
}

// isSimilarToUsername checks if password is too similar to username.
func (v *PasswordValidator) isSimilarToUsername(password, username string) bool {
	if username == "" {
		return false
	}

	lowerPass := strings.ToLower(password)
	lowerUser := strings.ToLower(username)

	// Direct containment check
	if strings.Contains(lowerPass, lowerUser) || strings.Contains(lowerUser, lowerPass) {
		return true
	}

	// Check if password is just username with numbers/symbols
	if len(lowerUser) > 3 {
		cleanPass := regexp.MustCompile(`[^a-z]`).ReplaceAllString(lowerPass, "")
		if strings.Contains(cleanPass, lowerUser) {
			return true
		}
	}

	return false
}

// calculateStrengthScore calculates a password strength score from 0-10.
func (v *PasswordValidator) calculateStrengthScore(password string) int {
	score := 0

	// Length scoring
	length := len(password)
	switch {
	case length >= 16:
		score += 3
	case length >= 12:
		score += 2
	case length >= 8:
		score += 1
	}

	// Character variety scoring
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r):
			hasSpecial = true
		}
	}

	charTypes := 0
	if hasUpper {
		charTypes++
	}
	if hasLower {
		charTypes++
	}
	if hasDigit {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	score += charTypes

	// Entropy bonus - unique character ratio
	uniqueChars := make(map[rune]bool)
	for _, r := range password {
		uniqueChars[r] = true
	}

	uniqueRatio := float64(len(uniqueChars)) / float64(len(password))
	if uniqueRatio > 0.8 {
		score += 2
	} else if uniqueRatio > 0.6 {
		score += 1
	}

	// Cap the score at 10
	if score > 10 {
		score = 10
	}

	return score
}

// loadCommonPasswords loads a list of common weak passwords.
func loadCommonPasswords() map[string]bool {
	commonPasswords := map[string]bool{
		"password":    true,
		"123456":      true,
		"password123": true,
		"admin":       true,
		"qwerty":      true,
		"letmein":     true,
		"welcome":     true,
		"monkey":      true,
		"dragon":      true,
		"master":      true,
		"hello":       true,
		"freedom":     true,
		"whatever":    true,
		"qazwsx":      true,
		"trustno1":    true,
		"654321":      true,
		"jordan23":    true,
		"harley":      true,
		"password1":   true,
		"1234":        true,
		"12345":       true,
		"123456789":   true,
		"12345678":    true,
		"1234567":     true,
		"1234567890":  true,
		"abc123":      true,
		"111111":      true,
		"1qaz2wsx":    true,
		"batman":      true,
		"pass":        true,
		"shadow":      true,
		"football":    true,
		"iloveyou":    true,
		"superman":    true,
		"michael":     true,
		"ninja":       true,
		"mustang":     true,
		"access":      true,
		"696969":      true,
		"12qwaszx":    true,
		"hunter":      true,
		"secret":      true,
		"hunter2":     true,
	}

	return commonPasswords
}

// compileWeakPatterns compiles regex patterns for common weak password patterns.
func compileWeakPatterns() []*regexp.Regexp {
	patterns := []string{
		`qwerty`,
		`asdfgh`,
		`zxcvbn`,
		`123456`,
		`654321`,
		`abcdef`,
		`fedcba`,
		`password`,
		`passw0rd`,
		`p@ssw0rd`,
		`p@ssword`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, regex)
		}
	}

	return compiled
}