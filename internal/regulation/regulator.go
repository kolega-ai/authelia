package regulation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
	"github.com/authelia/authelia/v4/internal/utils"
)

// NewRegulator create a regulator instance.
func NewRegulator(config schema.Regulation, store storage.RegulatorProvider, clock clock.Provider) *Regulator {
	return &Regulator{
		users:  config.MaxRetries > 0 && utils.IsStringInSlice(typeUser, config.Modes),
		ips:    config.MaxRetries > 0 && utils.IsStringInSlice(typeIP, config.Modes),
		store:  store,
		clock:  clock,
		config: config,
	}
}

func (r *Regulator) HandleAttempt(ctx Context, successful, banned bool, username, requestURI, requestMethod, authType string) {
	ctx.RecordAuthn(successful, banned, strings.ToLower(authType))

	attempt := model.AuthenticationAttempt{
		Time:          r.clock.Now(),
		Successful:    successful,
		Banned:        banned,
		Username:      username,
		Type:          authType,
		RemoteIP:      model.NewNullIP(ctx.RemoteIP()),
		RequestURI:    requestURI,
		RequestMethod: requestMethod,
	}

	// Enhanced authentication logging with robust error handling
	if err := r.logAuthenticationAttemptRobustly(ctx, attempt, authType, username, successful); err != nil {
		// Log the error but continue processing - authentication flow should not be blocked
		// unless it's a critical logging failure that indicates a severe security issue
		ctx.GetLogger().WithFields(map[string]any{
			fieldUsername: username,
			"successful":  successful,
			"error_type":  classifyLoggingError(err),
		}).WithError(err).Errorf("Authentication logging experienced degraded operation for %s authentication attempt", authType)
	}

	// We only need to perform the ban checks when; the attempt is unsuccessful, there is not an effective ban in place,
	// regulation is enabled, and the authentication type is 1FA. Thus if this is not the case we can return here.
	if successful || banned || (!r.ips && !r.users) || authType != AuthType1FA {
		return
	}

	since := r.clock.Now().Add(-r.config.FindTime)

	r.handleAttemptPossibleBannedIP(ctx, since)
	r.handleAttemptPossibleBannedUser(ctx, since, username)
}

func (r *Regulator) handleAttemptPossibleBannedIP(ctx Context, since time.Time) {
	if !r.ips {
		return
	}

	var (
		records []model.RegulationRecord
		err     error
	)

	ip := model.NewIP(ctx.RemoteIP())

	log := ctx.GetLogger()

	if records, err = r.store.LoadRegulationRecordsByIP(ctx, ip, since, r.config.MaxRetries); err != nil {
		log.WithFields(map[string]any{fieldRecordType: typeIP}).WithError(err).Error("Failed to load regulation records")

		return
	}

	banexp := r.expires(since, records)

	if banexp == nil {
		return
	}

	sqlban := &model.BannedIP{
		Expires: sql.NullTime{Valid: true, Time: *banexp},
		IP:      ip,
		Source:  "regulation",
		Reason:  sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
	}

	if err = r.store.SaveBannedIP(ctx, sqlban); err != nil {
		log.WithFields(map[string]any{fieldBanType: typeIP}).WithError(err).Error("Failed to save ban")

		return
	}
}

func (r *Regulator) handleAttemptPossibleBannedUser(ctx Context, since time.Time, username string) {
	if !r.users || username == "" {
		return
	}

	var (
		records []model.RegulationRecord
		err     error
	)

	log := ctx.GetLogger()

	if records, err = r.store.LoadRegulationRecordsByUser(ctx, username, since, r.config.MaxRetries); err != nil {
		log.WithFields(map[string]any{fieldRecordType: typeUser, fieldUsername: username}).WithError(err).Error("Failed to load regulation records")

		return
	}

	banexp := r.expires(since, records)

	if banexp == nil {
		return
	}

	sqlban := &model.BannedUser{
		Expires:  sql.NullTime{Valid: true, Time: *banexp},
		Username: username,
		Source:   "regulation",
		Reason:   sql.NullString{Valid: true, String: "Exceeding Maximum Retries"},
	}

	if err = r.store.SaveBannedUser(ctx, sqlban); err != nil {
		log.WithFields(map[string]any{fieldBanType: typeUser, fieldUsername: username}).WithError(err).Error("Failed to save ban")

		return
	}
}

func (r *Regulator) BanCheck(ctx Context, username string) (ban BanType, value string, expires *time.Time, err error) {
	ip := model.NewIP(ctx.RemoteIP())

	var bansIP []model.BannedIP

	if bansIP, err = r.store.LoadBannedIP(ctx, ip); err != nil {
		return BanTypeNone, "", nil, err
	}

	if len(bansIP) != 0 {
		b := bansIP[0]

		return returnBanResult(BanTypeIP, ip.String(), b.Expires)
	}

	var bansUser []model.BannedUser

	if bansUser, err = r.store.LoadBannedUser(ctx, username); err != nil {
		return BanTypeNone, "", nil, err
	}

	if len(bansUser) != 0 {
		b := bansUser[0]

		return returnBanResult(BanTypeUser, username, b.Expires)
	}

	return BanTypeNone, "", nil, nil
}

func (r *Regulator) expires(since time.Time, records []model.RegulationRecord) *time.Time {
	failures := make([]model.RegulationRecord, 0, len(records))

loop:
	for _, record := range records {
		switch {
		case record.Successful:
			break loop
		case len(failures) >= r.config.MaxRetries:
			continue
		case record.Time.Before(since):
			continue
		default:
			// We stop appending failed attempts once we find the first successful attempts or we reach
			// the configured number of retries, meaning the user is already banned.
			failures = append(failures, record)
		}
	}

	// If the number of failed attempts within the ban time is less than the max number of retries
	// then the user is not banned.
	if len(failures) < r.config.MaxRetries {
		return nil
	}

	expires := failures[0].Time.Add(r.config.BanTime)

	return &expires
}

// logAuthenticationAttemptRobustly implements robust authentication logging with retry mechanisms
// and fallback strategies to address CWE-778 (Insufficient Error Handling in Authentication Logging).
func (r *Regulator) logAuthenticationAttemptRobustly(ctx Context, attempt model.AuthenticationAttempt, authType, username string, successful bool) error {
	// Attempt primary logging with retry logic for transient failures
	var lastErr error
	err := utils.RunFuncWithRetry(3, 100*time.Millisecond, func() error {
		lastErr = r.store.AppendAuthenticationLog(ctx, attempt)
		// Only retry on transient errors
		if lastErr != nil && classifyLoggingError(lastErr) == "transient" {
			return lastErr
		}
		// For persistent errors or success, don't retry
		return nil
	})

	// Use the actual database error for analysis, not the retry wrapper error
	if lastErr != nil {
		err = lastErr
	}

	if err == nil {
		return nil
	}

	// Classify the error to determine appropriate handling strategy
	errorType := classifyLoggingError(err)
	logger := ctx.GetLogger().WithFields(map[string]any{
		fieldUsername:  username,
		"successful":   successful,
		"auth_type":    authType,
		"error_type":   errorType,
		"remote_ip":    attempt.RemoteIP,
		"request_uri":  attempt.RequestURI,
	})

	// For transient errors, we've already retried - log the persistent failure
	if errorType == "transient" {
		logger.WithError(err).Warning("Authentication logging failed after retries - transient database issue detected")
	} else {
		logger.WithError(err).Error("Authentication logging failed - persistent database issue detected")
	}

	// Attempt fallback logging to ensure audit trail continuity
	fallbackErr := r.fallbackAuthenticationLog(ctx, attempt, authType)
	if fallbackErr == nil {
		logger.Info("Authentication attempt successfully logged to fallback storage")
		return nil
	}

	// If even fallback logging fails, this indicates a critical system issue
	logger.WithError(fallbackErr).Error("Critical: Both primary and fallback authentication logging failed")

	// For critical security logging failures, we still continue the authentication flow
	// but ensure the failure is properly escalated for monitoring/alerting
	return fmt.Errorf("authentication logging failure: primary error: %w, fallback error: %v", err, fallbackErr)
}

// fallbackAuthenticationLog provides file-based fallback logging for authentication attempts
// when primary database logging fails, ensuring audit trail continuity.
func (r *Regulator) fallbackAuthenticationLog(ctx Context, attempt model.AuthenticationAttempt, authType string) error {
	// Create fallback log directory if it doesn't exist
	fallbackDir := "/var/log/authelia/auth-fallback"
	if err := os.MkdirAll(fallbackDir, 0700); err != nil {
		return fmt.Errorf("failed to create fallback log directory: %w", err)
	}

	// Create date-based log file with secure permissions
	logFileName := fmt.Sprintf("auth-fallback-%s.log", attempt.Time.Format("2006-01-02"))
	logFilePath := filepath.Join(fallbackDir, logFileName)

	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open fallback log file: %w", err)
	}
	defer logFile.Close()

	// Create structured log entry with all critical authentication information
	logEntry := map[string]any{
		"timestamp":       attempt.Time.Format(time.RFC3339Nano),
		"successful":      attempt.Successful,
		"banned":          attempt.Banned,
		"username":        attempt.Username,
		"auth_type":       authType,
		"remote_ip":       attempt.RemoteIP,
		"request_uri":     attempt.RequestURI,
		"request_method":  attempt.RequestMethod,
		"fallback_reason": "primary_logging_failure",
		"context": map[string]any{
			"remote_ip_raw": ctx.RemoteIP().String(),
		},
	}

	// Write JSON-formatted log entry
	encoder := json.NewEncoder(logFile)
	if err := encoder.Encode(logEntry); err != nil {
		return fmt.Errorf("failed to write fallback log entry: %w", err)
	}

	// Force synchronization to disk to ensure data persistence
	if err := logFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync fallback log file: %w", err)
	}

	return nil
}

// classifyLoggingError determines whether a logging error is transient (suitable for retry)
// or persistent (requiring alternative handling strategies).
func classifyLoggingError(err error) string {
	if err == nil {
		return "none"
	}

	errStr := strings.ToLower(err.Error())

	// Transient errors that may resolve with retry
	transientIndicators := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"too many connections",
		"connection lost",
		"network unreachable",
		"connection timed out",
		"deadlock",
		"lock wait timeout",
	}

	for _, indicator := range transientIndicators {
		if strings.Contains(errStr, indicator) {
			return "transient"
		}
	}

	// Check for specific network-related errors
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return "transient"
	}

	// Check for specific system call errors that might be transient
	if err == syscall.ECONNREFUSED || err == syscall.ECONNRESET || err == syscall.ETIMEDOUT {
		return "transient"
	}

	// Persistent errors that require alternative strategies
	persistentIndicators := []string{
		"permission denied",
		"no space left on device",
		"read-only file system",
		"disk full",
		"database is locked",
		"constraint violation",
		"invalid syntax",
		"table doesn't exist",
		"column doesn't exist",
	}

	for _, indicator := range persistentIndicators {
		if strings.Contains(errStr, indicator) {
			return "persistent"
		}
	}

	// Default to persistent for unknown errors to trigger appropriate handling
	return "persistent"
}
