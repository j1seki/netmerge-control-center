package ttlmgr

import (
	"errors"
	"fmt"
	"strings"
)

// Error codes. They are stable strings rather than numbers so a log line, a JSON field and a
// UI message all carry the same identifier, and so a report can be grepped.
const (
	// CodeConfigUnreadable means the configuration file existed but could not be parsed.
	CodeConfigUnreadable = "ttl_config_unreadable"
	// CodeConfigInvalid means the configuration parsed but failed validation.
	CodeConfigInvalid = "ttl_config_invalid"
	// CodeUnsupported means this host has no mechanism for the requested setting.
	CodeUnsupported = "ttl_unsupported_platform"
	// CodePermission means the change was refused for lack of privileges.
	CodePermission = "ttl_permission_denied"
	// CodeReadFailed means reading a setting failed.
	CodeReadFailed = "ttl_read_failed"
	// CodeWriteFailed means writing a setting failed.
	CodeWriteFailed = "ttl_write_failed"
	// CodeVerifyFailed means the write ran without error but the value did not change. A
	// successful exit status is not evidence of success, so this is a distinct outcome.
	CodeVerifyFailed = "ttl_verify_failed"
	// CodeRollbackIncomplete means a partially applied change could not be fully undone.
	CodeRollbackIncomplete = "ttl_rollback_incomplete"
	// CodeNoCapture means a restore was asked for but nothing was captured.
	CodeNoCapture = "ttl_no_captured_originals"
	// CodeBusy means another operation holds the manager lock and the request was cancelled.
	CodeBusy = "ttl_busy"
	// CodeCancelled means the caller cancelled the operation.
	CodeCancelled = "ttl_cancelled"
	// CodeTimeout means an external command exceeded its deadline.
	CodeTimeout = "ttl_timeout"
	// CodeNoChange means the requested value already equals the current value.
	CodeNoChange = "ttl_already_at_value"
)

// Error is the error type this package returns. Every field is meant to be shown: Code and
// Message go to logs and the UI, Hint is what the user should try next, and Details carries
// the raw command output that made diagnosis possible.
type Error struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Hint    string   `json:"hint,omitempty"`
	Details []string `json:"details,omitempty"`
}

func (e *Error) Error() string {
	if len(e.Details) == 0 {
		return e.Code + ": " + e.Message
	}
	return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, strings.Join(e.Details, "; "))
}

// newError builds an Error with one detail line per argument.
func newError(code, message, hint string, details ...string) *Error {
	return &Error{Code: code, Message: message, Hint: hint, Details: details}
}

// ConfigError reports every problem found in a configuration file at once rather than the
// first, so a user fixing a hand-edited file sees the whole list.
type ConfigError struct {
	Code     string   `json:"code"`
	Problems []string `json:"problems"`
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, strings.Join(e.Problems, "; "))
}

// ErrorCode extracts the stable code from any error this package returns, using a neutral
// fallback so callers never have to handle a nil code.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	var ce *ConfigError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return "ttl_error"
}

// IsCode reports whether err carries the given code.
func IsCode(err error, code string) bool { return ErrorCode(err) == code }
