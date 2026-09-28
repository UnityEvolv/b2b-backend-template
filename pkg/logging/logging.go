// Package logging is the one way a service logs: structured JSON on stdout,
// every line tagged with the service name.
//
// No PII in logs. User and membership ids are fine; names and emails are not.
// Log ids, never structs that carry a person.
package logging

import (
	"log/slog"
	"os"
	"strings"

	"github.com/UnityEvolv/b2b-backend-template/pkg/errtrack"
)

// New is the service's logger at level ("debug", "info", "warn", "error").
func New(service, level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	// Errors (and warnings marked alert=true) also go to error tracking, when
	// it is on. Everything still lands on stdout.
	handler := errtrack.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
	return slog.New(handler).With("service", service)
}
