// Package httpx is the HTTP plumbing every service shares: the error
// envelope, health checks, request logging and a server that shuts down
// cleanly.
package httpx

import (
	"encoding/json"
	"net/http"
)

// Error is the one error envelope every endpoint returns.
//
// Code is stable and is what clients branch on; Message is for a person and is
// never parsed. Fields names the inputs that were wrong, when there were any.
type Error struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// Stable codes shared by every service. A service adds its own, namespaced by
// resource: "organization.not_found".
const (
	CodeInvalidRequest   = "invalid_request"
	CodeUnauthenticated  = "unauthenticated"
	CodeForbidden        = "forbidden"
	CodeNotFound         = "not_found"
	CodeConflict         = "conflict"
	CodeRateLimited      = "rate_limited"
	CodeInternal         = "internal"
	CodeUnavailable      = "unavailable"
	CodeMethodNotAllowed = "method_not_allowed"
)

// WriteJSON writes body as JSON with status.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteError writes the error envelope with status.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, Error{Code: code, Message: message})
}

// WriteFieldErrors writes an invalid_request envelope naming the bad fields.
func WriteFieldErrors(w http.ResponseWriter, message string, fields map[string]string) {
	WriteJSON(w, http.StatusBadRequest, Error{Code: CodeInvalidRequest, Message: message, Fields: fields})
}
