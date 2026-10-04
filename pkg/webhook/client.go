package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Message is one event a service sends to an org's endpoints.
type Message struct {
	// ID makes the send idempotent: a second message with the same id is
	// the same event and is not delivered again. Leave empty for a fresh
	// one. A UUID.
	ID string `json:"id,omitempty"`
	// Type is a registered event type.
	Type Type `json:"type"`
	// OccurredAt is when it happened, if not now.
	OccurredAt time.Time `json:"occurred_at,omitzero"`
	// Data is the event's own payload: ids and values, never a name or an
	// email (CheckData).
	Data map[string]any `json:"data"`
}

// Payload is the body of every delivery, as a receiver reads it.
type Payload struct {
	// ID is the message id, also in the webhook-id header.
	ID         string         `json:"id"`
	Type       Type           `json:"type"`
	OrgID      string         `json:"org_id"`
	OccurredAt time.Time      `json:"occurred_at"`
	Data       map[string]any `json:"data"`
}

// Emitter sends events.
type Emitter interface {
	Emit(ctx context.Context, orgID string, m Message) error
}

// Discard sends nothing: a service with no webhooks service, and tests.
type Discard struct{}

// Emit does nothing.
func (Discard) Emit(context.Context, string, Message) error { return nil }

// ErrRefused is the webhooks service refusing a message: a type nobody
// registered, data that names a person, or the org over its cap.
var ErrRefused = errors.New("webhook: message refused")

// Client sends events through the webhooks service's internal API, as this
// service.
type Client struct {
	baseURL string
	tokens  auth.TokenSource
	http    *http.Client
}

// NewClient is an emitter over the webhooks service at baseURL
// (WEBHOOKS_URL), authenticating with tokens.
func NewClient(baseURL string, tokens auth.TokenSource, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{baseURL: baseURL, tokens: tokens, http: client}
}

// Emit sends m to orgID's endpoints that subscribe to its type. The
// webhooks service records a delivery per endpoint before it answers and
// attempts them at once, off this call's path; nothing is queued here.
func (c *Client) Emit(ctx context.Context, orgID string, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/internal/organizations/"+orgID+"/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: emit: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	var envelope httpx.Error
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&envelope)
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w: %d %s: %s", ErrRefused, resp.StatusCode, envelope.Code, envelope.Message)
	}
	return fmt.Errorf("webhook: emit: webhooks service answered %d %s", resp.StatusCode, envelope.Code)
}
