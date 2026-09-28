// Package email is the one call a service makes to send mail (UO-112).
//
//	err := sender.Send(ctx, email.Message{
//	    OrgID: orgID, OrgName: "Acme", To: address, Template: "notice",
//	    Data: map[string]any{"heading": "You were invited", "lines": []string{"…"}},
//	})
//
// The notification service renders the template, queues the mail in its
// outbox and delivers it with retries. Send returns once it is queued; a
// queued mail is delivered or ends up failed and visible, never dropped.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Message is one email to queue.
type Message struct {
	OrgID    string
	OrgName  string
	To       string
	Template string
	Data     map[string]any
}

// Sender queues messages.
type Sender interface {
	Send(ctx context.Context, m Message) (Queued, error)
}

// Queued is what the outbox knows about a message.
type Queued struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// ErrNotQueued means the notification service refused or could not be reached.
var ErrNotQueued = errors.New("email: not queued")

// Validate checks a message before it leaves the caller.
func (m Message) Validate() error {
	if m.OrgID == "" || m.OrgName == "" || m.Template == "" {
		return errors.New("email: an org id, an org name and a template are required")
	}
	if _, err := mail.ParseAddress(m.To); err != nil {
		return fmt.Errorf("email: not an address: %w", err)
	}
	if _, ok := Templates[m.Template]; !ok {
		return fmt.Errorf("email: no template %q", m.Template)
	}
	return nil
}

// Client queues through the notification service's API, as this service.
type Client struct {
	baseURL string
	tokens  auth.TokenSource
	http    *http.Client
}

// NewClient is a sender that posts to the notification service at baseURL.
func NewClient(baseURL string, tokens auth.TokenSource, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{baseURL: baseURL, tokens: tokens, http: client}
}

// Send queues m.
func (c *Client) Send(ctx context.Context, m Message) (Queued, error) {
	if err := m.Validate(); err != nil {
		return Queued{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"org_id": m.OrgID, "org_name": m.OrgName, "to": m.To, "template": m.Template, "data": m.Data,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/internal/emails", bytes.NewReader(body))
	if err != nil {
		return Queued{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return Queued{}, fmt.Errorf("%w: %v", ErrNotQueued, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Queued{}, fmt.Errorf("%w: %v", ErrNotQueued, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		var envelope httpx.Error
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&envelope)
		return Queued{}, fmt.Errorf("%w: notification service answered %d %s", ErrNotQueued, resp.StatusCode, envelope.Code)
	}
	var q Queued
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&q); err != nil {
		return Queued{}, fmt.Errorf("%w: unreadable answer", ErrNotQueued)
	}
	return q, nil
}

// Discard queues nothing, for tests of code that sends mail.
type Discard struct{}

// Send does nothing.
func (Discard) Send(context.Context, Message) (Queued, error) { return Queued{State: "queued"}, nil }
