// Package audit is the one call a service makes to record who did what.
// Entries go to the audit service, which owns the append-only store;
// nothing else can write to it.
//
//	if err := recorder.Record(ctx, audit.Event{
//	    OrgID: orgID, Action: "organization.plan.changed",
//	    TargetType: "organization", TargetID: orgID,
//	    Details: map[string]any{"from": "free", "to": "team"},
//	}); err != nil {
//	    return err // a security-sensitive action that cannot be recorded does not happen
//	}
//
// The actor, the source address and the request id are taken from the
// request context, so a caller never fills them in and cannot fill them in
// wrongly.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Event is one thing that happened. Ids and values only in Details: never a
// name or an email.
type Event struct {
	OrgID      string
	Action     string
	TargetType string
	TargetID   string
	Details    map[string]any
	// Actor overrides the one from the context, for a service acting on its
	// own (a housekeeping tick). Leave empty for a request.
	Actor db.Actor
}

// Recorder records events.
type Recorder interface {
	Record(ctx context.Context, ev Event) error
}

var actionShape = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// ErrNotRecorded means the audit service refused or could not be reached.
// Callers treat it as a failure of the action being recorded.
var ErrNotRecorded = errors.New("audit: entry not recorded")

// Client records through the audit service's API, as this service.
type Client struct {
	baseURL string
	tokens  auth.TokenSource
	http    *http.Client
}

// NewClient is a recorder that posts to the audit service at baseURL (from
// configuration), authenticating with tokens.
func NewClient(baseURL string, tokens auth.TokenSource, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{baseURL: baseURL, tokens: tokens, http: client}
}

type wire struct {
	OrgID      string         `json:"org_id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	SourceIP   string         `json:"source_ip,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

// Record appends ev. It fails rather than drops: an audit entry that could
// not be written is the caller's error to handle, usually by failing the
// action.
func (c *Client) Record(ctx context.Context, ev Event) error {
	body, err := c.encode(ctx, ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/audit/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRecorded, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var envelope httpx.Error
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&envelope)
		return fmt.Errorf("%w: audit service answered %d %s", ErrNotRecorded, resp.StatusCode, envelope.Code)
	}
	return nil
}

func (c *Client) encode(ctx context.Context, ev Event) ([]byte, error) {
	if ev.OrgID == "" || !actionShape.MatchString(ev.Action) || ev.TargetType == "" || ev.TargetID == "" {
		return nil, fmt.Errorf("audit: event needs an org, a dotted action, a target type and a target id")
	}
	actor := ev.Actor
	if actor == "" {
		a, ok := db.ActorFrom(ctx)
		if !ok {
			return nil, fmt.Errorf("audit: no actor in context and none given")
		}
		actor = a
	}
	info := httpx.RequestInfoFrom(ctx)
	return json.Marshal(wire{
		OrgID: ev.OrgID, Actor: string(actor), Action: ev.Action,
		TargetType: ev.TargetType, TargetID: ev.TargetID,
		SourceIP: info.ClientIP, RequestID: info.ID, Details: ev.Details,
	})
}

// Discard records nothing, for tests of code that audits.
type Discard struct{}

// Record does nothing.
func (Discard) Record(context.Context, Event) error { return nil }
