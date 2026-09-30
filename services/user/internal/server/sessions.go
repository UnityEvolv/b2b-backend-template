package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Sessions is what this service needs of the identity service: to say a
// membership ended, so every session carrying it moves or ends at once and
// the person's open sockets in that org are told. Without it, a
// deactivated person keeps working until their next token refresh.
type Sessions interface {
	MembershipEnded(ctx context.Context, orgID, membershipID, userID uuid.UUID, reason string) error
}

type httpSessions struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewSessions is a Sessions over the identity service at baseURL.
func NewSessions(baseURL string, tokens auth.TokenSource, client *http.Client) Sessions {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpSessions{base: baseURL, tokens: tokens, http: client}
}

func (s *httpSessions) MembershipEnded(ctx context.Context, orgID, membershipID, userID uuid.UUID, reason string) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(map[string]any{"org_id": orgID, "membership_id": membershipID, "user_id": userID, "reason": reason}); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/v1/internal/memberships/ended", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", uuid.NewString())
	if err := auth.Authorize(ctx, s.tokens, req); err != nil {
		return err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("identity service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("identity service answered %d", resp.StatusCode)
	}
	return nil
}

// Invites is what the bulk import needs of the identity service: an invite
// per valid row.
type Invites interface {
	CreateInvite(ctx context.Context, in NewInvite) error
}

// NewInvite is what the identity service's internal invite endpoint takes.
type NewInvite struct {
	OrgID                 uuid.UUID  `json:"org_id"`
	Email                 string     `json:"email"`
	Role                  string     `json:"role"`
	InvitedByMembershipID *uuid.UUID `json:"invited_by_membership_id,omitempty"`
}

// InviteRefusal is the identity service saying no to one invite.
type InviteRefusal struct {
	Status int
	Code   string
}

func (r *InviteRefusal) Error() string {
	return fmt.Sprintf("identity service refused: %d %s", r.Status, r.Code)
}

func (s *httpSessions) CreateInvite(ctx context.Context, in NewInvite) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/v1/internal/invites", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", uuid.NewString())
	if err := auth.Authorize(ctx, s.tokens, req); err != nil {
		return err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("identity service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return &InviteRefusal{Status: resp.StatusCode, Code: e.Code}
	}
	return nil
}

// NewInvites is an Invites over the identity service at baseURL.
func NewInvites(baseURL string, tokens auth.TokenSource, client *http.Client) Invites {
	return NewSessions(baseURL, tokens, client).(*httpSessions)
}

// membershipEnded tells the identity service. A failure is logged, not
// returned: the membership has already changed, and the next token refresh
// notices on its own within one access token's life. What is lost is only
// the immediacy, and that is logged loudly rather than silently.
func (s *Server) membershipEnded(ctx context.Context, orgID, membershipID, userID uuid.UUID, reason string) {
	if s.sessions == nil {
		return
	}
	if err := s.sessions.MembershipEnded(ctx, orgID, membershipID, userID, reason); err != nil {
		s.logger.Error("could not end the sessions of a membership", "error", err, "org_id", orgID, "membership_id", membershipID)
	}
}
