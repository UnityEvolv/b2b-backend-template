package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// The template's services over HTTP, each call with this service's own
// token. The template's services accept it because the product is a data
// owner there (DATA_OWNERS), which is what makes "projects" a known service.

type caller struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

func (c caller) do(ctx context.Context, method, path string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.base, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return nil, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	return c.http.Do(req)
}

func newCaller(base string, tokens auth.TokenSource) caller {
	return caller{base: base, tokens: tokens, http: &http.Client{Timeout: 5 * time.Second}}
}

// UserService is Members over the user service at base.
type UserService struct{ c caller }

// NewUserService is the user service at base, asked with tokens.
func NewUserService(base string, tokens auth.TokenSource) *UserService {
	return &UserService{c: newCaller(base, tokens)}
}

// Get is one membership of org.
func (u *UserService) Get(ctx context.Context, org, membership uuid.UUID) (Member, error) {
	resp, err := u.c.do(ctx, http.MethodGet, "/v1/organizations/"+org.String()+"/memberships/"+membership.String(), nil)
	if err != nil {
		return Member{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Member{}, ErrNoMember
	default:
		return Member{}, fmt.Errorf("user service answered %d", resp.StatusCode)
	}
	var body struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
		User   struct {
			ID uuid.UUID `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Member{}, err
	}
	return Member{ID: body.ID, UserID: body.User.ID, Status: body.Status}, nil
}

// NotificationService is Notifier over the notification service's intake
// at base: the same intake as its Redis channel, but answered, so an event
// it cannot route is an error here rather than a line in its log.
type NotificationService struct{ c caller }

// NewNotificationService is the notification service at base.
func NewNotificationService(base string, tokens auth.TokenSource) *NotificationService {
	return &NotificationService{c: newCaller(base, tokens)}
}

// Notify hands n to the notification service.
func (s *NotificationService) Notify(ctx context.Context, n Notice) error {
	resp, err := s.c.do(ctx, http.MethodPost, "/v1/internal/events", n)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		var e httpx.Error
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		return fmt.Errorf("notification service answered %d %s: %s", resp.StatusCode, e.Code, e.Message)
	}
	return nil
}
