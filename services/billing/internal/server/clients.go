package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
)

// Orgs is what billing needs of the organization service: the plan as it
// stands, moving it, and the org's name for the provider's customer.
type Orgs interface {
	Band(ctx context.Context, org uuid.UUID) (plan.Band, error)
	SetPlan(ctx context.Context, org uuid.UUID, band plan.Band, reason string) error
	Name(ctx context.Context, org uuid.UUID) (string, error)
}

// Members is the org's active member count, from the user service.
type Members interface {
	Active(ctx context.Context, org uuid.UUID) (int, error)
}

// Notice is an event for the notification service: every Owner, Admin and
// Billing Admin, by email and in the feed.
type Notice struct {
	ID       string         `json:"id"`
	OrgID    string         `json:"org_id"`
	Kind     string         `json:"kind"`
	Category string         `json:"category"`
	Audience string         `json:"audience"`
	Link     string         `json:"link"`
	Data     map[string]any `json:"data"`
}

// Notifier hands notices to the notification service.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// RedisNotifier publishes on the notification service's channel,
// config.Redis.Notify.
type RedisNotifier struct {
	Client  *redis.Client
	Channel string
}

// Notify publishes n.
func (r RedisNotifier) Notify(ctx context.Context, n Notice) error {
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return r.Client.Publish(ctx, r.Channel, raw).Err()
}

// Services is Orgs and Members over HTTP, with this service's own token.
type Services struct {
	Organization, User string
	Tokens             auth.TokenSource
	HTTP               *http.Client
	plans              plan.Source
}

// NewServices is the organization and user services at their base URLs.
func NewServices(organization, user string, tokens auth.TokenSource) *Services {
	return &Services{Organization: strings.TrimRight(organization, "/"), User: strings.TrimRight(user, "/"), Tokens: tokens,
		HTTP: &http.Client{Timeout: 15 * time.Second}, plans: plan.Client(organization, tokens, nil)}
}

func (s *Services) do(ctx context.Context, method, u string, body, out any) (int, error) {
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := auth.Authorize(ctx, s.Tokens, req); err != nil {
		return 0, err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

func (s *Services) Band(ctx context.Context, org uuid.UUID) (plan.Band, error) {
	return s.plans.Band(ctx, org.String())
}

func (s *Services) SetPlan(ctx context.Context, org uuid.UUID, band plan.Band, reason string) error {
	status, err := s.do(ctx, http.MethodPut, fmt.Sprintf("%s/v1/internal/organizations/%s/plan", s.Organization, org), map[string]string{"plan": string(band), "reason": reason}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("organization service answered %d setting the plan", status)
	}
	return nil
}

func (s *Services) Name(ctx context.Context, org uuid.UUID) (string, error) {
	var o struct {
		Name string `json:"name"`
	}
	status, err := s.do(ctx, http.MethodGet, fmt.Sprintf("%s/v1/internal/organizations/%s", s.Organization, org), nil, &o)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("organization service answered %d", status)
	}
	return o.Name, nil
}

func (s *Services) Active(ctx context.Context, org uuid.UUID) (int, error) {
	var c struct {
		Active int `json:"active"`
	}
	status, err := s.do(ctx, http.MethodGet, fmt.Sprintf("%s/v1/internal/organizations/%s/member-count", s.User, org), nil, &c)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("user service answered %d", status)
	}
	return c.Active, nil
}
