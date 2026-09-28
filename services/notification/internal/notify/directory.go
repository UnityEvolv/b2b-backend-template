package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// Services is the Directory over the user and organization services, asked
// with this service's own token at the moment of each event.
type Services struct {
	User, Organization string
	Tokens             auth.TokenSource
	HTTP               *http.Client
}

func (s Services) get(ctx context.Context, u string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	if err := auth.Authorize(ctx, s.Tokens, req); err != nil {
		return 0, err
	}
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

type membership struct {
	ID     uuid.UUID `json:"id"`
	Status string    `json:"status"`
	User   struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		Name         string `json:"name"`
		DisplayName  string `json:"display_name"`
		TimeZone     string `json:"time_zone"`
		WorkingHours *struct {
			Start string `json:"start"`
		} `json:"working_hours"`
	} `json:"user"`
}

// minutes is "HH:MM" as minutes after midnight, or fallback.
func minutes(hhmm string, fallback int) int {
	h, m, ok := strings.Cut(hhmm, ":")
	if !ok {
		return fallback
	}
	hi, err1 := strconv.Atoi(h)
	mi, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hi < 0 || hi > 23 || mi < 0 || mi > 59 {
		return fallback
	}
	return hi*60 + mi
}

// Person is one membership's person, from the user service.
func (s Services) Person(ctx context.Context, org, id uuid.UUID) (Person, error) {
	var m membership
	status, err := s.get(ctx, fmt.Sprintf("%s/v1/organizations/%s/memberships/%s", strings.TrimRight(s.User, "/"), org, id), &m)
	if err != nil {
		return Person{}, err
	}
	if status == http.StatusNotFound {
		return Person{}, nil
	}
	if status != http.StatusOK {
		return Person{}, fmt.Errorf("user service answered %d", status)
	}
	zone := time.UTC
	if m.User.TimeZone != "" {
		if z, err := time.LoadLocation(m.User.TimeZone); err == nil {
			zone = z
		}
	}
	start := 9 * 60
	if m.User.WorkingHours != nil {
		start = minutes(m.User.WorkingHours.Start, start)
	}
	name := m.User.DisplayName
	if name == "" {
		name = m.User.Name
	}
	return Person{UserID: m.User.ID, Email: m.User.Email, Name: name, Zone: zone, WorkStart: start, Active: m.Status == "active"}, nil
}

// audiences is the roles each audience reaches.
var audiences = map[string][]string{
	"admins":  {"owner", "admin"},
	"billing": {"owner", "admin", "billing_admin"},
}

// Members is everyone active in an audience.
func (s Services) Members(ctx context.Context, org uuid.UUID, audience string) ([]uuid.UUID, error) {
	roles, ok := audiences[audience]
	if !ok {
		return nil, fmt.Errorf("no audience %q", audience)
	}
	var out []uuid.UUID
	for _, role := range roles {
		cursor := ""
		for range 50 {
			q := url.Values{"role": {role}, "status": {"active"}, "limit": {"200"}}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			var page struct {
				Memberships []membership `json:"memberships"`
				NextCursor  string       `json:"next_cursor"`
			}
			status, err := s.get(ctx, fmt.Sprintf("%s/v1/organizations/%s/memberships?%s", strings.TrimRight(s.User, "/"), org, q.Encode()), &page)
			if err != nil {
				return nil, err
			}
			if status != http.StatusOK {
				return nil, fmt.Errorf("user service answered %d", status)
			}
			for _, m := range page.Memberships {
				out = append(out, m.ID)
			}
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
	}
	return out, nil
}

// OrgName is the org's name, for an email sent on its behalf.
func (s Services) OrgName(ctx context.Context, org uuid.UUID) (string, error) {
	var o struct {
		Name string `json:"name"`
	}
	status, err := s.get(ctx, fmt.Sprintf("%s/v1/internal/organizations/%s", strings.TrimRight(s.Organization, "/"), org), &o)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("organization service answered %d", status)
	}
	return o.Name, nil
}

// ToMembersChannel is the Redis channel the realtime service delivers
// per-person socket events from. Named in the realtime service too.
const ToMembersChannel = "unityofis:to-members"

// RedisLive tells open apps over the realtime service.
type RedisLive struct{ Client redis.Cmdable }

// Feed says a new entry arrived; each app reads its feed and count again.
func (l RedisLive) Feed(ctx context.Context, org uuid.UUID, recipients []uuid.UUID) error {
	ids := make([]string, len(recipients))
	for i, r := range recipients {
		ids[i] = r.String()
	}
	raw, err := json.Marshal(map[string]any{"org_id": org, "recipients": ids, "event": "notify:feed", "payload": map[string]any{}})
	if err != nil {
		return err
	}
	return l.Client.Publish(ctx, ToMembersChannel, raw).Err()
}
