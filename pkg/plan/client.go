package plan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Source says which band an org is on. The organization service answers
// from its table; a test answers from a map.
type Source interface {
	// Band is the org's plan, read now.
	Band(ctx context.Context, orgID string) (Band, error)
}

// ErrNoOrganization means the org does not exist.
var ErrNoOrganization = fmt.Errorf("plan: no such organization")

// Static is a Source over a map: for tests, and for the platform org.
type Static map[string]Band

// Band is the mapped band, or the lowest when the org is not in the map.
func (s Static) Band(_ context.Context, orgID string) (Band, error) {
	if b, ok := s[orgID]; ok {
		return b, nil
	}
	return Lowest(), nil
}

// client asks the organization service's internal API, as this service,
// at the moment of every call. Nothing is cached: a plan change takes effect
// on the next attempt.
type client struct {
	baseURL string
	tokens  auth.TokenSource
	http    *http.Client
}

// Client is a Source over the organization service at baseURL.
func Client(baseURL string, tokens auth.TokenSource, h *http.Client) Source {
	if h == nil {
		h = &http.Client{Timeout: 5 * time.Second}
	}
	return &client{baseURL: baseURL, tokens: tokens, http: h}
}

func (c *client) Band(ctx context.Context, orgID string) (Band, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/internal/organizations/"+orgID+"/plan", nil)
	if err != nil {
		return "", err
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return "", err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("plan: fetch: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", ErrNoOrganization
	default:
		return "", fmt.Errorf("plan: organization service answered %d", resp.StatusCode)
	}
	var body struct {
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("plan: decode: %w", err)
	}
	return Parse(body.Plan)
}
