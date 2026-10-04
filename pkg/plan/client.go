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

// Source says what an org may do: its band and the overrides a platform
// operator set for it. The organization service answers from its tables; a
// test answers from a map. A gate reads it at the moment of the action and
// checks the Entitlements it returns, never the band alone, so an override
// reaches every service's gates.
type Source interface {
	// Entitlements is the org's band and its overrides, read now.
	Entitlements(ctx context.Context, orgID string) (Entitlements, error)
}

// ErrNoOrganization means the org does not exist.
var ErrNoOrganization = fmt.Errorf("plan: no such organization")

// Static is a Source over a map of bands, with no overrides: for tests, and
// for the platform org.
type Static map[string]Band

// Entitlements is the mapped band, or the lowest when the org is not in the
// map.
func (s Static) Entitlements(_ context.Context, orgID string) (Entitlements, error) {
	if b, ok := s[orgID]; ok {
		return Of(b), nil
	}
	return Of(Lowest()), nil
}

// StaticEntitlements is a Source over a map of entitlements, for tests of
// overrides: an org not in the map is on the lowest band.
type StaticEntitlements map[string]Entitlements

// Entitlements is the mapped entitlements.
func (s StaticEntitlements) Entitlements(_ context.Context, orgID string) (Entitlements, error) {
	if e, ok := s[orgID]; ok {
		return e, nil
	}
	return Of(Lowest()), nil
}

// client asks the organization service's internal API, as this service,
// at the moment of every call. Nothing is cached: a plan change, or an
// override set, ended or past its end, takes effect on the next attempt.
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

// WireOverride is an override as the organization service's plan endpoints
// carry it.
type WireOverride struct {
	Kind    string     `json:"kind"` // limit or feature
	Key     string     `json:"key"`
	Cap     *int       `json:"cap,omitempty"`
	Allowed *bool      `json:"allowed,omitempty"`
	EndsAt  *time.Time `json:"ends_at,omitempty"`
}

// FromWire is the override w carries; ok is false for a kind it does not know.
func FromWire(w WireOverride) (Override, bool) {
	o := Override{EndsAt: w.EndsAt}
	switch {
	case w.Kind == "limit" && w.Cap != nil:
		o.Limit, o.Cap = Limit(w.Key), *w.Cap
	case w.Kind == "feature" && w.Allowed != nil:
		o.Feature, o.Allowed = Feature(w.Key), *w.Allowed
	default:
		return Override{}, false
	}
	return o, true
}

func (c *client) Entitlements(ctx context.Context, orgID string) (Entitlements, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/internal/organizations/"+orgID+"/plan", nil)
	if err != nil {
		return Entitlements{}, err
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return Entitlements{}, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Entitlements{}, fmt.Errorf("plan: fetch: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Entitlements{}, ErrNoOrganization
	default:
		return Entitlements{}, fmt.Errorf("plan: organization service answered %d", resp.StatusCode)
	}
	var body struct {
		Plan      string         `json:"plan"`
		Overrides []WireOverride `json:"overrides"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Entitlements{}, fmt.Errorf("plan: decode: %w", err)
	}
	band, err := Parse(body.Plan)
	if err != nil {
		return Entitlements{}, err
	}
	e := Of(band)
	for _, w := range body.Overrides {
		if o, ok := FromWire(w); ok {
			e.Overrides = append(e.Overrides, o)
		}
	}
	return e, nil
}
