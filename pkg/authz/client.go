package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

type client struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// Client is a Checker over the authorization service at baseURL. Every
// check is a call: a role or configuration change is seen on the next action.
func Client(baseURL string, tokens auth.TokenSource, h *http.Client) Checker {
	if h == nil {
		h = &http.Client{Timeout: 5 * time.Second}
	}
	return &client{base: baseURL, tokens: tokens, http: h}
}

func (c *client) Grant(ctx context.Context, orgID, membershipID string) (Grant, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/internal/organizations/"+orgID+"/memberships/"+membershipID+"/permissions", nil)
	if err != nil {
		return Grant{}, err
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return Grant{}, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Grant{}, fmt.Errorf("authz: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Grant{}, ErrNoMembership
	default:
		return Grant{}, fmt.Errorf("authz: authorization service answered %d", resp.StatusCode)
	}
	var body struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Grant{}, fmt.Errorf("authz: decode: %w", err)
	}
	g := Grant{Role: Role(body.Role)}
	for _, p := range body.Permissions {
		g.Permissions = append(g.Permissions, Permission(p))
	}
	return g, nil
}
