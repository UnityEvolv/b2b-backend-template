package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
)

// HTTPPlatform is Platform over the identity, billing, audit and user
// services, with this service's own token.
type HTTPPlatform struct {
	Identity, Billing, Audit, User string
	Tokens                         auth.TokenSource
	HTTP                           *http.Client
}

func (p HTTPPlatform) client(name, base string) *serviceClient {
	c := p.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return &serviceClient{name: name, base: strings.TrimRight(base, "/"), tokens: p.Tokens, http: c}
}

func (p HTTPPlatform) RevokeOrgSessions(ctx context.Context, org uuid.UUID) error {
	return p.client("identity", p.Identity).post(ctx, fmt.Sprintf("/v1/internal/organizations/%s/sessions/revoke", org), map[string]any{"reason": "organization_closing"}, nil, "")
}

func (p HTTPPlatform) CloseBilling(ctx context.Context, org uuid.UUID) error {
	return p.client("billing", p.Billing).post(ctx, fmt.Sprintf("/v1/internal/organizations/%s/close", org), map[string]any{}, nil, "")
}

func (p HTTPPlatform) ExpireAudit(ctx context.Context, org uuid.UUID, before time.Time) error {
	return p.client("audit", p.Audit).post(ctx, fmt.Sprintf("/v1/internal/organizations/%s/audit/expire", org), map[string]any{"before": before.UTC()}, nil, "")
}

// Person is the user's address and memberships, from the user service.
func (p HTTPPlatform) Person(ctx context.Context, user uuid.UUID) (Person, error) {
	c := p.client("user", p.User)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/internal/users/%s/memberships", c.base, user), nil)
	if err != nil {
		return Person{}, err
	}
	if err := auth.Authorize(ctx, p.Tokens, req); err != nil {
		return Person{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Person{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Person{}, &Refusal{Status: resp.StatusCode}
	}
	var out struct {
		Memberships []struct {
			ID    uuid.UUID `json:"id"`
			OrgID uuid.UUID `json:"org_id"`
			User  struct {
				Email string `json:"email"`
			} `json:"user"`
		} `json:"memberships"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Person{}, err
	}
	var person Person
	for _, m := range out.Memberships {
		if person.Email == "" {
			person.Email = m.User.Email
		}
		person.Memberships = append(person.Memberships, orgdata.Membership{OrgID: m.OrgID, MembershipID: m.ID})
	}
	return person, nil
}
