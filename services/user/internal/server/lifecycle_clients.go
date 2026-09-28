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
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// What account deletion and org offboarding (UO-183, UO-184) need of other
// services, each over its API with this service's own token.

// Accounts is the identity service's side of a person: deleting one ends
// their sessions and removes their sign-in account.
type Accounts interface {
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}

// OrgNames is the organization service's name for an org, for emails sent
// on its behalf.
type OrgNames interface {
	Name(ctx context.Context, orgID uuid.UUID) (string, error)
}

// Forgetter is a service that keeps something personal under a membership
// (usage, calendar, notification) and deletes it for account deletion.
type Forgetter interface {
	Name() string
	Forget(ctx context.Context, orgID, membershipID uuid.UUID) error
}

// send is one call to another service; 404 is done when notFoundOK.
func send(ctx context.Context, client *http.Client, tokens auth.TokenSource, method, url string, notFoundOK bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}
	if err := auth.Authorize(ctx, tokens, req); err != nil {
		return err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && notFoundOK {
		return nil
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s answered %d", method, req.URL.Path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// DeleteUser asks the identity service to delete what it keeps about a
// person. Idempotent there.
func (s *httpSessions) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	return send(ctx, s.http, s.tokens, http.MethodDelete, s.base+"/v1/internal/users/"+userID.String(), true, nil)
}

// NewAccounts is an Accounts over the identity service at baseURL.
func NewAccounts(baseURL string, tokens auth.TokenSource, client *http.Client) Accounts {
	return NewSessions(baseURL, tokens, client).(*httpSessions)
}

type httpOrgNames struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewOrgNames is an OrgNames over the organization service at baseURL.
func NewOrgNames(baseURL string, tokens auth.TokenSource, client *http.Client) OrgNames {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpOrgNames{base: strings.TrimRight(baseURL, "/"), tokens: tokens, http: client}
}

func (o *httpOrgNames) Name(ctx context.Context, orgID uuid.UUID) (string, error) {
	var out struct {
		Name string `json:"name"`
	}
	err := send(ctx, o.http, o.tokens, http.MethodGet, o.base+"/v1/internal/organizations/"+orgID.String(), false, &out)
	return out.Name, err
}

type httpForgetter struct {
	name   string
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewForgetter is the named service at baseURL, forgetting memberships.
func NewForgetter(name, baseURL string, tokens auth.TokenSource, client *http.Client) Forgetter {
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	return &httpForgetter{name: name, base: strings.TrimRight(baseURL, "/"), tokens: tokens, http: client}
}

func (f *httpForgetter) Name() string { return f.name }

// Forget deletes what the service keeps under the membership; a service
// that never heard of it answers 404, which is as good as done.
func (f *httpForgetter) Forget(ctx context.Context, orgID, membershipID uuid.UUID) error {
	u := fmt.Sprintf("%s/v1/internal/organizations/%s/memberships/%s/data", f.base, orgID, membershipID)
	return send(ctx, f.http, f.tokens, http.MethodDelete, u, true, nil)
}
