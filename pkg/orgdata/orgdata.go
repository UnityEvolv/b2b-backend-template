// Package orgdata is the one contract every service keeps for data it
// holds about an org or a person: hand it over for an
// export, delete it for a purge, and forget a member. The organization
// service drives the first two from its daily loop, the user service the
// third; no service reaches into another's tables. Which services answer
// which is the data-owner registry, pkg/dataowner.
//
// Each service answers, in its own OpenAPI contract, with the shapes here:
//
//	GET    /v1/internal/organizations/{org_id}/data   an org export part
//	DELETE /v1/internal/organizations/{org_id}/data   purge; how many rows remain
//	GET    /v1/internal/users/{user_id}/data?membership=org:membership
//	                                                  a person's export part
//	DELETE /v1/internal/organizations/{org_id}/memberships/{membership_id}/data
//	                                                  erase a member; 204
//
// The first three are for the organization service only, the last for the
// user service (Eraser) as well. A purge is idempotent and checked: it
// deletes, then counts what is left of the org, and the caller treats
// anything above zero as a failure to retry the next day. A call that fails
// is a *Blocked naming the owner: an export or a purge does not complete
// without every owner, and nothing is skipped quietly.
package orgdata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
)

// Caller is the only service that may ask for, or delete, an org's data.
const Caller = "organization"

// Eraser is the service that asks owners to forget a member, when the
// person's account is deleted.
const Eraser = "user"

// File is an object in storage that belongs in an export.
type File struct {
	// Key is the storage key, under the org's own prefix.
	Key string `json:"key"`
	// Name is where it goes in the archive, relative to the service's folder.
	Name string `json:"name"`
}

// Part is one service's share of an export: its records as JSON, and the
// files that go with them.
type Part struct {
	Service string          `json:"service"`
	Data    json.RawMessage `json:"data"`
	Files   []File          `json:"files"`
}

// Purged is what a purge leaves: zero when the org is gone from the service.
type Purged struct {
	Remaining int `json:"remaining"`
}

// Membership is one of a person's memberships, for a personal export.
type Membership struct {
	OrgID        uuid.UUID
	MembershipID uuid.UUID
}

// String is the query form, org:membership.
func (m Membership) String() string { return m.OrgID.String() + ":" + m.MembershipID.String() }

// ParseMemberships reads the membership query parameters.
func ParseMemberships(values []string) ([]Membership, error) {
	out := make([]Membership, 0, len(values))
	for _, v := range values {
		org, mbr, ok := strings.Cut(v, ":")
		if !ok {
			return nil, fmt.Errorf("orgdata: %q is not org:membership", v)
		}
		o, err := uuid.Parse(org)
		if err != nil {
			return nil, err
		}
		m, err := uuid.Parse(mbr)
		if err != nil {
			return nil, err
		}
		out = append(out, Membership{OrgID: o, MembershipID: m})
	}
	return out, nil
}

// Marshal is v as a part's data.
func Marshal(service string, v any, files []File) (Part, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Part{}, err
	}
	if files == nil {
		files = []File{}
	}
	return Part{Service: service, Data: raw, Files: files}, nil
}

// Blocked is an owner whose call failed, so the export, purge or erasure it
// was part of did not complete: it is retried, and reported by name.
type Blocked struct {
	// Owner is the data owner's name.
	Owner string
	// Step is what was asked of it: export, purge or erase.
	Step string
	Err  error
}

func (b *Blocked) Error() string {
	return fmt.Sprintf("orgdata: %s blocked by %s: %v", b.Step, b.Owner, b.Err)
}

func (b *Blocked) Unwrap() error { return b.Err }

// Client asks data owners for data and deletes it, with this service's token.
type Client struct {
	tokens auth.TokenSource
	http   *http.Client
}

// NewClient is a client with the caller's token source.
func NewClient(tokens auth.TokenSource, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Client{tokens: tokens, http: client}
}

// do sends one call; an answer other than ok is an error.
func (c *Client) do(ctx context.Context, method, u string, out any, ok ...int) error {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if !slices.Contains(ok, resp.StatusCode) {
		return fmt.Errorf("orgdata: %s %s answered %d", method, req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func base(o dataowner.Owner) string { return strings.TrimRight(o.URL, "/") }

// Export is o's part of an org's export.
func (c *Client) Export(ctx context.Context, o dataowner.Owner, org uuid.UUID) (Part, error) {
	var p Part
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/v1/internal/organizations/%s/data", base(o), org), &p, http.StatusOK)
	return p, err
}

// Purge deletes an org from o; the rows it has left.
func (c *Client) Purge(ctx context.Context, o dataowner.Owner, org uuid.UUID) (int, error) {
	var p Purged
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("%s/v1/internal/organizations/%s/data", base(o), org), &p, http.StatusOK)
	return p.Remaining, err
}

// ExportUser is o's part of a person's export, across their memberships.
func (c *Client) ExportUser(ctx context.Context, o dataowner.Owner, user uuid.UUID, memberships []Membership) (Part, error) {
	q := url.Values{}
	for _, m := range memberships {
		q.Add("membership", m.String())
	}
	u := fmt.Sprintf("%s/v1/internal/users/%s/data", base(o), user)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var p Part
	err := c.do(ctx, http.MethodGet, u, &p, http.StatusOK)
	return p, err
}

// Erase has o forget what it keeps under one membership. Idempotent there:
// it answers 204 for a membership it never heard of too, so anything else,
// a 404 included, is a failure and not a service with nothing to forget.
func (c *Client) Erase(ctx context.Context, o dataowner.Owner, org, membership uuid.UUID) error {
	u := fmt.Sprintf("%s/v1/internal/organizations/%s/memberships/%s/data", base(o), org, membership)
	return c.do(ctx, http.MethodDelete, u, nil, http.StatusNoContent)
}
