// Package orgdata is the one contract every service keeps for data it
// holds about an org or a person (UO-183, UO-184): hand it over for an
// export, and delete it for a purge. The organization service drives both
// from its daily loop; no service reaches into another's tables.
//
// Each service answers, in its own OpenAPI contract, with the shapes here:
//
//	GET    /v1/internal/organizations/{org_id}/data   an org export part
//	DELETE /v1/internal/organizations/{org_id}/data   purge; how many rows remain
//	GET    /v1/internal/users/{user_id}/data?membership=org:membership
//	                                                  a person's export part
//
// All three are for the organization service only. A purge is idempotent and
// checked: it deletes, then counts what is left of the org, and the caller
// treats anything above zero as a failure to retry the next day.
package orgdata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// Caller is the only service that may ask for, or delete, anyone's data.
const Caller = "organization"

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

// Service is one service's data endpoints, at its base URL.
type Service struct {
	Name string
	Base string
}

// Client asks services for data and deletes it, with this service's token.
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

func (c *Client) do(ctx context.Context, method, u string, out any) error {
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
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("orgdata: %s %s answered %d", method, req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Export is s's part of an org's export.
func (c *Client) Export(ctx context.Context, s Service, org uuid.UUID) (Part, error) {
	var p Part
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/v1/internal/organizations/%s/data", strings.TrimRight(s.Base, "/"), org), &p)
	return p, err
}

// Purge deletes an org from s; the rows it has left.
func (c *Client) Purge(ctx context.Context, s Service, org uuid.UUID) (int, error) {
	var p Purged
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("%s/v1/internal/organizations/%s/data", strings.TrimRight(s.Base, "/"), org), &p)
	return p.Remaining, err
}

// ExportUser is s's part of a person's export, across their memberships.
func (c *Client) ExportUser(ctx context.Context, s Service, user uuid.UUID, memberships []Membership) (Part, error) {
	q := url.Values{}
	for _, m := range memberships {
		q.Add("membership", m.String())
	}
	u := fmt.Sprintf("%s/v1/internal/users/%s/data", strings.TrimRight(s.Base, "/"), user)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var p Part
	err := c.do(ctx, http.MethodGet, u, &p)
	return p, err
}
