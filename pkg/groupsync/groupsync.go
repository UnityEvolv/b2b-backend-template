// Package groupsync is the contract between the user service and the
// product service that carries a SCIM group to what it grants (a team, a
// project, a workspace). The template stores groups as the directory sent
// them and grants nothing by itself; the product decides what membership
// of a group means.
//
// A product running the user service unchanged names that service in
// SCIM_GROUP_SYNC. It must be a data owner (DATA_OWNERS, pkg/dataowner),
// so its URL is its entry's url or its <NAME>_URL, and it answers, in its
// own OpenAPI contract, with the shapes here:
//
//	POST /v1/internal/organizations/{org_id}/scim-groups/{group_id}/sync
//	     a Request; 200 with a Result
//
// for the user service only (auth.RequireService(ctx, groupsync.Caller)).
// The call is the user service's own service token.
//
// The request is the group whole, never a delta: SCIM pushes are lost,
// duplicated and reordered, so the product makes what the group grants
// match Members exactly and says who that added and removed. With DryRun
// it changes nothing and only says who would be; the user service asks
// that first and halts a change that would take too many people away at
// once for an admin, instead of applying it.
//
// There is no queue. The call is made when the directory changes the group;
// a failure is logged and the daily SCIM reconciliation calls again with the
// group as it then stands, so the product catches up within a day. A group
// the directory deletes is sent once more with no members before it goes;
// that call failing fails the directory's delete, which it retries.
package groupsync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

// Caller is the only service that calls the endpoint.
const Caller = "user"

// Why a group is being synced: Request.Change.
const (
	// ChangeDirectory: the directory created the group or changed its
	// members or name.
	ChangeDirectory = "directory"
	// ChangeDeleted: the directory deleted the group. Members is empty, and
	// the group is gone once this succeeds.
	ChangeDeleted = "deleted"
	// ChangeReconciliation: the daily reconciliation, sending every group
	// as it stands so a failed or missed call is made good.
	ChangeReconciliation = "reconciliation"
	// ChangeApproved: an admin applied a change that had been halted for
	// taking too many people away at once.
	ChangeApproved = "approved"
)

// Member is one person in the group.
type Member struct {
	MembershipID uuid.UUID `json:"membership_id"`
	UserID       uuid.UUID `json:"user_id"`
}

// Request is the group as it stands, sent whole.
type Request struct {
	OrgID   uuid.UUID `json:"org_id"`
	GroupID uuid.UUID `json:"group_id"`
	// DisplayName is the group's name in the directory.
	DisplayName string `json:"display_name"`
	// Members is everyone in the group now; what it grants should match
	// it exactly. Never null.
	Members []Member `json:"members"`
	// Change is why it is sent: one of the Change constants.
	Change string `json:"change"`
	// DryRun: change nothing, only say who would be added and removed.
	DryRun bool `json:"dry_run"`
}

// Result is who the sync added to and removed from what the group grants,
// by membership id, or would have with DryRun.
type Result struct {
	Added   []uuid.UUID `json:"added"`
	Removed []uuid.UUID `json:"removed"`
}

// Path is the endpoint for a group, under the product service's base URL.
func Path(org, group uuid.UUID) string {
	return fmt.Sprintf("/v1/internal/organizations/%s/scim-groups/%s/sync", org, group)
}

// Client calls the product's endpoint with the user service's token.
type Client struct {
	// Service is the product service's name, for logs.
	Service string
	url     string
	tokens  auth.TokenSource
	http    *http.Client
}

// NewClient calls the service named service at baseURL.
func NewClient(service, baseURL string, tokens auth.TokenSource, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{Service: service, url: strings.TrimRight(baseURL, "/"), tokens: tokens, http: client}
}

// Sync sends r and reads the result. Any answer but 200 is an error.
func (c *Client) Sync(ctx context.Context, r Request) (Result, error) {
	if r.Members == nil {
		r.Members = []Member{}
	}
	body, err := json.Marshal(r)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+Path(r.OrgID, r.GroupID), bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return Result{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("groupsync: %s: %w", c.Service, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("groupsync: %s answered %d", c.Service, resp.StatusCode)
	}
	var out Result
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("groupsync: %s: %w", c.Service, err)
	}
	return out, nil
}
