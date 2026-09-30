package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// Capacity is what this service needs of the billing service: room
// for more members when the cap is reached, by an automatic upgrade where
// the org has one on, and word of the count so billing can warn at 80%.
type Capacity interface {
	// MakeRoom reports whether the org now has room for members active
	// members; false is the plan's refusal, unchanged.
	MakeRoom(ctx context.Context, orgID uuid.UUID, members int) (bool, error)
	MembersChanged(ctx context.Context, orgID uuid.UUID, members int)
}

// WithCapacity is s, asking billing before refusing at the cap.
func (s *Server) WithCapacity(c Capacity) *Server {
	s.capacity = c
	return s
}

type httpCapacity struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewCapacity is Capacity over the billing service at baseURL.
func NewCapacity(baseURL string, tokens auth.TokenSource, client *http.Client) Capacity {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &httpCapacity{base: baseURL, tokens: tokens, http: client}
}

func (c *httpCapacity) post(ctx context.Context, path string, body any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *httpCapacity) MakeRoom(ctx context.Context, orgID uuid.UUID, members int) (bool, error) {
	resp, err := c.post(ctx, fmt.Sprintf("/v1/internal/organizations/%s/capacity", orgID), map[string]int{"members": members})
	if err != nil {
		return false, fmt.Errorf("billing service: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusConflict:
		return false, nil
	default:
		return false, fmt.Errorf("billing service answered %d", resp.StatusCode)
	}
}

func (c *httpCapacity) MembersChanged(ctx context.Context, orgID uuid.UUID, members int) {
	resp, err := c.post(ctx, fmt.Sprintf("/v1/internal/organizations/%s/members-changed", orgID), map[string]int{"members": members})
	if err == nil {
		resp.Body.Close()
	}
}

// CountMembers is the org's active members: what its plan caps, for the
// billing page.
func (s *Server) CountMembers(ctx context.Context, req api.CountMembersRequestObject) (api.CountMembersResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.CountMembers403JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: "Services only."}}, nil
	}
	var active int64
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		active, err = store.New(tx).CountActiveMemberships(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.CountMembers200JSONResponse{Active: int(active)}, nil
}
