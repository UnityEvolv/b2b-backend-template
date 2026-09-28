package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
)

type httpOrganizations struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewOrganizations is an Organizations over the organization service.
func NewOrganizations(baseURL string, tokens auth.TokenSource, client *http.Client) Organizations {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &httpOrganizations{base: baseURL, tokens: tokens, http: client}
}

func (o *httpOrganizations) Name(ctx context.Context, orgID uuid.UUID) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+"/v1/internal/organizations/"+orgID.String(), nil)
	if err != nil {
		return "", err
	}
	if err := auth.Authorize(ctx, o.tokens, req); err != nil {
		return "", err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("organization service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("organization service answered %d", resp.StatusCode)
	}
	var out struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Name, nil
}
