package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// TokenSource is where a service gets the token it presents to another
// service. Locally that is the stub issuer; deployed, the identity service or
// the platform's own service identity.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed token, for tests.
type StaticToken string

// Token is the token.
func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }

type issuerSource struct {
	url     string
	service string
	client  *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// IssuerTokenSource asks issuerURL's /token endpoint for a token for service
// and reuses it until it nears expiry. issuerURL comes from configuration.
func IssuerTokenSource(issuerURL, service string, client *http.Client) TokenSource {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &issuerSource{url: issuerURL, service: service, client: client}
}

func (s *issuerSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Until(s.expires) > time.Minute {
		return s.token, nil
	}

	body, _ := json.Marshal(map[string]any{"service": s.service, "ttl_seconds": 3600})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	// Deployed, the issuer wants proof of who is asking: the identity token
	// the platform signs for this workload's own service account, for the
	// issuer as audience. On a laptop there is no platform and no proof;
	// the local issuer mints for anyone.
	if proof, err := platformIdentity(ctx, s.url); err != nil {
		return "", fmt.Errorf("auth: service token: platform identity: %w", err)
	} else if proof != "" {
		req.Header.Set("Authorization", "Bearer "+proof)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth: service token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth: service token: issuer answered %d", resp.StatusCode)
	}
	var issued struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil || issued.AccessToken == "" {
		return "", fmt.Errorf("auth: service token: unreadable answer")
	}
	s.token = issued.AccessToken
	s.expires = time.Now().Add(time.Duration(issued.ExpiresIn) * time.Second)
	return s.token, nil
}

// Authorize adds the caller's service token to an outgoing request.
func Authorize(ctx context.Context, source TokenSource, req *http.Request) error {
	token, err := source.Token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// The call is part of this request's trace.
	httpx.Propagate(ctx, req)
	return nil
}

// platformIdentity is the workload's platform-signed identity token for
// audience, or "" off a cloud platform. A variable so tests can stand in.
var platformIdentity = func(ctx context.Context, audience string) (string, error) {
	if !metadata.OnGCE() {
		return "", nil
	}
	return metadata.GetWithContext(ctx, "instance/service-accounts/default/identity?audience="+url.QueryEscape(audience)+"&format=full")
}
