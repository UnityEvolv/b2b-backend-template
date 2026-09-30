package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// What self-serve signup needs of the other services, and of DNS.

// Users is what this service needs of the user service.
type Users interface {
	// CreateMembership makes the signer-up's user and their Owner membership.
	CreateMembership(ctx context.Context, in NewMembership) (Membership, error)
}

// Accounts is what this service needs of the identity service.
type Accounts interface {
	// CreateLocalAccount starts the Owner's local account, already verified.
	CreateLocalAccount(ctx context.Context, in NewLocalAccount) (LocalAccount, error)
}

// DomainVerifier looks for the record that proves a domain claim.
type DomainVerifier interface {
	HasTXT(ctx context.Context, name, value string) (bool, error)
}

// Deps is what the signup and domain endpoints call out to. Zero values are
// for tests that do not touch them.
type Deps struct {
	Email    email.Sender
	Users    Users
	Accounts Accounts
	DNS      DomainVerifier
}

type NewMembership struct {
	OrgID          uuid.UUID `json:"org_id"`
	Email          string    `json:"email"`
	Name           string    `json:"name,omitempty"`
	Kind           string    `json:"kind"`
	Role           string    `json:"role"`
	Source         string    `json:"source"`
	IdempotencyKey string    `json:"-"`
}

type Membership struct {
	ID   uuid.UUID `json:"id"`
	User struct {
		ID uuid.UUID `json:"id"`
	} `json:"user"`
}

type NewLocalAccount struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	OrgID    uuid.UUID `json:"org_id"`
	OrgName  string    `json:"org_name"`
	App      string    `json:"app"`
	Verified bool      `json:"verified"`
}

type LocalAccount struct {
	UserID     uuid.UUID `json:"user_id"`
	SetupToken *string   `json:"setup_token,omitempty"`
}

// Refusal is another service saying no, with its envelope.
type Refusal struct {
	Status int
	Code   string
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused: %d %s", r.Status, r.Code) }

type serviceClient struct {
	name   string
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

func (c *serviceClient) post(ctx context.Context, path string, in, out any, key string) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(in); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if key == "" {
		key = uuid.NewString()
	}
	req.Header.Set("Idempotency-Key", key)
	if err := auth.Authorize(ctx, c.tokens, req); err != nil {
		return err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s service: %w", c.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return &Refusal{Status: resp.StatusCode, Code: e.Code}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

type httpUsers struct{ serviceClient }

// NewUsers is a Users over the user service.
func NewUsers(baseURL string, tokens auth.TokenSource, client *http.Client) Users {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpUsers{serviceClient{name: "user", base: baseURL, tokens: tokens, http: client}}
}

func (u *httpUsers) CreateMembership(ctx context.Context, in NewMembership) (Membership, error) {
	var out Membership
	err := u.post(ctx, "/v1/internal/memberships", in, &out, in.IdempotencyKey)
	return out, err
}

type httpAccounts struct{ serviceClient }

// NewAccounts is an Accounts over the identity service.
func NewAccounts(baseURL string, tokens auth.TokenSource, client *http.Client) Accounts {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpAccounts{serviceClient{name: "identity", base: baseURL, tokens: tokens, http: client}}
}

func (a *httpAccounts) CreateLocalAccount(ctx context.Context, in NewLocalAccount) (LocalAccount, error) {
	var out LocalAccount
	err := a.post(ctx, "/v1/internal/local-accounts", in, &out, "")
	return out, err
}

// DNS looks records up with the system resolver.
type DNS struct{ Resolver *net.Resolver }

// HasTXT is whether name has a TXT record equal to value.
func (d DNS) HasTXT(ctx context.Context, name, value string) (bool, error) {
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	records, err := r.LookupTXT(ctx, name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == value {
			return true, nil
		}
	}
	return false, nil
}
