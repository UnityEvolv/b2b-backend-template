package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// Users is what this service needs of the user service.
type Users interface {
	RecordSignIn(ctx context.Context, in SignIn) (SignInResult, error)
	ListMemberships(ctx context.Context, userID uuid.UUID) ([]Membership, error)
	RecordActivity(ctx context.Context, orgID, membershipID uuid.UUID) error
	// MembershipByEmail is the membership an address has in an org, whatever
	// its status, or ErrNotFound.
	MembershipByEmail(ctx context.Context, orgID uuid.UUID, email string) (Membership, error)
	// CreateMembership is a membership from an invite. The user is made on
	// first sight. A plan refusal comes back as a Refusal.
	CreateMembership(ctx context.Context, in NewMembership) (Membership, error)
	// FindByEmail is the person who has an address, or ErrNotFound.
	FindByEmail(ctx context.Context, email string) (uuid.UUID, error)
	// SetEmail changes a person's address once the new one is proven; a
	// Refusal with 409 means somebody else has it.
	SetEmail(ctx context.Context, userID uuid.UUID, email string) error
	// SignedIn says a person signed in without an identity provider, which
	// cancels a pending account deletion.
	SignedIn(ctx context.Context, userID uuid.UUID) error
	// CountMembers is how many active members an org has: for the platform
	// org, whether there is any operator yet.
	CountMembers(ctx context.Context, orgID uuid.UUID) (int, error)
}

// The standings an org can be in, as the organization service says.
const (
	orgSuspended = "suspended"
	orgClosing   = "closing"
)

// OrgStatus is an org's standing: active, suspended, or closing with the
// date its data is deleted.
type OrgStatus struct {
	Status     string     `json:"status"`
	PurgeAfter *time.Time `json:"purge_after,omitempty"`
}

// Organizations is what this service needs of the organization service.
type Organizations interface {
	ByDomain(ctx context.Context, domain string) (uuid.UUID, error)
	// Name is the org's name, for emails sent on its behalf.
	Name(ctx context.Context, orgID uuid.UUID) (string, error)
	// Status is the org's standing: active, suspended by a platform
	// operator, or closing with the date it is deleted.
	Status(ctx context.Context, orgID uuid.UUID) (OrgStatus, error)
}

// NewMembership is what an accepted invite asks the user service for.
type NewMembership struct {
	OrgID          uuid.UUID `json:"org_id"`
	Email          string    `json:"email"`
	Name           string    `json:"name,omitempty"`
	Kind           string    `json:"kind"`
	Role           string    `json:"role"`
	Source         string    `json:"source"`
	IdempotencyKey string    `json:"-"`
}

// SignIn is what the identity provider said.
type SignIn struct {
	OrgID      uuid.UUID         `json:"org_id"`
	Email      string            `json:"email"`
	Name       string            `json:"name"`
	IdpSubject string            `json:"idp_subject,omitempty"`
	Directory  map[string]string `json:"directory,omitempty"`
}

// Membership is one org a person belongs to, as the user service tells it.
type Membership struct {
	ID     uuid.UUID `json:"id"`
	OrgID  uuid.UUID `json:"org_id"`
	Kind   string    `json:"kind"`
	Status string    `json:"status"`
	Role   string    `json:"role"`
	// Source is how the membership came to exist: idp and scim mean the
	// org's identity provider manages the person's address.
	Source       string     `json:"source,omitempty"`
	LastActiveAt *time.Time `json:"last_active_at,omitempty"`
	User         struct {
		ID uuid.UUID `json:"id"`
	} `json:"user"`
	// purgeAfter is when a closing org is deleted, set by screen.
	purgeAfter *time.Time
}

// SignInResult is the user service's answer to a sign-in.
type SignInResult struct {
	User struct {
		ID uuid.UUID `json:"id"`
	} `json:"user"`
	Membership  Membership   `json:"membership"`
	Memberships []Membership `json:"memberships"`
}

// Refusal is the user service saying no, with its envelope.
type Refusal struct {
	Status int
	Code   string
}

func (r *Refusal) Error() string { return fmt.Sprintf("user service refused: %d %s", r.Status, r.Code) }

// ErrNotFound means the thing asked for does not exist.
var ErrNotFound = errors.New("not found")

type httpUsers struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewUsers is a Users over the user service at baseURL.
func NewUsers(baseURL string, tokens auth.TokenSource, client *http.Client) Users {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpUsers{base: baseURL, tokens: tokens, http: client}
}

func (u *httpUsers) call(ctx context.Context, method, path string, in, out any) error {
	return u.callWithKey(ctx, method, path, in, out, "")
}

// callWithKey is call with a chosen idempotency key, so a retried create
// finds the first.
func (u *httpUsers) callWithKey(ctx context.Context, method, path string, in, out any, key string) error {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.base+path, &body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
		if key == "" {
			key = uuid.NewString()
		}
		req.Header.Set("Idempotency-Key", key)
	}
	if err := auth.Authorize(ctx, u.tokens, req); err != nil {
		return err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := u.http.Do(req)
	if err != nil {
		return fmt.Errorf("user service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
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

func (u *httpUsers) RecordSignIn(ctx context.Context, in SignIn) (SignInResult, error) {
	var out SignInResult
	err := u.call(ctx, http.MethodPost, "/v1/internal/sign-ins", in, &out)
	return out, err
}

func (u *httpUsers) ListMemberships(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	var out struct {
		Memberships []Membership `json:"memberships"`
	}
	err := u.call(ctx, http.MethodGet, "/v1/internal/users/"+userID.String()+"/memberships", nil, &out)
	return out.Memberships, err
}

func (u *httpUsers) RecordActivity(ctx context.Context, orgID, membershipID uuid.UUID) error {
	return u.call(ctx, http.MethodPost, "/v1/internal/organizations/"+orgID.String()+"/memberships/"+membershipID.String()+"/activity", nil, nil)
}

func (u *httpUsers) MembershipByEmail(ctx context.Context, orgID uuid.UUID, email string) (Membership, error) {
	var out Membership
	err := u.call(ctx, http.MethodGet, "/v1/internal/organizations/"+orgID.String()+"/membership-by-email?email="+url.QueryEscape(email), nil, &out)
	return out, err
}

func (u *httpUsers) CreateMembership(ctx context.Context, in NewMembership) (Membership, error) {
	var out Membership
	err := u.callWithKey(ctx, http.MethodPost, "/v1/internal/memberships", in, &out, in.IdempotencyKey)
	return out, err
}

func (u *httpUsers) FindByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	var out struct {
		UserID uuid.UUID `json:"user_id"`
	}
	err := u.call(ctx, http.MethodGet, "/v1/internal/user-by-email?email="+url.QueryEscape(email), nil, &out)
	return out.UserID, err
}

func (u *httpUsers) SetEmail(ctx context.Context, userID uuid.UUID, email string) error {
	return u.call(ctx, http.MethodPut, "/v1/internal/users/"+userID.String()+"/email", map[string]string{"email": email}, nil)
}

func (u *httpUsers) SignedIn(ctx context.Context, userID uuid.UUID) error {
	return u.call(ctx, http.MethodPost, "/v1/internal/users/"+userID.String()+"/signed-in", nil, nil)
}

func (u *httpUsers) CountMembers(ctx context.Context, orgID uuid.UUID) (int, error) {
	var out struct {
		Active int `json:"active"`
	}
	err := u.call(ctx, http.MethodGet, "/v1/internal/organizations/"+orgID.String()+"/member-count", nil, &out)
	return out.Active, err
}

type httpOrganizations struct {
	base   string
	tokens auth.TokenSource
	http   *http.Client
}

// NewOrganizations is an Organizations over the organization service.
func NewOrganizations(baseURL string, tokens auth.TokenSource, client *http.Client) Organizations {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &httpOrganizations{base: baseURL, tokens: tokens, http: client}
}

func (o *httpOrganizations) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+path, nil)
	if err != nil {
		return err
	}
	if err := auth.Authorize(ctx, o.tokens, req); err != nil {
		return err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return fmt.Errorf("organization service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("organization service answered %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (o *httpOrganizations) ByDomain(ctx context.Context, domain string) (uuid.UUID, error) {
	var out struct {
		OrgID uuid.UUID `json:"org_id"`
	}
	if err := o.get(ctx, "/v1/internal/domains/"+url.PathEscape(domain)+"/organization", &out); err != nil {
		return uuid.Nil, err
	}
	return out.OrgID, nil
}

func (o *httpOrganizations) Status(ctx context.Context, orgID uuid.UUID) (OrgStatus, error) {
	var out OrgStatus
	err := o.get(ctx, "/v1/internal/organizations/"+orgID.String(), &out)
	return out, err
}

func (o *httpOrganizations) Name(ctx context.Context, orgID uuid.UUID) (string, error) {
	var out struct {
		Name string `json:"name"`
	}
	if err := o.get(ctx, "/v1/internal/organizations/"+orgID.String(), &out); err != nil {
		return "", err
	}
	return out.Name, nil
}
