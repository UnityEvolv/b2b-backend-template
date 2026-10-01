// Command seed fills a local stack with something to look at:
//
//   - Demo Co, an organization that signs in with passwords, with a person
//     in each role an invite can give (owner, admin, billing_admin, user)
//     and its roles configured: the Admin role holds every registered
//     permission group.
//   - SSO Demo Co, an organization at sso.example.test that signs in
//     through the stub issuer (docs/sso.md): anyone@sso.example.test signs
//     in there and is made a member on the way.
//
// Everything goes in through the services' own APIs, the way a person would
// put it there: the organization service creates the orgs, the identity
// service invites each person and saves the identity provider, the
// authorization service takes the roles; the invite and verification emails
// are read back from the local mail catcher. No schema is written across.
// Running it twice changes nothing: each org create carries a fixed
// idempotency key, a person who can already sign in is left alone, and the
// rest are PUTs.
//
// Local only. It needs the compose stack's token endpoint, which hands out a
// token for anyone, and its mail catcher.
//
//	docker compose -f deploy/docker-compose.yml --profile seed run --rm seed
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Fixed, so a second run finds what the first made.
const (
	operatorUserID = "01992b00-0000-7000-8000-000000005d01"
	orgKey         = "seed-demo-organization"
	ssoOrgKey      = "seed-sso-organization"
	platformOrg    = "00000000-0000-7000-8000-000000000000"
)

type person struct {
	Email, Name, Role, Password string
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

type config struct {
	identity, organization, authorization, mail string
	password                                    string
	stubIssuer                                  string
}

type organization struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func run(ctx context.Context) error {
	cfg := config{
		identity:      os.Getenv("SEED_IDENTITY_URL"),
		organization:  os.Getenv("SEED_ORGANIZATION_URL"),
		authorization: os.Getenv("SEED_AUTHORIZATION_URL"),
		mail:          os.Getenv("SEED_MAIL_URL"),
		password:      env("SEED_PASSWORD", "demo-password-change-me"),
		// Empty leaves the SSO organization out.
		stubIssuer: os.Getenv("SEED_STUB_ISSUER"),
	}
	if cfg.identity == "" || cfg.organization == "" || cfg.authorization == "" || cfg.mail == "" {
		return errors.New("SEED_IDENTITY_URL, SEED_ORGANIZATION_URL, SEED_AUTHORIZATION_URL and SEED_MAIL_URL are required")
	}
	domain := env("SEED_DOMAIN", "demo.example.test")
	timeZone := env("SEED_TIME_ZONE", "Europe/London")
	people := []person{
		{Email: "owner@" + domain, Name: "Olivia Owner", Role: "owner", Password: cfg.password},
		{Email: "admin@" + domain, Name: "Adam Admin", Role: "admin", Password: cfg.password},
		{Email: "billing@" + domain, Name: "Bella Billing", Role: "billing_admin", Password: cfg.password},
		{Email: "member@" + domain, Name: "Mona Member", Role: "user", Password: cfg.password},
	}

	operator, err := localToken(ctx, cfg.identity, map[string]any{"user_id": operatorUserID, "org_id": platformOrg, "membership_id": operatorUserID})
	if err != nil {
		return fmt.Errorf("operator token: %w", err)
	}

	var org organization
	if err := call(ctx, http.MethodPost, cfg.organization+"/v1/organizations", operator, orgKey,
		map[string]any{"name": "Demo Co", "time_zone": timeZone}, &org); err != nil {
		return fmt.Errorf("organization: %w", err)
	}
	fmt.Printf("organization %s (%s)\n", org.Name, org.OrgID)

	for _, p := range people {
		if err := ensurePerson(ctx, cfg, operator, org.OrgID, p); err != nil {
			return fmt.Errorf("%s: %w", p.Email, err)
		}
	}
	if err := configureRoles(ctx, cfg, org.OrgID, people[0]); err != nil {
		return fmt.Errorf("roles: %w", err)
	}

	ssoDomain := env("SEED_SSO_DOMAIN", "sso.example.test")
	if cfg.stubIssuer != "" {
		sso, err := ensureSSOOrganization(ctx, cfg, operator, ssoDomain, timeZone)
		if err != nil {
			return fmt.Errorf("SSO organization: %w", err)
		}
		fmt.Printf("organization %s (%s) signs in through %s\n", sso.Name, sso.OrgID, cfg.stubIssuer)
	}

	fmt.Println()
	fmt.Println("Sign in with a password as any of:")
	for _, p := range people {
		fmt.Printf("  %-32s %-14s %s\n", p.Email, p.Role, p.Password)
	}
	if cfg.stubIssuer != "" {
		fmt.Printf("or through the stub issuer as anyone@%s (no password).\n", ssoDomain)
	}
	return nil
}

// configureRoles sets the demo org's roles as its Owner would on the roles
// page: the Admin role holds every registered permission group, the
// Billing Admin role the ones it holds by default.
func configureRoles(ctx context.Context, cfg config, orgID string, owner person) error {
	token, err := signIn(ctx, cfg.identity, owner.Email, owner.Password)
	if err != nil {
		return fmt.Errorf("owner sign-in: %w", err)
	}
	var groups struct {
		Groups []struct {
			Key          string   `json:"key"`
			DefaultRoles []string `json:"default_roles"`
		} `json:"groups"`
	}
	if err := call(ctx, http.MethodGet, cfg.authorization+"/v1/permission-groups", token, "", nil, &groups); err != nil {
		return err
	}
	admin, billing := []string{}, []string{}
	for _, g := range groups.Groups {
		admin = append(admin, g.Key)
		for _, r := range g.DefaultRoles {
			if r == "billing_admin" {
				billing = append(billing, g.Key)
			}
		}
	}
	if err := call(ctx, http.MethodPut, cfg.authorization+"/v1/organizations/"+orgID+"/permissions", token, "",
		map[string]any{"admin": admin, "billing_admin": billing}, nil); err != nil {
		return err
	}
	fmt.Printf("roles: admin holds %s; billing_admin holds %s\n", strings.Join(admin, ", "), strings.Join(billing, ", "))
	return nil
}

// ensureSSOOrganization makes an organization that owns domain and signs in
// through the stub issuer. A platform operator sets the domain directly, so
// no DNS record is needed.
func ensureSSOOrganization(ctx context.Context, cfg config, operator, domain, timeZone string) (organization, error) {
	var org organization
	if err := call(ctx, http.MethodPost, cfg.organization+"/v1/organizations", operator, ssoOrgKey,
		map[string]any{"name": "SSO Demo Co", "time_zone": timeZone, "domain": domain}, &org); err != nil {
		return org, err
	}
	err := call(ctx, http.MethodPut, cfg.identity+"/v1/organizations/"+org.OrgID+"/identity-provider", operator, "",
		map[string]any{
			"preset": "generic", "issuer": cfg.stubIssuer,
			"client_id":     env("SEED_STUB_CLIENT_ID", "local-sso"),
			"client_secret": env("SEED_STUB_CLIENT_SECRET", "local-sso-secret"),
		}, nil)
	return org, err
}

// signIn signs in with a password and returns the access token.
func signIn(ctx context.Context, identityURL, email, password string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := call(ctx, http.MethodPost, identityURL+"/v1/sign-in/local", "", "", map[string]any{"email": email, "password": password}, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("no access token: a second factor is due")
	}
	return out.AccessToken, nil
}

// ensurePerson invites someone and walks their emails through to a password,
// unless they can already sign in.
func ensurePerson(ctx context.Context, cfg config, operator, orgID string, p person) error {
	if code := signInStatus(ctx, cfg.identity, p.Email, p.Password); code == http.StatusOK || code == http.StatusAccepted {
		fmt.Printf("%s can already sign in\n", p.Email)
		return nil
	}
	since := time.Now().Add(-2 * time.Second)
	if err := call(ctx, http.MethodPost, cfg.identity+"/v1/organizations/"+orgID+"/invites", operator, "seed-invite-"+p.Email,
		map[string]any{"email": p.Email, "role": p.Role}, nil); err != nil {
		return fmt.Errorf("invite: %w", err)
	}
	inviteToken, err := linkToken(ctx, cfg.mail, p.Email, "accept-invite", since)
	if err != nil {
		return fmt.Errorf("invite email: %w", err)
	}
	since = time.Now().Add(-2 * time.Second)
	var accepted struct {
		Next string `json:"next"`
	}
	if err := call(ctx, http.MethodPost, cfg.identity+"/v1/invites/"+url.PathEscape(inviteToken)+"/accept", "", "", map[string]any{"name": p.Name}, &accepted); err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if accepted.Next == "verify_email" {
		verifyToken, err := linkToken(ctx, cfg.mail, p.Email, "verify-email", since)
		if err != nil {
			return fmt.Errorf("verification email: %w", err)
		}
		var verified struct {
			SetupToken string `json:"setup_token"`
		}
		if err := call(ctx, http.MethodPost, cfg.identity+"/v1/email-verification/verify", "", "", map[string]any{"token": verifyToken}, &verified); err != nil {
			return fmt.Errorf("verify: %w", err)
		}
		if err := call(ctx, http.MethodPost, cfg.identity+"/v1/local/password", "", "", map[string]any{"token": verified.SetupToken, "password": p.Password}, nil); err != nil {
			return fmt.Errorf("password: %w", err)
		}
	}
	fmt.Printf("%s joined as %s\n", p.Email, p.Role)
	return nil
}

// localToken asks the compose stack's token endpoint for a token.
func localToken(ctx context.Context, identityURL string, claims map[string]any) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := call(ctx, http.MethodPost, identityURL+"/token", "", "", claims, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

func signInStatus(ctx context.Context, identityURL, email, password string) int {
	body, _ := json.Marshal(map[string]any{"email": email, "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, identityURL+"/v1/sign-in/local", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// call sends JSON and decodes JSON; any answer outside 2xx is an error.
func call(ctx context.Context, method, target, token, key string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s answered %d: %s", req.URL.Path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// tokenIn finds the token a link to page carries in an email body.
var tokenIn = regexp.MustCompile(`/(accept-invite|verify-email)\?token=([A-Za-z0-9_\-.%]+)`)

// linkToken waits for the newest email to address sent after since, and
// returns the token its link to page carries.
func linkToken(ctx context.Context, mailURL, address, page string, since time.Time) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var list struct {
			Messages []struct {
				ID      string    `json:"ID"`
				Created time.Time `json:"Created"`
			} `json:"messages"`
		}
		if err := call(ctx, http.MethodGet, mailURL+"/api/v1/search?query="+url.QueryEscape("to:"+address), "", "", nil, &list); err != nil {
			return "", err
		}
		for _, m := range list.Messages {
			if m.Created.Before(since) {
				continue
			}
			var msg struct {
				Text string `json:"Text"`
				HTML string `json:"HTML"`
			}
			if err := call(ctx, http.MethodGet, mailURL+"/api/v1/message/"+m.ID, "", "", nil, &msg); err != nil {
				return "", err
			}
			for _, match := range tokenIn.FindAllStringSubmatch(msg.Text+msg.HTML, -1) {
				if match[1] == page {
					token, err := url.QueryUnescape(match[2])
					if err != nil {
						return "", err
					}
					return token, nil
				}
			}
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("no %s email for the address within 30 seconds", page)
}
