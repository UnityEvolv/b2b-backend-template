// Command seed fills a local stack with something to look at (UO-203): one
// organization, and its Owner and one colleague who can sign in with a password.
//
// Everything goes in through the services' own APIs, the way a person would
// put it there: the organization service creates the org, the identity
// service invites each person, the invite and verification emails are read
// back from the local mail catcher. No schema is written across. Running it
// twice changes nothing: the org create carries a fixed idempotency key, and
// a person who can already sign in is left alone.
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
	identity, organization, mail string
	password                     string
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func run(ctx context.Context) error {
	cfg := config{
		identity:     os.Getenv("SEED_IDENTITY_URL"),
		organization: os.Getenv("SEED_ORGANIZATION_URL"),
		mail:         os.Getenv("SEED_MAIL_URL"),
		password:     env("SEED_PASSWORD", "demo-password-change-me"),
	}
	if cfg.identity == "" || cfg.organization == "" || cfg.mail == "" {
		return errors.New("SEED_IDENTITY_URL, SEED_ORGANIZATION_URL and SEED_MAIL_URL are required")
	}
	domain := env("SEED_DOMAIN", "demo.example.test")
	people := []person{
		{Email: "owner@" + domain, Name: "Olivia Owner", Role: "owner", Password: cfg.password},
		{Email: "colleague@" + domain, Name: "Colin Colleague", Role: "user", Password: cfg.password},
	}

	operator, err := localToken(ctx, cfg.identity, map[string]any{"user_id": operatorUserID, "org_id": platformOrg, "membership_id": operatorUserID})
	if err != nil {
		return fmt.Errorf("operator token: %w", err)
	}

	var org struct {
		OrgID string `json:"org_id"`
		Name  string `json:"name"`
	}
	if err := call(ctx, http.MethodPost, cfg.organization+"/v1/organizations", operator, orgKey,
		map[string]any{"name": "Demo Co", "time_zone": env("SEED_TIME_ZONE", "Europe/London")}, &org); err != nil {
		return fmt.Errorf("organization: %w", err)
	}
	fmt.Printf("organization %s (%s)\n", org.Name, org.OrgID)

	for _, p := range people {
		if err := ensurePerson(ctx, cfg, operator, org.OrgID, p); err != nil {
			return fmt.Errorf("%s: %w", p.Email, err)
		}
	}

	fmt.Println()
	fmt.Println("Sign in with either of:")
	for _, p := range people {
		fmt.Printf("  %-40s %s\n", p.Email, p.Password)
	}
	return nil
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
