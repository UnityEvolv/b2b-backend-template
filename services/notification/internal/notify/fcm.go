package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// FCM sends to Android devices with Firebase Cloud Messaging's HTTP v1 API,
// straight from this service. The token source is the service's own Google
// identity, which the Firebase project grants the messaging role; nothing
// else of Firebase is used.
type FCM struct {
	base    string
	project string
	tokens  oauth2.TokenSource
	http    *http.Client
	now     func() time.Time
}

// FCMScope is the OAuth scope FCM's send endpoint wants.
const FCMScope = "https://www.googleapis.com/auth/firebase.messaging"

// NewFCM is FCM for project, at base (the API's origin, from config).
func NewFCM(base, project string, tokens oauth2.TokenSource, client *http.Client) *FCM {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &FCM{base: strings.TrimRight(base, "/"), project: project, tokens: tokens, http: client, now: time.Now}
}

// Push sends p to one registration token, as data plus a notification, with
// the expiry as the time to live.
func (f *FCM) Push(ctx context.Context, token string, p Payload) error {
	ttl := p.TTL(f.now())
	if ttl <= 0 {
		return nil
	}
	android := map[string]any{"priority": "HIGH", "ttl": fmt.Sprintf("%ds", int(ttl/time.Second))}
	if p.Collapse != "" {
		android["collapse_key"] = p.Collapse
	}
	data := map[string]string{"category": string(p.Category), "link": p.Link}
	if !p.Expires.IsZero() {
		data["expires_at"] = p.Expires.UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(map[string]any{"message": map[string]any{
		"token":        token,
		"notification": map[string]string{"title": p.Title, "body": p.Body},
		"data":         data,
		"android":      android,
	}})
	if err != nil {
		return err
	}
	bearer, err := f.tokens.Token()
	if err != nil {
		return ErrTransient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.base+"/v1/projects/"+f.project+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer.SetAuthHeader(req)
	resp, err := f.http.Do(req)
	if err != nil {
		return ErrTransient
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || bytes.Contains(answer, []byte("UNREGISTERED")):
		return ErrInvalidToken
	case resp.StatusCode == http.StatusBadRequest && bytes.Contains(answer, []byte("registration token")):
		return ErrInvalidToken
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	case resp.StatusCode >= 500:
		return ErrTransient
	default:
		return fmt.Errorf("fcm: answered %d", resp.StatusCode)
	}
}
