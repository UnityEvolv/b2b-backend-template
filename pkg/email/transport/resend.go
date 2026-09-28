package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Resend sends through Resend's API with a sending-only key.
type Resend struct {
	// BaseURL is Resend's API, from configuration; a test points it elsewhere.
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

type resendTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Send posts one email. Resend answers 200 with the message id.
func (r Resend) Send(ctx context.Context, m Outgoing) (string, error) {
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var tags []resendTag
	for k, v := range m.Tags {
		tags = append(tags, resendTag{Name: k, Value: v})
	}
	payload := map[string]any{
		"from": m.From, "to": []string{m.To}, "subject": m.Subject, "html": m.HTML, "text": m.Text, "tags": tags,
	}
	if h := m.Headers(); h != nil {
		payload["headers"] = h
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resend: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch {
	case resp.StatusCode == http.StatusOK:
		var answer struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &answer); err != nil || answer.ID == "" {
			return "", errors.New("resend: no message id in the answer")
		}
		return answer.ID, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return "", fmt.Errorf("resend: %d (retry)", resp.StatusCode)
	default:
		var answer struct {
			Name    string `json:"name"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &answer)
		return "", Permanent{Err: fmt.Errorf("resend: %d %s: %s", resp.StatusCode, answer.Name, answer.Message)}
	}
}
