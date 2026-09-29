// Package transport delivers one rendered email to a provider: Resend in the
// cloud, plain SMTP to the mail catcher locally. The outbox decides what to
// retry; a transport only says whether a failure is worth retrying.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Outgoing is one email ready to send.
type Outgoing struct {
	From    string
	To      string
	Subject string
	HTML    string
	Text    string
	// Tags travel to the provider for its own dashboards; never PII.
	Tags map[string]string
	// Unsubscribe is the one-click unsubscribe URL (RFC 8058), sent as the
	// List-Unsubscribe headers; empty for transactional mail.
	Unsubscribe string
}

// Headers is the extra headers m carries.
func (m Outgoing) Headers() map[string]string {
	if m.Unsubscribe == "" {
		return nil
	}
	return map[string]string{"List-Unsubscribe": "<" + m.Unsubscribe + ">", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"}
}

// Transport sends.
type Transport interface {
	// Send delivers m and returns the provider's message id. A Permanent
	// error is not retried; anything else is.
	Send(ctx context.Context, m Outgoing) (providerID string, err error)
}

// Permanent marks a failure that will not change on retry: a bad address, a
// refused sender, a provider rejecting the content.
type Permanent struct{ Err error }

func (p Permanent) Error() string { return "permanent: " + p.Err.Error() }
func (p Permanent) Unwrap() error { return p.Err }

// IsPermanent reports whether err is not worth retrying.
func IsPermanent(err error) bool {
	var p Permanent
	return errors.As(err, &p)
}

// SMTP sends to a plain SMTP server with no authentication: the local mail
// catcher. Never a real provider.
type SMTP struct {
	Addr string
}

// Send delivers over SMTP as a two-part message.
func (s SMTP) Send(ctx context.Context, m Outgoing) (string, error) {
	id := fmt.Sprintf("%d@local", time.Now().UnixNano())
	boundary := "part-" + strings.ReplaceAll(id, "@", "-")
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s>\r\nMIME-Version: 1.0\r\n", m.From, m.To, m.Subject, id)
	for k, v := range m.Headers() {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", boundary, m.Text)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n", boundary, m.HTML)
	fmt.Fprintf(&b, "--%s--\r\n", boundary)

	// The envelope sender is the bare address; the display name stays in the header.
	sender := m.From
	if parsed, err := mail.ParseAddress(m.From); err == nil {
		sender = parsed.Address
	}
	recipient := m.To
	if parsed, err := mail.ParseAddress(m.To); err == nil {
		recipient = parsed.Address
	}
	done := make(chan error, 1)
	go func() { done <- smtp.SendMail(s.Addr, nil, sender, []string{recipient}, []byte(b.String())) }()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("smtp %s: %w", s.Addr, err)
		}
		return id, nil
	}
}
