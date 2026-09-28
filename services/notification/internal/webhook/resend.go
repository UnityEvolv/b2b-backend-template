// Package webhook takes delivery events from Resend: a hard bounce or a
// complaint marks the address so nothing is sent to it again, and marks the
// email itself. Verified (Svix signature over the raw body) and idempotent:
// the same event twice changes nothing the second time.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Resend handles Resend's webhook.
type Resend struct {
	cluster *db.Cluster
	secret  []byte
	logger  *slog.Logger
	now     func() time.Time
}

// New is the handler for events signed with secret ("whsec_…" from Resend).
func New(cluster *db.Cluster, secret string, logger *slog.Logger) (*Resend, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(raw) == 0 {
		return nil, errors.New("webhook: RESEND_WEBHOOK_SECRET is not a whsec_ secret")
	}
	return &Resend{cluster: cluster, secret: raw, logger: logger, now: time.Now}, nil
}

// Tolerance is how old a signed event may be.
const Tolerance = 5 * time.Minute

type event struct {
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Data      struct {
		EmailID string   `json:"email_id"`
		To      []string `json:"to"`
		Bounce  struct {
			Type string `json:"type"`
		} `json:"bounce"`
	} `json:"data"`
}

// ServeHTTP verifies and applies one event.
func (r *Resend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 64<<10))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Unreadable body.")
		return
	}
	id, ts, sigs := req.Header.Get("svix-id"), req.Header.Get("svix-timestamp"), req.Header.Get("svix-signature")
	if !r.verify(id, ts, sigs, body) {
		httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthenticated, "Bad signature.")
		return
	}
	var ev event
	if err := json.Unmarshal(body, &ev); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "Not an event.")
		return
	}
	if err := r.apply(req.Context(), id, ev); err != nil {
		r.logger.Error("webhook failed", "event", id, "type", ev.Type, "error", err)
		httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "Not handled; send it again.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// verify is Svix's scheme: HMAC-SHA256 over "id.timestamp.body", any of the
// space-separated "v1,<base64>" signatures may match, timestamp within tolerance.
func (r *Resend) verify(id, ts, sigs string, body []byte) bool {
	if id == "" || ts == "" || sigs == "" {
		return false
	}
	seconds, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if age := r.now().Sub(time.Unix(seconds, 0)); age > Tolerance || age < -Tolerance {
		return false
	}
	mac := hmac.New(sha256.New, r.secret)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, sig := range strings.Fields(sigs) {
		version, value, ok := strings.Cut(sig, ",")
		if !ok || version != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(value)
		if err == nil && subtle.ConstantTimeCompare(got, want) == 1 {
			return true
		}
	}
	return false
}

func (r *Resend) apply(ctx context.Context, eventID string, ev event) error {
	var reason string
	switch ev.Type {
	case "email.bounced":
		// A soft bounce (a full mailbox) is not a dead address.
		if ev.Data.Bounce.Type != "" && ev.Data.Bounce.Type != "Permanent" {
			return nil
		}
		reason = "bounced"
	case "email.complained":
		reason = "complained"
	default:
		return nil
	}
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	return r.cluster.Tx(ctx, envelope.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		for _, address := range ev.Data.To {
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			if err := q.Suppress(ctx, store.SuppressParams{ID: id, Address: address, Reason: reason, ProviderEventID: pgtype.Text{String: eventID, Valid: true}}); err != nil {
				return err
			}
		}
		if ev.Data.EmailID != "" {
			if _, err := q.MarkEmailBouncedByProviderId(ctx, store.MarkEmailBouncedByProviderIdParams{
				ProviderMessageID: pgtype.Text{String: ev.Data.EmailID, Valid: true},
				LastError:         pgtype.Text{String: reason, Valid: true},
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
