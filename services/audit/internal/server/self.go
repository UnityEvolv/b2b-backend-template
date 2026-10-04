package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/audit/internal/store"
)

// Record appends an entry from inside this service, with the same checks
// as RecordAuditEvent: what a support session reads of the audit log is
// recorded here (pkg/audit.Impersonation), without a call to itself.
func (s *Server) Record(ctx context.Context, ev audit.Event) error {
	actor := string(ev.Actor)
	if actor == "" {
		a, ok := db.ActorFrom(ctx)
		if !ok {
			return fmt.Errorf("%w: no actor", audit.ErrNotRecorded)
		}
		actor = string(a)
	}
	org, err := uuid.Parse(ev.OrgID)
	if err != nil || !actionShape.MatchString(ev.Action) || !actorShape.MatchString(actor) || ev.TargetType == "" || ev.TargetID == "" ||
		len(ev.TargetType) > maxTextLength || len(ev.TargetID) > maxTextLength {
		return fmt.Errorf("%w: not a valid entry", audit.ErrNotRecorded)
	}
	details := []byte("{}")
	if ev.Details != nil {
		if details, err = json.Marshal(ev.Details); err != nil || len(details) > maxDetails {
			return fmt.Errorf("%w: details", audit.ErrNotRecorded)
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	info := httpx.RequestInfoFrom(ctx)
	params := store.RecordAuditEventParams{OrgID: org, ID: id, OccurredAt: time.Now().UTC(), Actor: actor, Action: ev.Action,
		TargetType: ev.TargetType, TargetID: ev.TargetID, Details: details}
	if addr, err := netip.ParseAddr(info.ClientIP); err == nil {
		params.SourceIp = &addr
	}
	if info.ID != "" {
		params.RequestID = pgtype.Text{String: info.ID, Valid: true}
	}
	err = s.cluster.Tx(db.WithActor(ctx, db.SystemActor("audit")), org.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).RecordAuditEvent(ctx, params)
		return err
	})
	if err != nil {
		return fmt.Errorf("%w: %v", audit.ErrNotRecorded, err)
	}
	return nil
}
