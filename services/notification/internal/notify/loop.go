package notify

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Run is the delivery loop, in this service's own process like the email
// outbox's: what quiet hours held is released when they end, each person's
// digest goes at their chosen time, and once a day the feed and dead devices
// are cleared. There is no scheduler.
func (r *Router) Run(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	lastPurge := time.Time{}
	for {
		if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			r.logger.Error("notification loop failed", "error", err)
		}
		if r.now().Sub(lastPurge) > 24*time.Hour {
			if err := r.Purge(ctx); err != nil && ctx.Err() == nil {
				r.logger.Error("notification purge failed", "error", err)
			}
			lastPurge = r.now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Tick is one pass: held deliveries due, and digests due.
func (r *Router) Tick(ctx context.Context) error {
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	var orgs []uuid.UUID
	err := r.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrgsWithWork(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, org := range orgs {
		if err := r.release(ctx, org); err != nil {
			return err
		}
		if err := r.digests(ctx, org); err != nil {
			return err
		}
	}
	return nil
}

// release sends what quiet hours held, except what expired meanwhile.
func (r *Router) release(ctx context.Context, org uuid.UUID) error {
	var due []store.Held
	err := r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		due, err = store.New(tx).TakeDueHeld(ctx, org)
		return err
	})
	if err != nil {
		return err
	}
	now := r.now()
	for _, h := range due {
		if h.ExpiresAt.Valid && !h.ExpiresAt.Time.After(now) {
			continue
		}
		switch h.Channel {
		case "push":
			var p Payload
			if json.Unmarshal(h.Notification, &p) == nil {
				r.PushTo(ctx, org, h.MembershipID, p.Category, p)
			}
		case "email":
			var held emailHeld
			if json.Unmarshal(h.Notification, &held) != nil {
				continue
			}
			if err := r.emailHeld(ctx, org, h.MembershipID, held.EntryID); err != nil {
				r.logger.Warn("held email not queued", "org_id", org, "membership_id", h.MembershipID, "error", err)
			}
		}
	}
	return nil
}

// emailHeld sends a held email, unless it was read or emailed meanwhile.
func (r *Router) emailHeld(ctx context.Context, org, to, entryID uuid.UUID) error {
	var entries []store.FeedEntry
	err := r.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		entries, err = store.New(tx).DigestItems(ctx, store.DigestItemsParams{OrgID: org, MembershipID: to, Since: time.Time{}})
		return err
	})
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.ID != entryID {
			continue
		}
		person, err := r.people.Person(ctx, org, to)
		if err != nil || !person.Active {
			return err
		}
		return r.emailEntry(ctx, org, to, person, e)
	}
	return nil
}

// digests sends each person whose time has come one email with what they
// have email on for and have not seen, and nothing when there is nothing.
func (r *Router) digests(ctx context.Context, org uuid.UUID) error {
	var candidates []store.DigestCandidatesRow
	err := r.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		candidates, err = store.New(tx).DigestCandidates(ctx, org)
		return err
	})
	if err != nil {
		return err
	}
	now := r.now()
	for _, c := range candidates {
		person, err := r.people.Person(ctx, org, c.MembershipID)
		if err != nil {
			r.logger.Warn("digest recipient unknown", "org_id", org, "membership_id", c.MembershipID, "error", err)
			continue
		}
		if !person.Active {
			continue
		}
		minute := person.WorkStart
		if c.DigestMinute.Valid {
			minute = int(c.DigestMinute.Int32)
		}
		last := time.Time{}
		if c.LastDigestAt.Valid {
			last = c.LastDigestAt.Time
		}
		if !DigestDue(now, person.Zone, minute, last) {
			continue
		}
		if err := r.digest(ctx, org, c.MembershipID, person, last, now); err != nil {
			r.logger.Warn("digest not sent", "org_id", org, "membership_id", c.MembershipID, "error", err)
		}
	}
	return nil
}

func (r *Router) digest(ctx context.Context, org, to uuid.UUID, person Person, last, now time.Time) error {
	s, err := r.settings(ctx, org, to, person.Zone)
	if err != nil {
		return err
	}
	// Everything not yet emailed since the last digest: entries already
	// emailed or read are left out by the query itself.
	since := last
	var entries []store.FeedEntry
	err = r.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		entries, err = store.New(tx).DigestItems(ctx, store.DigestItemsParams{OrgID: org, MembershipID: to, Since: since})
		return err
	})
	if err != nil {
		return err
	}
	var (
		items []map[string]any
		ids   []uuid.UUID
	)
	for _, e := range entries {
		category := Category(e.Category)
		if !s.channels[category].Email {
			continue
		}
		var data map[string]any
		_ = json.Unmarshal(e.Data, &data)
		title, _ := Words(e.Kind, data, int(e.Count))
		items = append(items, map[string]any{"line": title, "link": r.appLink(category, e.Link)})
		ids = append(ids, e.ID)
	}
	if len(items) > 0 {
		if err := r.queueEmail(ctx, org, to, person, Mention, "digest", map[string]any{"items": items}, ids); err != nil {
			return err
		}
	}
	// Recorded either way, so an empty day is not asked about again today.
	return r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		return store.New(tx).TouchDigest(ctx, store.TouchDigestParams{OrgID: org, MembershipID: to, At: pgtype.Timestamptz{Time: now, Valid: true}})
	})
}

// Purge clears feed entries past 30 days and devices unseen for 90.
func (r *Router) Purge(ctx context.Context) error {
	ctx = db.WithActor(ctx, db.SystemActor("notification"))
	var orgs []uuid.UUID
	err := r.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		orgs, err = store.New(tx).OrgsWithFeed(ctx)
		return err
	})
	if err != nil {
		return err
	}
	for _, org := range orgs {
		err := r.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
			q := store.New(tx)
			if _, err := q.PurgeFeed(ctx, org); err != nil {
				return err
			}
			_, err := q.PurgeStaleDevices(ctx, org)
			return err
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}
