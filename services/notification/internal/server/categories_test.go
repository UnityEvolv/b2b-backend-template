package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/notify"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Every registered category, the template's and a product's, can be
// written to the feed: the table checks none of them, so a category the
// product adds needs no migration.
func TestEveryCategoryFitsTheFeed(t *testing.T) {
	f := newFixture(t)
	org := uuid.Must(uuid.NewV7())
	ctx := db.WithActor(context.Background(), db.SystemActor("test"))
	for _, c := range testCategories().Categories() {
		err := f.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
			_, err := store.New(tx).InsertFeedEntry(ctx, store.InsertFeedEntryParams{
				OrgID: org, ID: uuid.Must(uuid.NewV7()), MembershipID: uuid.New(), Category: c.ID,
				Kind: "test", Data: []byte("{}"), Link: "/", Items: []byte("[]"),
				OccurredAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			})
			return err
		})
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
	}
}

// The registered categories are listed for the preferences pages,
// the template's first, with where each goes and may go; an event or a
// preference naming a category nobody registered is refused.
func TestCategoriesAreRegistered(t *testing.T) {
	f := newNotify(t)
	id, token := f.person(t, authz.User)
	code, out := f.do(t, http.MethodGet, "/v1/notification-categories", token, nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %v", code, out)
	}
	byID := map[string]map[string]any{}
	var order []string
	for _, x := range out["categories"].([]any) {
		c := x.(map[string]any)
		byID[c["id"].(string)] = c
		order = append(order, c["id"].(string))
	}
	want := []string{"security", "membership", "billing", "admin_notices", chat, chatRoom, ping}
	if len(order) != len(want) {
		t.Fatalf("categories %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("categories %v, want %v", order, want)
		}
	}
	if b := byID["billing"]; b["audience"] != "admin" || b["label"] != "Billing" || b["quiet_hours"] != true ||
		b["default_channels"].(map[string]any)["email"] != true || len(b["channels"].([]any)) != 4 {
		t.Errorf("billing: %v", b)
	}
	if p := byID[ping]; p["quiet_hours"] != false || len(p["channels"].([]any)) != 1 || p["channels"].([]any)[0] != "push" || p["audience"] != "member" {
		t.Errorf("ping: %v", p)
	}
	if c := byID[chat]; c["batched"] != true || c["default_channels"].(map[string]any)["digest"] != true {
		t.Errorf("chat: %v", c)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/notification-categories", "", nil); code != http.StatusUnauthorized {
		t.Errorf("signed out: %d", code)
	}

	// An event naming an unregistered category is refused at intake.
	service, err := f.issuer.Issue(auth.Caller{Service: "billing"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"id": uuid.NewString(), "org_id": f.org, "kind": "x", "category": "mention", "recipients": []uuid.UUID{id}, "link": "/"}
	if code, out := f.do(t, http.MethodPost, "/v1/internal/events", service, body); code != http.StatusBadRequest {
		t.Errorf("an unregistered category: %d %v", code, out)
	}
	body["category"] = "billing"
	if code, out := f.do(t, http.MethodPost, "/v1/internal/events", service, body); code != http.StatusAccepted {
		t.Errorf("a registered category: %d %v", code, out)
	}
	if err := f.router.Handle(context.Background(), notify.Event{ID: "x", OrgID: f.org, Kind: "x", Category: "knock", Recipients: []uuid.UUID{id}, Link: "/"}); err == nil {
		t.Error("the router routed an unregistered category")
	}
}
