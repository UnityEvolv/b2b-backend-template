package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/notify"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Every category the service knows can be written to the feed: a category
// the table refused would drop its notification entirely, push and email
// included.
func TestEveryCategoryFitsTheFeed(t *testing.T) {
	f := newFixture(t)
	org := uuid.Must(uuid.NewV7())
	ctx := db.WithActor(context.Background(), db.SystemActor("test"))
	for _, c := range notify.Categories {
		err := f.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
			_, err := store.New(tx).InsertFeedEntry(ctx, store.InsertFeedEntryParams{
				OrgID: org, ID: uuid.Must(uuid.NewV7()), MembershipID: uuid.New(), Category: string(c),
				Kind: "test", Data: []byte("{}"), Link: "/", Items: []byte("[]"),
				OccurredAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			})
			return err
		})
		if err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
}
