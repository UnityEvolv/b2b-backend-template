package server_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// An org's notification rows go out in its export with no push token or
// email body; a purge leaves nothing of it and another org untouched; a
// person's export has only their own rows; forgetting a membership deletes
// them.
func TestOrgData(t *testing.T) {
	f := newNotify(t)
	service := func(name string) string {
		token, err := f.issuer.Issue(auth.Caller{Service: name}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	organization, user, billing := service("organization"), service("user"), service("billing")
	acme := f.org

	ana, anaToken := f.person(t, authz.User)
	ben, _ := f.person(t, authz.User)
	f.device(t, anaToken, "android")
	f.device(t, anaToken, "web")
	f.do(t, http.MethodPut, f.path("/notification-preferences"), anaToken, map[string]any{
		"channels": map[string]any{chat: map[string]any{"in_app": true, "push": true, "email": true, "digest": false}}, "push_previews": true, "muted": []string{},
		"quiet_hours": map[string]any{"enabled": false, "start_minute": 0, "end_minute": 0, "days": []int{}},
	})
	f.emit(t, mention(ana, uuid.NewString()))
	f.emit(t, mention(ben, uuid.NewString()))
	if code, _ := f.do(t, http.MethodPost, f.path("/notification-preferences/test"), anaToken, map[string]any{"channel": "email"}); code != http.StatusAccepted {
		t.Fatalf("test email: %d", code)
	}
	// Another org, with its own person and feed.
	globex := uuid.Must(uuid.NewV7())
	f.org = globex
	gus, gusToken := f.person(t, authz.User)
	f.device(t, gusToken, "android")
	f.emit(t, mention(gus, uuid.NewString()))
	f.org = acme

	path := "/v1/internal/organizations/" + acme.String() + "/data"
	forget := "/v1/internal/organizations/" + acme.String() + "/memberships/" + ana.String() + "/data"
	for _, token := range []string{user, anaToken} {
		if code, _ := f.do(t, http.MethodGet, path, token, nil); code != http.StatusForbidden {
			t.Errorf("export by another caller: %d", code)
		}
		if code, _ := f.do(t, http.MethodDelete, path, token, nil); code != http.StatusForbidden {
			t.Errorf("purge by another caller: %d", code)
		}
		if code, _ := f.do(t, http.MethodGet, "/v1/internal/users/"+uuid.NewString()+"/data", token, nil); code != http.StatusForbidden {
			t.Errorf("personal export by another caller: %d", code)
		}
	}
	if code, _ := f.do(t, http.MethodDelete, forget, billing, nil); code != http.StatusForbidden {
		t.Errorf("forget by the billing service: %d", code)
	}

	code, part := f.do(t, http.MethodGet, path, organization, nil)
	if code != http.StatusOK || part["service"] != "notification" {
		t.Fatalf("export: %d %v", code, part)
	}
	data := part["data"].(map[string]any)
	if len(data["devices"].([]any)) != 2 || len(data["feed_entries"].([]any)) != 2 || len(data["preferences"].([]any)) == 0 || len(data["emails"].([]any)) != 2 {
		t.Errorf("export: %v", data)
	}
	raw, _ := json.Marshal(part)
	for _, secret := range []string{"fcm-", "push.example.org", "p256dh", "token_hash", "session_id", "html_body", "text_body", "unsubscribe_url", gus.String()} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the export has %q: %s", secret, raw)
		}
	}

	personal := func(mbr uuid.UUID) map[string]any {
		t.Helper()
		q := url.Values{"membership": {acme.String() + ":" + mbr.String()}}
		code, out := f.do(t, http.MethodGet, "/v1/internal/users/"+uuid.NewString()+"/data?"+q.Encode(), organization, nil)
		if code != http.StatusOK {
			t.Fatalf("personal export: %d %v", code, out)
		}
		return out["data"].(map[string]any)["memberships"].([]any)[0].(map[string]any)
	}
	mine := personal(ana)
	if len(mine["preferences"].([]any)) != 1 || len(mine["feed_entries"].([]any)) != 1 || len(mine["devices"].([]any)) != 2 {
		t.Errorf("hers: %v", mine)
	}
	for _, e := range mine["feed_entries"].([]any) {
		if e.(map[string]any)["membership_id"] != ana.String() {
			t.Errorf("someone else's entry: %v", e)
		}
	}
	if raw, _ := json.Marshal(mine); strings.Contains(string(raw), "fcm-") {
		t.Errorf("a push token in her export: %s", raw)
	}
	if code, _ := f.do(t, http.MethodGet, "/v1/internal/users/"+uuid.NewString()+"/data?membership=nonsense", organization, nil); code != http.StatusBadRequest {
		t.Errorf("a bad membership: %d", code)
	}

	// Forgetting Ana leaves Ben.
	if code, _ := f.do(t, http.MethodDelete, forget, user, nil); code != http.StatusNoContent {
		t.Fatalf("forget: %d", code)
	}
	mine = personal(ana)
	if len(mine["preferences"].([]any)) != 0 || len(mine["feed_entries"].([]any)) != 0 || len(mine["devices"].([]any)) != 0 {
		t.Errorf("left of her: %v", mine)
	}
	if his := personal(ben); len(his["feed_entries"].([]any)) != 1 {
		t.Errorf("his: %v", his)
	}

	for i := range 2 {
		code, out := f.do(t, http.MethodDelete, path, organization, nil)
		if code != http.StatusOK || out["remaining"] != float64(0) {
			t.Fatalf("purge %d: %d %v", i+1, code, out)
		}
	}
	_, part = f.do(t, http.MethodGet, path, organization, nil)
	for table, rows := range part["data"].(map[string]any) {
		if list, ok := rows.([]any); ok && len(list) != 0 {
			t.Errorf("%s left after the purge: %v", table, list)
		}
	}
	_, other := f.do(t, http.MethodGet, "/v1/internal/organizations/"+globex.String()+"/data", organization, nil)
	if d := other["data"].(map[string]any); len(d["devices"].([]any)) != 1 || len(d["feed_entries"].([]any)) != 1 {
		t.Errorf("globex touched: %v", d)
	}
}
