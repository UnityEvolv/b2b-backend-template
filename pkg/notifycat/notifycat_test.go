package notifycat_test

import (
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/notifycat"
)

func registry() *notifycat.Registry {
	r := notifycat.New()
	r.Register(notifycat.Category{ID: "chat", Audience: notifycat.Member, Default: notifycat.Channels{InApp: true, Push: true}})
	r.Register(notifycat.Category{ID: "ping", Audience: notifycat.Member, Default: notifycat.Channels{Push: true}, Channels: []notifycat.Channel{notifycat.Push}})
	return r
}

// A person's choice, else the org's, else the category's; never a channel
// the category may not use; a stored category no longer registered is gone.
func TestResolve(t *testing.T) {
	got := registry().Resolve(
		[]byte(`{"chat":{"in_app":true,"push":false,"email":true},"ping":{"in_app":true,"push":false,"email":true,"digest":true},"reminder":{"push":true}}`),
		[]byte(`{"security":{"in_app":true,"push":false,"email":false,"digest":true}}`))
	if c := got["chat"]; c.Push || !c.Email {
		t.Errorf("the person's choice: %+v", c)
	}
	if s := got["security"]; s.Push || s.Email || !s.Digest {
		t.Errorf("the org's default where the person chose nothing: %+v", s)
	}
	if p := got["ping"]; p != (notifycat.Channels{}) {
		t.Errorf("a ping only ever pushes: %+v", p)
	}
	if b := got[notifycat.Billing]; !b.Email || !b.InApp || b.Push {
		t.Errorf("the category's default: %+v", b)
	}
	if _, ok := got["reminder"]; ok {
		t.Error("an unregistered category resolved")
	}
}

// The words: a kind's copy filled in from the data, fallbacks for what is
// missing, the batch title with its count, and the event's own heading
// for a category with no copy.
func TestWords(t *testing.T) {
	r := notifycat.New()
	r.Register(notifycat.Category{ID: "project_shared", Audience: notifycat.Member, Default: notifycat.Channels{InApp: true},
		Copy: map[string]notifycat.Copy{"": {Title: "{by|Someone} shared {project}", Line: "Open it.", Many: "{count} projects shared with you"}}})
	if title, line := r.Words("project_shared", "shared", map[string]any{"by": "Ana", "project": "Apollo"}, 1); title != "Ana shared Apollo" || line != "Open it." {
		t.Errorf("%q %q", title, line)
	}
	if title, _ := r.Words("project_shared", "shared", map[string]any{"project": "Apollo"}, 3); title != "3 projects shared with you" {
		t.Errorf("batch: %q", title)
	}
	if title, _ := r.Words(notifycat.Security, "new_sign_in", nil, 1); title != "New sign-in to your account" {
		t.Errorf("security: %q", title)
	}
	if title, line := r.Words(notifycat.Billing, "payment_failed", map[string]any{"heading": "Payment failed", "line": "Update the card."}, 1); title != "Payment failed" || line != "Update the card." {
		t.Errorf("billing: %q %q", title, line)
	}
}

// A category that is malformed, for nobody, defaults to a channel it may
// not use, or takes the digest's name, is refused.
func TestParse(t *testing.T) {
	cs, err := notifycat.Parse(`[{"id":"project_shared","label":"Shared projects","audience":"member","default":{"in_app":true,"digest":true},"quiet_hours":true,
		"copy":{"":{"title":"{by|Someone} shared a project"}}}]`)
	if err != nil || len(cs) != 1 || cs[0].Label != "Shared projects" || !cs[0].Default.Digest || !cs[0].QuietHours {
		t.Fatalf("%+v %v", cs, err)
	}
	for _, bad := range []string{
		`[{"id":"Bad","audience":"member"}]`,
		`[{"id":"x","audience":"everyone"}]`,
		`[{"id":"x","audience":"member","default":{"email":true},"channels":["push"]}]`,
		`[{"id":"digest","audience":"member"}]`,
		`[{"id":"x","audience":"member","channels":["sms"]}]`,
		`[{"id":"x","audience":"member","colour":"red"}]`,
	} {
		if _, err := notifycat.Parse(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
