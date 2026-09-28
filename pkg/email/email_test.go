package email_test

import (
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
)

func TestNoticeRendersBothBodiesWithTheOrgName(t *testing.T) {
	r, err := email.Render("notice", "Acme", map[string]any{
		"heading": "You have been invited",
		"lines":   []string{"Click the link.", "It expires <soon>."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Subject != "Acme: You have been invited" {
		t.Errorf("subject %q", r.Subject)
	}
	for _, body := range []string{r.HTML, r.Text} {
		if !strings.Contains(body, "on behalf of Acme") || !strings.Contains(body, "Click the link.") {
			t.Errorf("body lacks the org or the lines: %q", body)
		}
	}
	// HTML is escaped; text is plain.
	if !strings.Contains(r.HTML, "It expires &lt;soon&gt;.") || !strings.Contains(r.Text, "It expires <soon>.") {
		t.Errorf("escaping: html %q text %q", r.HTML, r.Text)
	}
}

func TestUnknownTemplateAndBadMessages(t *testing.T) {
	if _, err := email.Render("no-such-template", "Acme", nil); err == nil {
		t.Error("unknown template rendered")
	}
	for _, m := range []email.Message{
		{OrgID: "o", OrgName: "Acme", To: "not an address", Template: "notice"},
		{OrgID: "o", OrgName: "Acme", To: "a@example.com", Template: "nope"},
		{OrgName: "Acme", To: "a@example.com", Template: "notice"},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%+v validated", m)
		}
	}
	if err := (email.Message{OrgID: "o", OrgName: "Acme", To: "Ada <ada@example.com>", Template: "notice"}).Validate(); err != nil {
		t.Errorf("good message refused: %v", err)
	}
}

// Every template has a subject, both bodies, and shows the org's name.
func TestEveryTemplateShowsTheOrg(t *testing.T) {
	for name := range email.Templates {
		r, err := email.Render(name, "Acme Ltd", map[string]any{"heading": "h", "lines": []string{"l"}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Subject == "" || !strings.Contains(r.HTML, "Acme Ltd") || !strings.Contains(r.Text, "Acme Ltd") {
			t.Errorf("%s does not carry the org name in subject/html/text", name)
		}
	}
}
