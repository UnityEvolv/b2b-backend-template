package email

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
)

// Template is one kind of email: a subject, an HTML body and a plain-text
// body rendered from the same data. Every template shows the org's name, so
// the recipient knows who wrote.
type Template struct {
	Subject string
	HTML    string
	Text    string
}

// Rendered is a template filled in.
type Rendered struct {
	Subject string
	HTML    string
	Text    string
}

// Templates is every template a service may send. A story that needs a new
// kind of email adds one here, with both bodies.
var Templates = map[string]Template{
	// A plain notice: a heading and some lines. The first consumer, and what
	// the setup check sends.
	"notice": {
		Subject: `{{.OrgName}}: {{.Data.heading}}`,
		HTML: `<p>{{.Data.heading}}</p>
{{range .Data.lines}}<p>{{.}}</p>
{{end}}<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `{{.Data.heading}}

{{range .Data.lines}}{{.}}
{{end}}
Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// Prove ownership of an email address before a local account can sign
	// in (UO-67). link is the app's page with the token; hours is how long it
	// lasts.
	"verify_email": {
		Subject: `{{.OrgName}}: verify your email address`,
		HTML: `<p>{{.OrgName}} has added you to unityofis. Confirm that this is your address to continue:</p>
<p><a href="{{.Data.link}}">Verify my email address</a></p>
<p>The link works once and for {{.Data.hours}} hours. If you did not expect this email, ignore it; nothing happens without the link.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `{{.OrgName}} has added you to unityofis. Confirm that this is your address to continue:

{{.Data.link}}

The link works once and for {{.Data.hours}} hours. If you did not expect this email, ignore it; nothing happens without the link.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// Ownership transfer (UO-86): asked of the target, and told to both when
	// it happens. link is the page in the admin app; days is how long the
	// request lasts.
	"ownership_transfer_requested": {
		Subject: `{{.OrgName}}: you are asked to take ownership`,
		HTML: `<p>The Owner of {{.OrgName}} on unityofis has asked you to become its Owner. Nothing changes until you accept.</p>
<p><a href="{{.Data.link}}">Review the request</a></p>
<p>The request lasts {{.Data.days}} days. If you do nothing, it expires and nothing changes.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `The Owner of {{.OrgName}} on unityofis has asked you to become its Owner. Nothing changes until you accept.

{{.Data.link}}

The request lasts {{.Data.days}} days. If you do nothing, it expires and nothing changes.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	"ownership_transferred": {
		Subject: `{{.OrgName}}: ownership has been transferred`,
		HTML: `<p>Ownership of {{.OrgName}} on unityofis has been transferred. {{.Data.line}}</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `Ownership of {{.OrgName}} on unityofis has been transferred. {{.Data.line}}

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// A self-serve signup (UO-55): prove the address before the org is made.
	// OrgName is the org the person is about to create; link is the app's
	// page with the token; hours is how long it lasts.
	"signup_verify": {
		Subject: `Confirm your email to create {{.OrgName}} on unityofis`,
		HTML: `<p>You asked to create {{.OrgName}} on unityofis. Confirm that this is your address to continue:</p>
<p><a href="{{.Data.link}}">Create my organization</a></p>
<p>The link works once and for {{.Data.hours}} hours. If you did not ask for this, ignore it; nothing is created without the link.</p>
<p style="color:#666;font-size:12px">Sent by unityofis.</p>`,
		Text: `You asked to create {{.OrgName}} on unityofis. Confirm that this is your address to continue:

{{.Data.link}}

The link works once and for {{.Data.hours}} hours. If you did not ask for this, ignore it; nothing is created without the link.

Sent by unityofis.`,
	},
	// An invitation (UO-54): into the org, or as a guest into one room. link
	// is the app's page with the token; what is a sentence saying which
	// ("to join Acme's office", "as a guest to the Design room"); purpose
	// is the inviter's note, if any; until is when the link stops working.
	"invite": {
		Subject: `{{.OrgName}}: you are invited`,
		HTML: `<p>{{.OrgName}} has invited you {{.Data.what}} on unityofis.</p>
{{if .Data.purpose}}<p>Purpose: {{.Data.purpose}}</p>
{{end}}<p><a href="{{.Data.link}}">Accept the invitation</a></p>
<p>The link works once and until {{.Data.until}}. If you did not expect this email, ignore it; nothing happens without the link.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `{{.OrgName}} has invited you {{.Data.what}} on unityofis.
{{if .Data.purpose}}
Purpose: {{.Data.purpose}}
{{end}}
{{.Data.link}}

The link works once and until {{.Data.until}}. If you did not expect this email, ignore it; nothing happens without the link.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// A forgotten password (UO-56). link is the app's page with the token;
	// minutes is how long it lasts.
	"reset_password": {
		Subject: `{{.OrgName}}: reset your password`,
		HTML: `<p>Someone asked to reset the unityofis password for this address. If it was you, choose a new one here:</p>
<p><a href="{{.Data.link}}">Reset my password</a></p>
<p>The link works once and for {{.Data.minutes}} minutes. If it was not you, ignore this email; your password stays as it is.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `Someone asked to reset the unityofis password for this address. If it was you, choose a new one here:

{{.Data.link}}

The link works once and for {{.Data.minutes}} minutes. If it was not you, ignore this email; your password stays as it is.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// One notification, when it must be known now (UO-177): heading, line,
	// link into the app, and preferences, where this kind can be turned off.
	"notification": {
		Subject: `{{.OrgName}}: {{.Data.heading}}`,
		HTML: `<p><strong>{{.Data.heading}}</strong></p>
<p>{{.Data.line}}</p>
<p><a href="{{.Data.link}}">Open in unityofis</a></p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}. <a href="{{.Data.preferences}}">Stop these emails</a> or change what reaches you.</p>`,
		Text: `{{.Data.heading}}

{{.Data.line}}

{{.Data.link}}

Sent by unityofis on behalf of {{.OrgName}}. Stop these emails: {{.Data.preferences}}`,
	},
	// The daily digest (UO-177): what the person has email on for and has not
	// seen, one line each with its link.
	"digest": {
		Subject: `{{.OrgName}}: what you missed`,
		HTML: `<p><strong>While you were away</strong></p>
<ul>{{range .Data.items}}<li><a href="{{.link}}">{{.line}}</a></li>{{end}}</ul>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}, once a day at the time you chose. <a href="{{.Data.preferences}}">Change or stop the digest</a>.</p>`,
		Text: `While you were away:
{{range .Data.items}}
- {{.line}}: {{.link}}{{end}}

Sent by unityofis on behalf of {{.OrgName}}, once a day at the time you chose. Change or stop the digest: {{.Data.preferences}}`,
	},
	// An export is ready (UO-184): a link that lasts days days. kind is
	// "organization" or "personal".
	"export_ready": {
		Subject: `{{.OrgName}}: your data export is ready`,
		HTML: `<p>The {{.Data.kind}} data export you asked for is ready to download.</p>
<p><a href="{{.Data.link}}">Download the export</a></p>
<p>The link works for {{.Data.days}} days. It is a zip of JSON files and attachments; the README inside describes each file.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `The {{.Data.kind}} data export you asked for is ready to download.

{{.Data.link}}

The link works for {{.Data.days}} days. It is a zip of JSON files and attachments; the README inside describes each file.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// An org is closing (UO-183): told to its Owners, with the date it is
	// deleted and how to reverse it before then.
	"organization_closing": {
		Subject: `{{.OrgName}} is closing`,
		HTML: `<p>{{.OrgName}} has been closed on unityofis. Nobody can sign in to it now.</p>
<p>Everything in it will be permanently deleted on {{.Data.purge_date}}. Until then an Owner can reopen it from the sign-in page, and everything comes back as it was.</p>
<p><a href="{{.Data.link}}">Reopen {{.OrgName}}</a></p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `{{.OrgName}} has been closed on unityofis. Nobody can sign in to it now.

Everything in it will be permanently deleted on {{.Data.purge_date}}. Until then an Owner can reopen it from the sign-in page, and everything comes back as it was.

{{.Data.link}}

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// A new sign-in address to confirm (UO-184).
	"email_change_verify": {
		Subject: `{{.OrgName}}: confirm your new email address`,
		HTML: `<p>You asked to sign in to unityofis with this address from now on. Confirm it to make the change:</p>
<p><a href="{{.Data.link}}">Use this address</a></p>
<p>The link works once and for {{.Data.hours}} hours. If you did not ask for this, ignore it; nothing changes without the link.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `You asked to sign in to unityofis with this address from now on. Confirm it to make the change:

{{.Data.link}}

The link works once and for {{.Data.hours}} hours. If you did not ask for this, ignore it; nothing changes without the link.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// The old address is told, with an hour to undo it (UO-184).
	"email_changed": {
		Subject: `{{.OrgName}}: your sign-in email was changed`,
		HTML: `<p>Your unityofis sign-in email was changed to {{.Data.new_email}}.</p>
<p>If this was not you, undo it within the hour:</p>
<p><a href="{{.Data.link}}">Undo the change</a></p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `Your unityofis sign-in email was changed to {{.Data.new_email}}.

If this was not you, undo it within the hour:

{{.Data.link}}

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
	// Account deletion is scheduled (UO-184); signing in cancels it.
	"account_deletion_scheduled": {
		Subject: `{{.OrgName}}: your account will be deleted`,
		HTML: `<p>Your unityofis account is scheduled to be deleted on {{.Data.delete_date}}, with everything about you in every organization you belong to.</p>
<p>Changed your mind? Sign in before then and the deletion is cancelled.</p>
<p style="color:#666;font-size:12px">Sent by unityofis on behalf of {{.OrgName}}.</p>`,
		Text: `Your unityofis account is scheduled to be deleted on {{.Data.delete_date}}, with everything about you in every organization you belong to.

Changed your mind? Sign in before then and the deletion is cancelled.

Sent by unityofis on behalf of {{.OrgName}}.`,
	},
}

type templateData struct {
	OrgName string
	Data    map[string]any
}

// Render fills template name with the org's name and data. HTML escaping
// happens in the HTML body only; the text body is plain.
func Render(name, orgName string, data map[string]any) (Rendered, error) {
	t, ok := Templates[name]
	if !ok {
		return Rendered{}, fmt.Errorf("email: no template %q", name)
	}
	if data == nil {
		data = map[string]any{}
	}
	d := templateData{OrgName: orgName, Data: data}

	subject, err := renderText("subject", t.Subject, d)
	if err != nil {
		return Rendered{}, err
	}
	text, err := renderText("text", t.Text, d)
	if err != nil {
		return Rendered{}, err
	}
	html, err := htmltemplate.New("html").Parse(t.HTML)
	if err != nil {
		return Rendered{}, fmt.Errorf("email: template %s html: %w", name, err)
	}
	var out bytes.Buffer
	if err := html.Execute(&out, d); err != nil {
		return Rendered{}, fmt.Errorf("email: template %s html: %w", name, err)
	}
	return Rendered{Subject: strings.TrimSpace(subject), HTML: out.String(), Text: strings.TrimSpace(text) + "\n"}, nil
}

func renderText(part, src string, d templateData) (string, error) {
	t, err := texttemplate.New(part).Parse(src)
	if err != nil {
		return "", fmt.Errorf("email: %s: %w", part, err)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, d); err != nil {
		return "", fmt.Errorf("email: %s: %w", part, err)
	}
	return out.String(), nil
}
