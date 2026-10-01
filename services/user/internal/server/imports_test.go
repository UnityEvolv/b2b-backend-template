package server_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// importSheet posts a CSV with an optional mapping.
func importSheet(t *testing.T, f *fixture, token, org, csv, mapping string, dryRun bool) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, _ := w.CreateFormFile("file", "people.csv")
	part.Write([]byte(csv))
	if mapping != "" {
		w.WriteField("mapping", mapping)
	}
	w.Close()
	path := "/v1/organizations/" + org + "/imports"
	if dryRun {
		path += "?dry_run=true"
	}
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec.Code, decode(t, rec)
}

func rowsByNumber(out map[string]any) map[float64]map[string]any {
	rows := map[float64]map[string]any{}
	for _, r := range out["rows"].([]any) {
		m := r.(map[string]any)
		rows[m["row"].(float64)] = m
	}
	return rows
}

func firstError(row map[string]any) string {
	errs, _ := row["errors"].([]any)
	if len(errs) == 0 {
		return ""
	}
	return errs[0].(map[string]any)["code"].(string)
}

// A sheet with mixed valid and invalid rows
// imports the valid ones and reports the rest row by row.
func TestBulkImportInvitesTheValidRowsAndReportsTheRest(t *testing.T) {
	f := newAPI(t)
	// acme is on the free plan (ten users); one member already.
	existing := f.signIn(t, acme, "here@acme.com", "Here", nil)
	_ = existing
	adminID := uuid.NewString()
	// An Owner: the one role that may hand out admin and billing_admin.
	f.grants[acme.String()+"/"+adminID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	admin, _ := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: adminID}, 3600e9)
	user := f.person(t, uuid.NewString(), acme.String(), uuid.NewString())

	sheet := strings.Join([]string{
		"E-mail,Full name,Role",
		"ada@example.com,Ada Lovelace,admin",    // 2: fine
		"bob@example.com,,",                     // 3: no name
		"not-an-address,Carol,",                 // 4: bad address
		",Dave,",                                // 5: no email
		"ada@example.com,Ada Again,",            // 6: duplicate
		"here@acme.com,Here Already,",           // 7: already a member
		"eve@example.com,Eve,owner",             // 8: a role nobody imports
		"frank@example.com,Frank,billing_admin", // 9: fine
		"grace@example.com,Grace,user",          // 10: refused by identity
	}, "\n")
	mapping := `{"email":"E-mail","name":"Full name","role":"Role"}`

	// Permission, and the mapping must name real columns.
	if status, _ := importSheet(t, f, user, acme.String(), sheet, mapping, true); status != http.StatusForbidden {
		t.Errorf("a User importing: %d", status)
	}
	if status, out := importSheet(t, f, admin, acme.String(), sheet, `{"email":"Address"}`, true); status != http.StatusBadRequest {
		t.Errorf("mapping to a missing column: %d %v", status, out)
	}
	if status, out := importSheet(t, f, admin, acme.String(), "", mapping, true); status != http.StatusBadRequest {
		t.Errorf("empty file: %d %v", status, out)
	}

	// A dry run says what would happen and sends nothing.
	f.sessions.refuse = map[string]string{"grace@example.com": "invite.already_member"}
	status, out := importSheet(t, f, admin, acme.String(), sheet, mapping, true)
	if status != http.StatusOK || out["dry_run"] != true {
		t.Fatalf("dry run: %d %v", status, out)
	}
	rows := rowsByNumber(out)
	for row, want := range map[float64]string{2: "", 3: "missing_name", 4: "email_invalid", 5: "missing_email", 6: "duplicate", 7: "already_member", 8: "role_invalid", 9: "", 10: ""} {
		if got := firstError(rows[row]); got != want {
			t.Errorf("row %v: %q, want %q (%v)", row, got, want, rows[row])
		}
	}
	if rows[2]["status"] != "would_invite" || rows[9]["role"] != "billing_admin" || rows[3]["status"] != "failed" {
		t.Errorf("dry run rows: %v", rows)
	}
	summary := out["summary"].(map[string]any)
	if summary["rows"] != float64(9) || summary["valid"] != float64(3) || summary["invalid"] != float64(6) || summary["invited"] != float64(0) {
		t.Errorf("dry run summary: %v", summary)
	}
	if len(f.sessions.invites) != 0 {
		t.Error("a dry run sent invites")
	}

	// For real: the valid rows are invited, one refused by the identity
	// service is reported, nothing is dropped, and it is audited.
	status, out = importSheet(t, f, admin, acme.String(), sheet, mapping, false)
	if status != http.StatusOK {
		t.Fatalf("import: %d %v", status, out)
	}
	rows = rowsByNumber(out)
	if rows[2]["status"] != "invited" || rows[9]["status"] != "invited" || rows[10]["status"] != "failed" || firstError(rows[10]) != "already_member" {
		t.Errorf("import rows: %v %v %v", rows[2], rows[9], rows[10])
	}
	summary = out["summary"].(map[string]any)
	if summary["invited"] != float64(2) || summary["invalid"] != float64(7) {
		t.Errorf("import summary: %v", summary)
	}
	if len(f.sessions.invites) != 2 || f.sessions.invites[0].Role != "admin" || f.sessions.invites[0].Email != "ada@example.com" || f.sessions.invites[0].InvitedByMembershipID.String() != adminID {
		t.Errorf("invites sent: %+v", f.sessions.invites)
	}
	audited := false
	for _, a := range f.recorder.actions() {
		if a == "users.imported" {
			audited = true
		}
	}
	if !audited {
		t.Error("import not audited")
	}

	// The plan's cap: the free plan allows ten; nine seats are left after
	// the one member, so the tenth new row is reported, not dropped.
	var big strings.Builder
	big.WriteString("email,name\n")
	for i := 0; i < 12; i++ {
		big.WriteString(strings.ReplaceAll("pN@example.com,Person N\n", "N", string(rune('a'+i))))
	}
	f.sessions.refuse = nil
	_, out = importSheet(t, f, admin, acme.String(), big.String(), "", true)
	rows = rowsByNumber(out)
	if firstError(rows[10]) != "" || firstError(rows[11]) != "plan_limit" || firstError(rows[13]) != "plan_limit" {
		t.Errorf("cap: row 10 %q, row 11 %q, row 13 %q", firstError(rows[10]), firstError(rows[11]), firstError(rows[13]))
	}
}

// The import page's mapping step: the sheet's own column names and a few
// rows come back, nothing is invited, and only the users permission reads it.
func TestImportColumnsReadTheHeaderAndASample(t *testing.T) {
	f := newAPI(t)
	adminID := uuid.NewString()
	f.grants[acme.String()+"/"+adminID] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	admin, _ := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: adminID}, 3600e9)
	user := f.person(t, uuid.NewString(), acme.String(), uuid.NewString())

	rows := []string{"E-mail,Full name,Team"}
	for i := 0; i < 8; i++ {
		rows = append(rows, "p"+string(rune('a'+i))+"@example.com,Person,Ops")
	}
	post := func(token string) (int, map[string]any) {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		part, _ := w.CreateFormFile("file", "people.csv")
		part.Write([]byte(strings.Join(rows, "\n")))
		w.Close()
		req := httptest.NewRequest(http.MethodPost, "/v1/organizations/"+acme.String()+"/imports/columns", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec.Code, decode(t, rec)
	}
	if code, _ := post(user); code != http.StatusForbidden {
		t.Errorf("a User reading columns: %d", code)
	}
	code, out := post(admin)
	if code != http.StatusOK {
		t.Fatalf("columns: %d %v", code, out)
	}
	cols := out["columns"].([]any)
	if len(cols) != 3 || cols[0] != "E-mail" || cols[2] != "Team" {
		t.Errorf("columns: %v", cols)
	}
	if out["rows"] != float64(8) || len(out["sample"].([]any)) != 5 {
		t.Errorf("rows %v, sample %d", out["rows"], len(out["sample"].([]any)))
	}
}

// Every row is checked against what the importer may invite, the defaulted
// role included: a Billing Admin granted users manages nobody, so a row with
// no role (a User) is refused as one naming user would be, and nothing is
// sent. An Admin may still import Users with the role left blank.
func TestImportChecksTheDefaultedRoleToo(t *testing.T) {
	f := newAPI(t)
	billingID, adminID := uuid.NewString(), uuid.NewString()
	f.grants[acme.String()+"/"+billingID] = authz.Grant{Role: authz.BillingAdmin, Permissions: []authz.Permission{authz.Billing, authz.Users}}
	f.grants[acme.String()+"/"+adminID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	billing, _ := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: billingID}, 3600e9)
	admin, _ := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: acme.String(), MembershipID: adminID}, 3600e9)

	sheet := "email,name,role\nnorole@example.com,No Role,\nuser@example.com,Named User,user\n"
	status, out := importSheet(t, f, billing, acme.String(), sheet, "", false)
	if status != http.StatusOK {
		t.Fatalf("import: %d %v", status, out)
	}
	rows := rowsByNumber(out)
	if firstError(rows[2]) != "role_invalid" || firstError(rows[3]) != "role_invalid" || rows[2]["status"] != "failed" {
		t.Errorf("a Billing Admin's rows: %v %v", rows[2], rows[3])
	}
	if len(f.sessions.invites) != 0 {
		t.Fatalf("a Billing Admin's import sent invites: %+v", f.sessions.invites)
	}

	status, out = importSheet(t, f, admin, acme.String(), sheet, "", false)
	rows = rowsByNumber(out)
	if status != http.StatusOK || rows[2]["status"] != "invited" || rows[2]["role"] != "user" || rows[3]["status"] != "invited" {
		t.Errorf("an Admin's import: %d %v", status, out)
	}
}
