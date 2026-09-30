package server_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/dataowner"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/livebus"
	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/server"
)

// platform, data and files are the other services and the bucket, in memory.
type offFakes struct {
	mu        sync.Mutex
	revoked   []uuid.UUID
	billed    []uuid.UUID
	expired   map[uuid.UUID]time.Time
	emails    map[uuid.UUID]string
	purged    map[string]int
	holdOut   string // a service whose purge leaves rows
	failing   string // a service whose every call fails
	exported  map[string]int
	purgeLog  []string // every purge call, in order
	live      []livebus.Event
	objects   map[string][]byte
	deletedAt []string
}

func newOffFakes() *offFakes {
	return &offFakes{expired: map[uuid.UUID]time.Time{}, emails: map[uuid.UUID]string{}, purged: map[string]int{}, exported: map[string]int{}, objects: map[string][]byte{}}
}

func (f *offFakes) RevokeOrgSessions(_ context.Context, org uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, org)
	return nil
}
func (f *offFakes) Publish(_ context.Context, ev livebus.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live = append(f.live, ev)
	return nil
}
func (f *offFakes) CloseBilling(_ context.Context, org uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.billed = append(f.billed, org)
	return nil
}
func (f *offFakes) ExpireAudit(_ context.Context, org uuid.UUID, before time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expired[org] = before
	return nil
}
func (f *offFakes) Person(_ context.Context, user uuid.UUID) (server.Person, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return server.Person{Email: f.emails[user], Memberships: []orgdata.Membership{{OrgID: uuid.New(), MembershipID: uuid.New()}}}, nil
}
func (f *offFakes) Export(_ context.Context, s dataowner.Owner, org uuid.UUID) (orgdata.Part, error) {
	if err := f.call(s); err != nil {
		return orgdata.Part{}, err
	}
	files := []orgdata.File{}
	if s.Name == "documents" {
		files = append(files, orgdata.File{Key: "orgs/" + org.String() + "/document-file/" + uuid.NewString(), Name: "attachments/a.txt"})
		f.mu.Lock()
		f.objects[files[0].Key] = []byte("hello")
		f.mu.Unlock()
	}
	return orgdata.Marshal(s.Name, map[string]any{"org": org, "rows": 1}, files)
}

// call counts an export call to s, and fails it if s is failing.
func (f *offFakes) call(s dataowner.Owner) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.Name == f.failing {
		return errors.New("unreachable")
	}
	f.exported[s.Name]++
	return nil
}

func (f *offFakes) Purge(_ context.Context, s dataowner.Owner, org uuid.UUID) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.Name == f.failing {
		return 0, errors.New("unreachable")
	}
	f.purged[s.Name]++
	f.purgeLog = append(f.purgeLog, s.Name)
	if s.Name == f.holdOut {
		return 3, nil
	}
	return 0, nil
}
func (f *offFakes) ExportUser(_ context.Context, s dataowner.Owner, user uuid.UUID, ms []orgdata.Membership) (orgdata.Part, error) {
	if err := f.call(s); err != nil {
		return orgdata.Part{}, err
	}
	return orgdata.Marshal(s.Name, map[string]any{"user": user, "memberships": len(ms)}, nil)
}
func (f *offFakes) Put(_ context.Context, _ string, key storage.Key, _ string, _ int64, body io.Reader) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key.String()] = raw
	return nil
}
func (f *offFakes) Get(_ context.Context, _ string, key storage.Key) (io.ReadCloser, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, ok := f.objects[key.String()]
	if !ok {
		return nil, "", errors.New("no such object")
	}
	return io.NopCloser(bytes.NewReader(raw)), "application/octet-stream", nil
}
func (f *offFakes) Delete(_ context.Context, _ string, key storage.Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key.String())
	return nil
}
func (f *offFakes) DeleteAll(_ context.Context, org, _ string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedAt = append(f.deletedAt, org)
	return 0, nil
}
func (f *offFakes) ReadURL(_ context.Context, _ string, key storage.Key, _ time.Duration) (*url.URL, error) {
	return url.Parse("https://files.test/" + key.String())
}

type clockT struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clockT) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clockT) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// offOwners is the template's data owners and two of a product's,
// registered: nothing in the organization service names them.
func offOwners() *dataowner.Registry {
	r := dataowner.New()
	r.Register(dataowner.Owner{Name: "projects", Export: true, Purge: true, Erase: true})
	r.Register(dataowner.Owner{Name: "documents", Export: true, Purge: true})
	return r
}

// Closing an org (UO-183): the Owner types its name; sessions end and the
// subscription is cancelled at once; the Owner is emailed a link that
// reopens it within 30 days; after 30 days the purge empties every service,
// checked, and keeps only the fact that the org existed.
func TestCloseReopenAndPurge(t *testing.T) {
	h, _, issuer, srv, recorder := newAPIAudited(t)
	fakes := newOffFakes()
	clock := &clockT{t: time.Now()}
	srv.WithOffboarding(server.Offboarding{Platform: fakes, Data: fakes, Files: fakes, Owners: offOwners(), Live: fakes, Now: clock.now})
	public := srv.Handler(httpx.NewMux())

	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Acme", "time_zone": "UTC"})["org_id"].(string)
	owner, admin := uuid.NewString(), uuid.NewString()
	grants[orgID+"/"+owner] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	grants[orgID+"/"+admin] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	ownerUser := uuid.New()
	fakes.emails[ownerUser] = "owner@acme.test"
	ownerToken, err := issuer.Issue(auth.Caller{UserID: ownerUser.String(), OrgID: orgID, MembershipID: owner}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/organizations/" + orgID + "/close"

	if status, _ := do(t, h, http.MethodPost, path, tokenForMember(t, issuer, orgID, admin), map[string]any{"confirm_name": "Acme"}, ""); status != http.StatusForbidden {
		t.Errorf("an Admin closing: %d", status)
	}
	if status, out := do(t, h, http.MethodPost, path, ownerToken, map[string]any{"confirm_name": "acme"}, ""); status != http.StatusBadRequest {
		t.Errorf("the wrong name: %d %v", status, out)
	}
	if status, _ := do(t, h, http.MethodPost, path, operator, map[string]any{"confirm_name": "Acme"}, ""); status != http.StatusBadRequest {
		t.Errorf("an operator without a reason: %d", status)
	}
	deps.mu.Lock()
	deps.sent = nil
	deps.mu.Unlock()
	status, out := do(t, h, http.MethodPost, path, ownerToken, map[string]any{"confirm_name": "Acme"}, "")
	if status != http.StatusOK || out["status"] != "closing" || out["purge_after"] == nil {
		t.Fatalf("close: %d %v", status, out)
	}
	if len(fakes.revoked) != 1 || len(fakes.billed) != 1 {
		t.Errorf("sessions %v, billing %v", fakes.revoked, fakes.billed)
	}
	// Everyone with it open is told on the live-session bus.
	if len(fakes.live) != 1 || fakes.live[0].Type != livebus.OrgSuspended || fakes.live[0].OrgID != orgID || fakes.live[0].Code != "organization_closing" {
		t.Errorf("pushed live: %+v", fakes.live)
	}
	if !recorder.has("organization.closing") {
		t.Error("the close is not audited")
	}
	if status, _ := do(t, h, http.MethodPost, path, ownerToken, map[string]any{"confirm_name": "Acme"}, ""); status != http.StatusConflict {
		t.Errorf("closing twice: %d", status)
	}
	deps.mu.Lock()
	var link string
	for _, m := range deps.sent {
		if m.Template == "organization_closing" && m.To == "owner@acme.test" {
			link, _ = m.Data["link"].(string)
		}
	}
	deps.mu.Unlock()
	if !strings.HasPrefix(link, "http://admin.test/reopen?org="+orgID+"&token=") {
		t.Fatalf("reopen link %q", link)
	}
	u, _ := url.Parse(link)
	token := u.Query().Get("token")

	reopen := func(tok string) (int, map[string]any) {
		raw, _ := json.Marshal(map[string]any{"token": tok})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/organizations/"+orgID+"/reopen", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		public.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	if status, _ := reopen("not-the-token"); status != http.StatusNotFound {
		t.Errorf("a wrong token: %d", status)
	}
	// Day 10: the link reopens it, and everything is as it was.
	clock.add(10 * 24 * time.Hour)
	if status, out := reopen(token); status != http.StatusOK || out["status"] != "active" {
		t.Fatalf("reopen: %d %v", status, out)
	}
	if status, _ := reopen(token); status != http.StatusNotFound {
		t.Errorf("a used link: %d", status)
	}
	_, org := get(t, h, "/v1/organizations/"+orgID, ownerToken)
	if org["status"] != "active" || org["purge_after"] != nil {
		t.Errorf("reopened org: %v", org)
	}

	// Closed again, by an operator with a reason; a new link is asked for.
	if status, _ := do(t, h, http.MethodPost, path, operator, map[string]any{"confirm_name": "Acme", "reason": "Customer request by email"}, ""); status != http.StatusOK {
		t.Fatalf("operator close: %d", status)
	}
	rec := httptest.NewRecorder()
	public.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/organizations/"+orgID+"/reopen-link", nil))
	if rec.Code != http.StatusAccepted {
		t.Errorf("reopen link: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	public.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/organizations/"+uuid.NewString()+"/reopen-link", nil))
	if rec.Code != http.StatusAccepted {
		t.Errorf("a reopen link for no org answers differently: %d", rec.Code)
	}

	// Before 30 days nothing is purged; after, one service holding rows
	// stops it, and the next day it completes.
	if err := srv.RunPurges(t.Context()); err != nil || len(fakes.purged) != 0 {
		t.Fatalf("purged early: %v %v", err, fakes.purged)
	}
	clock.add(31 * 24 * time.Hour)
	fakes.holdOut = "user"
	if err := srv.RunPurges(t.Context()); err == nil {
		t.Error("a service still holding rows did not stop the purge")
	}
	if status, _ := get(t, h, "/v1/organizations/"+orgID, operator); status != http.StatusOK {
		t.Errorf("the org went although a service still held it: %d", status)
	}
	fakes.holdOut = ""
	if err := srv.RunPurges(t.Context()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if fakes.purged["user"] != 2 || fakes.purged["projects"] != 1 || fakes.purged["audit"] != 1 || len(fakes.deletedAt) != 1 || fakes.deletedAt[0] != orgID {
		t.Errorf("purged %v, files %v", fakes.purged, fakes.deletedAt)
	}
	if status, _ := get(t, h, "/v1/organizations/"+orgID, operator); status != http.StatusNotFound {
		t.Errorf("a purged org is still there: %d", status)
	}
	if status, _ := reopen(token); status != http.StatusNotFound {
		t.Errorf("reopening a purged org: %d", status)
	}
}

// The schedule (UO-183): shown to the org's admins; the audit retention is
// lengthened by an operator on enterprise only; the daily pass applies it.
func TestRetention(t *testing.T) {
	h, _, issuer, srv, _ := newAPIAudited(t)
	fakes := newOffFakes()
	srv.WithOffboarding(server.Offboarding{Platform: fakes, Data: fakes, Files: fakes, Owners: offOwners()})
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Globex", "time_zone": "UTC"})["org_id"].(string)
	admin := uuid.NewString()
	grants[orgID+"/"+admin] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	path := "/v1/organizations/" + orgID + "/retention"

	status, out := get(t, h, path, tokenForMember(t, issuer, orgID, admin))
	if status != http.StatusOK || out["audit_months"] != float64(13) || out["audit_configurable"] != false || len(out["classes"].([]any)) != 4 {
		t.Fatalf("schedule: %d %v", status, out)
	}
	if status, _ := get(t, h, path, tokenFor(t, issuer, orgID)); status != http.StatusForbidden {
		t.Errorf("a User reading the schedule: %d", status)
	}
	if status, _ := do(t, h, http.MethodPut, path, tokenForMember(t, issuer, orgID, admin), map[string]any{"audit_months": 84}, ""); status != http.StatusForbidden {
		t.Errorf("an Admin changing retention: %d", status)
	}
	if status, _ := do(t, h, http.MethodPut, path, operator, map[string]any{"audit_months": 84}, ""); status != http.StatusBadRequest {
		t.Errorf("seven years off enterprise: %d", status)
	}
	if status, _ := do(t, h, http.MethodPut, "/v1/organizations/"+orgID+"/plan", operator, map[string]any{"plan": "enterprise"}, ""); status != http.StatusOK {
		t.Fatalf("to enterprise: %d", status)
	}
	if status, out := do(t, h, http.MethodPut, path, operator, map[string]any{"audit_months": 84}, ""); status != http.StatusOK || out["audit_months"] != float64(84) {
		t.Errorf("seven years on enterprise: %d %v", status, out)
	}
	if err := srv.RunRetention(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, ok := fakes.expired[uuid.MustParse(orgID)]
	if !ok || time.Since(before) < 83*30*24*time.Hour {
		t.Errorf("retention applied from %v", before)
	}
}

// Exports (UO-184): the Owner asks, once per key and a few a day; the pass
// gathers every service's part and files into a zip, stores it and emails
// a link; a person's own export covers their memberships.
func TestExports(t *testing.T) {
	h, _, issuer, srv, _ := newAPIAudited(t)
	fakes := newOffFakes()
	clock := &clockT{t: time.Now()}
	srv.WithOffboarding(server.Offboarding{Platform: fakes, Data: fakes, Files: fakes, Owners: offOwners(), Now: clock.now})
	operator := platformToken(t, issuer)
	orgID := create(t, h, operator, map[string]any{"name": "Initech", "time_zone": "UTC"})["org_id"].(string)
	owner, admin := uuid.NewString(), uuid.NewString()
	grants[orgID+"/"+owner] = authz.Grant{Role: authz.Owner, Permissions: authz.Effective(authz.Owner, authz.Defaults())}
	grants[orgID+"/"+admin] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	ownerUser := uuid.New()
	fakes.emails[ownerUser] = "owner@initech.test"
	ownerToken, _ := issuer.Issue(auth.Caller{UserID: ownerUser.String(), OrgID: orgID, MembershipID: owner}, time.Hour)
	path := "/v1/organizations/" + orgID + "/exports"

	if status, _ := do(t, h, http.MethodPost, path, tokenForMember(t, issuer, orgID, admin), nil, "k1"); status != http.StatusForbidden {
		t.Errorf("an Admin exporting: %d", status)
	}
	status, first := do(t, h, http.MethodPost, path, ownerToken, nil, "k1")
	if status != http.StatusAccepted || first["status"] != "pending" {
		t.Fatalf("export: %d %v", status, first)
	}
	if _, again := do(t, h, http.MethodPost, path, ownerToken, nil, "k1"); again["id"] != first["id"] {
		t.Errorf("a retried request made a second export: %v", again)
	}
	do(t, h, http.MethodPost, path, ownerToken, nil, "k2")
	do(t, h, http.MethodPost, path, ownerToken, nil, "k3")
	if status, _ := do(t, h, http.MethodPost, path, ownerToken, nil, "k4"); status != http.StatusTooManyRequests {
		t.Errorf("a fourth export in a day: %d", status)
	}

	deps.mu.Lock()
	deps.sent = nil
	deps.mu.Unlock()
	if err := srv.RunExports(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, list := get(t, h, path, ownerToken)
	exports := list["exports"].([]any)
	var ready map[string]any
	for _, x := range exports {
		if e := x.(map[string]any); e["id"] == first["id"] {
			ready = e
		}
	}
	if ready == nil || ready["status"] != "ready" || ready["download_url"] == nil || ready["expires_at"] == nil {
		t.Fatalf("export after the pass: %v", exports)
	}
	// The archive: a README, every service's data, and the files.
	var archive []byte
	fakes.mu.Lock()
	for k, v := range fakes.objects {
		if strings.Contains(k, "/data-export/") {
			archive = v
		}
	}
	fakes.mu.Unlock()
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	names := map[string]bool{}
	for _, f := range z.File {
		names[f.Name] = true
	}
	for _, want := range []string{"README.md", "organization/data.json", "projects/data.json", "documents/data.json", "documents/files/attachments/a.txt", "audit/data.json"} {
		if !names[want] {
			t.Errorf("archive without %s: %v", want, names)
		}
	}
	deps.mu.Lock()
	emailed := false
	for _, m := range deps.sent {
		if m.Template == "export_ready" && m.To == "owner@initech.test" && strings.HasPrefix(m.Data["link"].(string), "https://files.test/") {
			emailed = true
		}
	}
	deps.mu.Unlock()
	if !emailed {
		t.Error("the link is not emailed")
	}

	// A week on, the link and the file are gone.
	clock.add(8 * 24 * time.Hour)
	if err := srv.RunExports(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, list = get(t, h, path, ownerToken)
	for _, x := range list["exports"].([]any) {
		if e := x.(map[string]any); e["id"] == first["id"] && (e["status"] != "expired" || e["download_url"] != nil) {
			t.Errorf("an old export: %v", e)
		}
	}

	// A person's own export, across their memberships.
	adminToken := tokenForMember(t, issuer, orgID, admin)
	status, mine := do(t, h, http.MethodPost, "/v1/me/exports", adminToken, nil, "p1")
	if status != http.StatusAccepted || mine["kind"] != "personal" {
		t.Fatalf("personal export: %d %v", status, mine)
	}
	if err := srv.RunExports(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, own := get(t, h, "/v1/me/exports", adminToken)
	if e := own["exports"].([]any); len(e) != 1 || e[0].(map[string]any)["status"] != "ready" {
		t.Errorf("my exports: %v", own)
	}
	_, others := get(t, h, "/v1/me/exports", ownerToken)
	if e := others["exports"].([]any); len(e) != 0 {
		t.Errorf("someone else's exports: %v", e)
	}
}

func (m *memoryRecorder) has(action string) bool {
	for _, a := range m.actions() {
		if a == action {
			return true
		}
	}
	return false
}
