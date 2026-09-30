package server_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/server"
)

// testDeps are the other services in memory. deps is the set the last
// fixture was built with.
type testDeps struct {
	mu       sync.Mutex
	sent     []email.Message
	members  []server.NewMembership
	accounts []server.NewLocalAccount
	records  map[string]string // TXT name => value
	refuse   string            // a code the user service answers with
	// active is each org's active members, as the user service counts
	// them; countDown makes the count fail.
	active    map[uuid.UUID]int
	countDown bool
	// duringLookup runs while a TXT lookup is in flight, to race it.
	duringLookup func()
}

var deps *testDeps

func newTestDeps() *testDeps {
	return &testDeps{records: map[string]string{}, active: map[uuid.UUID]int{}}
}

func (d *testDeps) deps() server.Deps {
	return server.Deps{Email: d, Users: d, Accounts: d, DNS: d}
}

func (d *testDeps) Send(_ context.Context, m email.Message) (email.Queued, error) {
	if err := m.Validate(); err != nil {
		return email.Queued{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sent = append(d.sent, m)
	return email.Queued{ID: uuid.NewString(), State: "queued"}, nil
}

func (d *testDeps) CreateMembership(_ context.Context, in server.NewMembership) (server.Membership, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.refuse != "" {
		return server.Membership{}, &server.Refusal{Status: 422, Code: d.refuse}
	}
	d.members = append(d.members, in)
	m := server.Membership{ID: uuid.New()}
	m.User.ID = uuid.New()
	return m, nil
}

func (d *testDeps) CountMembers(_ context.Context, orgID uuid.UUID) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.countDown {
		return 0, &server.Refusal{Status: 503, Code: "unavailable"}
	}
	return d.active[orgID], nil
}

func (d *testDeps) CreateLocalAccount(_ context.Context, in server.NewLocalAccount) (server.LocalAccount, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.accounts = append(d.accounts, in)
	setup := "setup-" + uuid.NewString()
	return server.LocalAccount{UserID: in.UserID, SetupToken: &setup}, nil
}

func (d *testDeps) HasTXT(_ context.Context, name, value string) (bool, error) {
	d.mu.Lock()
	found, race := d.records[name] == value, d.duringLookup
	d.mu.Unlock()
	if race != nil {
		race()
	}
	return found, nil
}

func (d *testDeps) lastLink(t *testing.T) (email.Message, string) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.sent) == 0 {
		t.Fatal("no email was sent")
	}
	m := d.sent[len(d.sent)-1]
	u, err := url.Parse(m.Data["link"].(string))
	if err != nil || u.Query().Get("token") == "" {
		t.Fatalf("no token in %v", m.Data["link"])
	}
	return m, u.Query().Get("token")
}

// A new org from a cold start, and a second
// signup on the same domain blocked.
func TestSelfServeSignupFromAColdStart(t *testing.T) {
	h, _, issuer, _, recorder := newAPIAudited(t)
	d := deps
	signup := map[string]any{"email": "Ada@Acme.com", "name": "Ada", "org_name": "Acme", "time_zone": "Europe/London"}

	for _, bad := range []map[string]any{
		{"email": "nope", "name": "Ada", "org_name": "Acme", "time_zone": "Europe/London"},
		{"email": "ada@acme.com", "name": "", "org_name": "Acme", "time_zone": "Europe/London"},
		{"email": "ada@acme.com", "name": "Ada", "org_name": "Acme", "time_zone": "+01:00"},
	} {
		if status, out := call(t, h, http.MethodPost, "/v1/signups", "", bad); status != http.StatusBadRequest {
			t.Errorf("%v: %d %v", bad, status, out)
		}
	}
	if status, _ := call(t, h, http.MethodPost, "/v1/signups", "", signup); status != http.StatusAccepted {
		t.Fatalf("signup: %d", status)
	}
	msg, token := d.lastLink(t)
	if msg.Template != "signup_verify" || msg.OrgName != "Acme" || msg.To != "ada@acme.com" || !strings.HasPrefix(msg.Data["link"].(string), "http://admin.test/signup/verify?token=") {
		t.Errorf("email: %+v", msg)
	}
	// Nothing exists yet: no org, no member.
	if len(d.members) != 0 {
		t.Error("a member before the link was used")
	}
	// The link: the org, its Owner, the verified account, the domain claimed.
	if status, out := call(t, h, http.MethodPost, "/v1/signups/complete", "", map[string]any{"token": "wrong"}); status != http.StatusNotFound || out["code"] != "signup.not_found" {
		t.Errorf("wrong token: %d %v", status, out)
	}
	status, out := call(t, h, http.MethodPost, "/v1/signups/complete", "", map[string]any{"token": token})
	if status != http.StatusCreated || out["domain_claimed"] != true || out["setup_token"] == nil {
		t.Fatalf("complete: %d %v", status, out)
	}
	orgID := out["org_id"].(string)
	if len(d.members) != 1 || d.members[0].Role != "owner" || d.members[0].Source != "owner" || d.members[0].Name != "Ada" || d.members[0].OrgID.String() != orgID {
		t.Errorf("owner membership: %+v", d.members)
	}
	if len(d.accounts) != 1 || !d.accounts[0].Verified || d.accounts[0].OrgName != "Acme" || d.accounts[0].App != "admin" {
		t.Errorf("owner account: %+v", d.accounts)
	}
	operator := tokenFor(t, issuer, auth.PlatformOrg)
	_, org := call(t, h, http.MethodGet, "/v1/organizations/"+orgID, operator, nil)
	if org["domain"] != "acme.com" || org["owner_user_id"] != out["user_id"] || org["plan"] != "free" || org["time_zone"] != "Europe/London" {
		t.Errorf("the org: %v", org)
	}
	if !contains(recorder.actions(), "organization.created") {
		t.Errorf("not audited: %v", recorder.actions())
	}
	// The link works once.
	if status, out := call(t, h, http.MethodPost, "/v1/signups/complete", "", map[string]any{"token": token}); status != http.StatusNotFound || out["code"] != "signup.used" {
		t.Errorf("link reused: %d %v", status, out)
	}
	// A second signup on the same domain is blocked and pointed at access.
	if status, out := call(t, h, http.MethodPost, "/v1/signups", "", map[string]any{"email": "bob@acme.com", "name": "Bob", "org_name": "Acme Two", "time_zone": "Europe/London"}); status != http.StatusConflict || out["code"] != "signup.domain_claimed" {
		t.Errorf("second signup: %d %v", status, out)
	}
	// A public mailbox claims nothing: a gmail org has no domain, and a
	// second gmail signup is fine.
	for _, who := range []string{"one@gmail.com", "two@gmail.com"} {
		if status, _ := call(t, h, http.MethodPost, "/v1/signups", "", map[string]any{"email": who, "name": "G", "org_name": "G " + who, "time_zone": "UTC"}); status != http.StatusAccepted {
			t.Fatalf("%s: %d", who, status)
		}
		_, tok := d.lastLink(t)
		if status, out := call(t, h, http.MethodPost, "/v1/signups/complete", "", map[string]any{"token": tok}); status != http.StatusCreated || out["domain_claimed"] != false {
			t.Errorf("%s complete: %d %v", who, status, out)
		}
	}
	// A race: the domain claimed between the link being sent and used.
	if status, _ := call(t, h, http.MethodPost, "/v1/signups", "", map[string]any{"email": "carol@globex.com", "name": "Carol", "org_name": "Globex", "time_zone": "UTC"}); status != http.StatusAccepted {
		t.Fatal("globex signup")
	}
	_, carol := d.lastLink(t)
	if status, _ := call(t, h, http.MethodPost, "/v1/organizations", operator, map[string]any{"name": "Globex Inc", "domain": "globex.com", "time_zone": "UTC"}); status != http.StatusCreated {
		t.Fatalf("operator claiming globex: %d", status)
	}
	if status, out := call(t, h, http.MethodPost, "/v1/signups/complete", "", map[string]any{"token": carol}); status != http.StatusConflict || out["code"] != "signup.domain_claimed" {
		t.Errorf("claimed meanwhile: %d %v", status, out)
	}
	// Three links an hour, then quiet.
	before := len(d.sent)
	for i := 0; i < 5; i++ {
		call(t, h, http.MethodPost, "/v1/signups", "", map[string]any{"email": "dave@initech.com", "name": "Dave", "org_name": "Initech", "time_zone": "UTC"})
	}
	if len(d.sent)-before != 3 {
		t.Errorf("links sent: %d, want 3", len(d.sent)-before)
	}
}

// A domain claimed later, by a TXT record; the settings cannot set it
// directly except for an operator.
func TestDomainClaimByTXTRecord(t *testing.T) {
	h, _, issuer, _, recorder := newAPIAudited(t)
	d := deps
	operator := tokenFor(t, issuer, auth.PlatformOrg)
	_, org := call(t, h, http.MethodPost, "/v1/organizations", operator, map[string]any{"name": "Initech", "time_zone": "UTC"})
	orgID := org["org_id"].(string)
	adminID := uuid.NewString()
	grants[orgID+"/"+adminID] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	admin, _ := issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: orgID, MembershipID: adminID}, 3600e9)
	member := tokenFor(t, issuer, orgID)
	path := "/v1/organizations/" + orgID + "/domain"

	// Not directly through the settings.
	if status, out := call(t, h, http.MethodPatch, "/v1/organizations/"+orgID, admin, map[string]any{"domain": "initech.com"}); status != http.StatusForbidden || out["code"] != "domain.verify_first" {
		t.Errorf("admin setting the domain directly: %d %v", status, out)
	}
	if status, _ := call(t, h, http.MethodPut, path, member, map[string]any{"domain": "initech.com"}); status != http.StatusForbidden {
		t.Errorf("a member claiming: %d", status)
	}
	for _, bad := range []string{"gmail.com", "not a domain"} {
		if status, _ := call(t, h, http.MethodPut, path, admin, map[string]any{"domain": bad}); status != http.StatusBadRequest {
			t.Errorf("%q: %d", bad, status)
		}
	}
	status, claim := call(t, h, http.MethodPut, path, admin, map[string]any{"domain": "Initech.com"})
	if status != http.StatusOK || claim["verified"] != false || claim["pending_domain"] != "initech.com" || claim["txt_name"] != "_b2bapp-verify.initech.com" || !strings.HasPrefix(claim["txt_value"].(string), "b2bapp-verify=") {
		t.Fatalf("pending claim: %d %v", status, claim)
	}
	// Not yet published: refused; published: claimed; sign-in by domain finds it.
	if status, out := call(t, h, http.MethodPost, path+"/verify", admin, nil); status != http.StatusConflict || out["code"] != "domain.not_verified" {
		t.Errorf("before the record: %d %v", status, out)
	}
	d.records["_b2bapp-verify.initech.com"] = claim["txt_value"].(string)
	status, claimed := call(t, h, http.MethodPost, path+"/verify", admin, nil)
	if status != http.StatusOK || claimed["verified"] != true || claimed["domain"] != "initech.com" || claimed["pending_domain"] != nil {
		t.Fatalf("verify: %d %v", status, claimed)
	}
	if !contains(recorder.actions(), "organization.domain_claimed") {
		t.Errorf("not audited: %v", recorder.actions())
	}
	if status, out := call(t, h, http.MethodGet, "/v1/internal/domains/initech.com/organization", tokenForService(t, issuer, "identity"), nil); status != http.StatusOK || out["org_id"] != orgID {
		t.Errorf("sign-in by domain after the claim: %d %v", status, out)
	}
	// Another org cannot claim it now, and verifying with nothing pending is not found.
	_, other := call(t, h, http.MethodPost, "/v1/organizations", operator, map[string]any{"name": "Other", "time_zone": "UTC"})
	otherAdmin := uuid.NewString()
	grants[other["org_id"].(string)+"/"+otherAdmin] = authz.Grant{Role: authz.Admin, Permissions: authz.Effective(authz.Admin, authz.Defaults())}
	otherToken, _ := issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: other["org_id"].(string), MembershipID: otherAdmin}, 3600e9)
	if status, _ := call(t, h, http.MethodPut, "/v1/organizations/"+other["org_id"].(string)+"/domain", otherToken, map[string]any{"domain": "initech.com"}); status != http.StatusConflict {
		t.Errorf("claiming a held domain: %d", status)
	}
	if status, _ := call(t, h, http.MethodPost, path+"/verify", admin, nil); status != http.StatusNotFound {
		t.Errorf("verify with nothing pending: %d", status)
	}

	// A claim for another domain started while a proven one is being looked
	// up is not claimed on the strength of the first one's record.
	otherPath := "/v1/organizations/" + other["org_id"].(string) + "/domain"
	_, proven := call(t, h, http.MethodPut, otherPath, otherToken, map[string]any{"domain": "proven.com"})
	d.records["_b2bapp-verify.proven.com"] = proven["txt_value"].(string)
	d.duringLookup = func() {
		call(t, h, http.MethodPut, otherPath, otherToken, map[string]any{"domain": "unproven.com"})
	}
	status, raced := call(t, h, http.MethodPost, otherPath+"/verify", otherToken, nil)
	d.duringLookup = nil
	if status == http.StatusOK || raced["domain"] == "unproven.com" {
		t.Errorf("an unproven domain was claimed: %d %v", status, raced)
	}
	if status, _ := call(t, h, http.MethodGet, "/v1/internal/domains/unproven.com/organization", tokenForService(t, issuer, "identity"), nil); status != http.StatusNotFound {
		t.Errorf("the unproven domain resolves: %d", status)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// call is do with a fresh idempotency key.
func call(t *testing.T, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, h, method, path, token, body, uuid.NewString())
}
