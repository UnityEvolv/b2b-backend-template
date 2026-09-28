package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/UnityEvolv/b2b-backend-template/migrations"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth/stubissuer"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email"
	"github.com/UnityEvolv/b2b-backend-template/pkg/email/transport"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/sender"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/server"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/webhook"
)

const org = "01922b5e-0000-7000-8000-0000000000a1"

// A transport that fails as many times as told, then delivers.
type flaky struct {
	mu        sync.Mutex
	failFirst int
	permanent bool
	sent      []transport.Outgoing
	calls     int
}

func (f *flaky) Send(_ context.Context, m transport.Outgoing) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.permanent {
		return "", transport.Permanent{Err: errors.New("mailbox does not exist")}
	}
	if f.calls <= f.failFirst {
		return "", errors.New("connection reset (transient)")
	}
	f.sent = append(f.sent, m)
	return "provider-" + strconv.Itoa(len(f.sent)), nil
}

type fixture struct {
	cluster *db.Cluster
	issuer  *stubissuer.Issuer
	api     *httptest.Server
	sender  *email.Client
	secret  string
	hook    *webhook.Resend
}

// A test signing secret in Svix's shape, built here so no scanner mistakes
// it for a real one.
var webhookSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("this-is-a-test-secret-key"))

func newFixture(t *testing.T) *fixture {
	t.Helper()
	url := dbtest.New(t)
	ctx := context.Background()
	service, _ := db.ServiceByName("notification")
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = service.Role()
	config.ConnConfig.Password, _ = dbtest.Password(service)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrator, err := db.Migrator(stdlib.OpenDBFromPool(pool), service, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Up(ctx); err != nil {
		t.Fatal(err)
	}

	issuer, _ := stubissuer.New("test", "unityofis")
	verifier := auth.NewStaticVerifier("test", "unityofis", issuer.PublicKeys())
	cluster := db.SingleShard(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hook, err := webhook.New(cluster, webhookSecret, logger)
	if err != nil {
		t.Fatal(err)
	}
	root := http.NewServeMux()
	root.Handle("POST /v1/webhooks/resend", hook)
	root.Handle("/", auth.Require(verifier, server.New(cluster, logger).Handler(httpx.NewMux())))
	api := httptest.NewServer(httpx.Logged(logger, root))
	t.Cleanup(api.Close)

	token, _ := issuer.Issue(auth.Caller{Service: "organization"}, time.Hour)
	return &fixture{
		cluster: cluster, issuer: issuer, api: api, hook: hook, secret: webhookSecret,
		sender: email.NewClient(api.URL, auth.StaticToken(token), api.Client()),
	}
}

func (f *fixture) state(t *testing.T, id string) map[string]any {
	t.Helper()
	token, _ := f.issuer.Issue(auth.Caller{Service: "organization"}, time.Hour)
	req, _ := http.NewRequest(http.MethodGet, f.api.URL+"/v1/internal/organizations/"+org+"/emails/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state: %d %v", resp.StatusCode, body)
	}
	return body
}

func (f *fixture) queue(t *testing.T, to string) string {
	t.Helper()
	q, err := f.sender.Send(context.Background(), email.Message{
		OrgID: org, OrgName: "Acme", To: to, Template: "notice",
		Data: map[string]any{"heading": "Hello", "lines": []string{"one", "two"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return q.ID
}

func newSender(f *fixture, tr transport.Transport) *sender.Sender {
	return sender.New(f.cluster, tr, "unityofis <no-reply@test.invalid>", slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithBackoff([]time.Duration{10 * time.Millisecond, 10 * time.Millisecond})
}

// Done criterion: a send that fails once is retried and delivered without any
// external scheduler.
func TestAFailedSendIsRetriedAndDelivered(t *testing.T) {
	f := newFixture(t)
	tr := &flaky{failFirst: 1}
	s := newSender(f, tr)
	id := f.queue(t, "ada@example.com")

	if n, _ := s.Deliver(context.Background()); n != 1 {
		t.Fatalf("first pass claimed %d", n)
	}
	st := f.state(t, id)
	if st["state"] != "queued" || st["attempts"].(float64) != 1 || st["last_error"] == nil {
		t.Fatalf("after a failure: %v", st)
	}

	time.Sleep(20 * time.Millisecond) // past the (test) backoff
	if n, _ := s.Deliver(context.Background()); n != 1 {
		t.Fatalf("second pass claimed %d", n)
	}
	st = f.state(t, id)
	if st["state"] != "sent" || st["attempts"].(float64) != 2 || st["sent_at"] == nil {
		t.Fatalf("after the retry: %v", st)
	}
	if len(tr.sent) != 1 || tr.sent[0].To != "ada@example.com" || !strings.Contains(tr.sent[0].Subject, "Acme") || tr.sent[0].Text == "" || tr.sent[0].HTML == "" {
		t.Fatalf("delivered: %+v", tr.sent)
	}
	if n, _ := s.Deliver(context.Background()); n != 0 {
		t.Fatalf("a sent email was claimed again")
	}
}

func TestPermanentFailureAndExhaustedRetriesEndAsFailed(t *testing.T) {
	f := newFixture(t)
	id := f.queue(t, "gone@example.com")
	s := newSender(f, &flaky{permanent: true})
	_, _ = s.Deliver(context.Background())
	if st := f.state(t, id); st["state"] != "failed" {
		t.Fatalf("permanent: %v", st)
	}

	id = f.queue(t, "flaky@example.com")
	s = newSender(f, &flaky{failFirst: 100})
	for range 3 {
		_, _ = s.Deliver(context.Background())
		time.Sleep(20 * time.Millisecond)
	}
	if st := f.state(t, id); st["state"] != "failed" || st["attempts"].(float64) != 3 {
		t.Fatalf("exhausted: %v", st)
	}
}

// Done criterion: a bounce marks the address.
func TestABounceMarksTheAddressAndStopsFutureMail(t *testing.T) {
	f := newFixture(t)
	tr := &flaky{}
	s := newSender(f, tr)
	id := f.queue(t, "Dead@Example.com")
	_, _ = s.Deliver(context.Background())
	if st := f.state(t, id); st["state"] != "sent" {
		t.Fatalf("not sent: %v", st)
	}

	code := f.postEvent(t, map[string]any{
		"type": "email.bounced", "created_at": time.Now().UTC().Format(time.RFC3339),
		"data": map[string]any{"email_id": "provider-1", "to": []string{"dead@example.com"}, "bounce": map[string]any{"type": "Permanent"}},
	}, true)
	if code != http.StatusNoContent {
		t.Fatalf("webhook: %d", code)
	}
	if st := f.state(t, id); st["state"] != "bounced" {
		t.Fatalf("after bounce: %v", st)
	}

	// Sent again, in any case: suppressed, never delivered.
	again := f.queue(t, "DEAD@example.com")
	_, _ = s.Deliver(context.Background())
	if st := f.state(t, again); st["state"] != "suppressed" {
		t.Fatalf("mail to a bounced address: %v", st)
	}
	if len(tr.sent) != 1 {
		t.Fatalf("delivered to a bounced address: %d sends", len(tr.sent))
	}
	// The same event again changes nothing and is still accepted.
	if code := f.postEvent(t, map[string]any{"type": "email.bounced", "data": map[string]any{"email_id": "provider-1", "to": []string{"dead@example.com"}}}, true); code != http.StatusNoContent {
		t.Fatalf("replayed event: %d", code)
	}
}

func TestWebhookRefusesBadSignatures(t *testing.T) {
	f := newFixture(t)
	ev := map[string]any{"type": "email.bounced", "data": map[string]any{"to": []string{"x@example.com"}}}
	if code := f.postEvent(t, ev, false); code != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", code)
	}
	// A soft bounce does not kill an address.
	_ = f.postEvent(t, map[string]any{"type": "email.bounced", "data": map[string]any{"to": []string{"full@example.com"}, "bounce": map[string]any{"type": "Transient"}}}, true)
	id := f.queue(t, "full@example.com")
	if st := f.state(t, id); st["state"] != "queued" {
		t.Fatalf("soft bounce suppressed the address: %v", st)
	}
}

func (f *fixture) postEvent(t *testing.T, ev map[string]any, sign bool) int {
	t.Helper()
	body, _ := json.Marshal(ev)
	req, _ := http.NewRequest(http.MethodPost, f.api.URL+"/v1/webhooks/resend", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if sign {
		id := "msg_" + uuid.NewString()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(f.secret, "whsec_"))
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id + "." + ts + "."))
		mac.Write(body)
		req.Header.Set("svix-id", id)
		req.Header.Set("svix-timestamp", ts)
		req.Header.Set("svix-signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	resp, err := f.api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestOnlyServicesQueueAndBadMessagesAreNamed(t *testing.T) {
	f := newFixture(t)
	person, _ := f.issuer.Issue(auth.Caller{UserID: uuid.NewString(), OrgID: org, MembershipID: uuid.NewString()}, time.Hour)
	body := `{"org_id":"` + org + `","org_name":"Acme","to":"a@example.com","template":"notice"}`
	post := func(token, body string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, f.api.URL+"/v1/internal/emails", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := f.api.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, _ := post(person, body); code != http.StatusForbidden {
		t.Errorf("a person queued mail: %d", code)
	}
	svc, _ := f.issuer.Issue(auth.Caller{Service: "organization"}, time.Hour)
	code, out := post(svc, `{"org_id":"`+org+`","org_name":"","to":"nope","template":"nope"}`)
	fields, _ := out["fields"].(map[string]any)
	if code != http.StatusBadRequest || fields["to"] == nil || fields["org_name"] == nil || fields["template"] == nil {
		t.Errorf("bad message: %d %v", code, out)
	}
}

// Against the local mail catcher: the real SMTP transport, a two-part message,
// read back through Mailpit's API. Needs TEST_SMTP_ADDR and TEST_MAILPIT_URL.
func TestSMTPDeliversToTheCatcher(t *testing.T) {
	smtpAddr, mailpit := os.Getenv("TEST_SMTP_ADDR"), os.Getenv("TEST_MAILPIT_URL")
	if smtpAddr == "" || mailpit == "" {
		t.Skip("TEST_SMTP_ADDR / TEST_MAILPIT_URL not set")
	}
	f := newFixture(t)
	to := "catcher-" + uuid.NewString()[:8] + "@example.test"
	id := f.queue(t, to)
	s := newSender(f, transport.SMTP{Addr: smtpAddr})
	if _, err := s.Deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := f.state(t, id); st["state"] != "sent" {
		t.Fatalf("not sent: %v", st)
	}
	resp, err := http.Get(mailpit + "/api/v1/search?query=to:" + to)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var found struct {
		Messages []struct {
			Subject string `json:"Subject"`
		} `json:"messages"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&found)
	if len(found.Messages) != 1 || !strings.Contains(found.Messages[0].Subject, "Acme") {
		t.Fatalf("in the catcher: %+v", found)
	}
}
