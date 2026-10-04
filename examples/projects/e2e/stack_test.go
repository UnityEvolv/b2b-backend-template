// Package e2e runs the example product against the template's own
// services, built from this repository and run unchanged as processes, each
// configured the way a deployment configures it: the product's permission
// group in PERMISSION_GROUPS, its notification category in
// NOTIFICATION_CATEGORIES, its data owner entry in DATA_OWNERS, its plan
// limit and ladder in PLANS, all rendered from package product. Nothing is
// faked: a seam that did not hold would fail here.
//
// The template's services cannot be imported from here (their packages
// are internal to each service, and a product never imports a service), so
// the harness builds their commands and runs them. It needs a Postgres, a
// Redis and an S3-compatible store (TEST_DATABASE_ADMIN_URL, TEST_REDIS_URL,
// TEST_S3_*), and skips without them.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/examples/projects/product"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db/dbtest"
)

// The template's services, and the product's.
var (
	core     = []string{"identity", "organization", "user", "authorization", "audit", "notification", "billing"}
	services = append(append([]string{}, core...), product.Name)
)

type proc struct {
	name string
	port int
	env  []string
	cmd  *exec.Cmd
	done chan struct{}
	log  string
}

// stack is every service running, on its own port, against one fresh
// database.
type stack struct {
	t      *testing.T
	bin    string
	dbURL  string
	prefix string
	procs  map[string]*proc
	mu     sync.Mutex
}

func need(t *testing.T, names ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range names {
		v := os.Getenv(n)
		if v == "" {
			t.Skipf("%s is not set", n)
		}
		out[n] = v
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// build compiles every service and the product's migrate command.
func build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pkgs := []string{"./examples/projects", "./examples/projects/cmd/projects-migrate"}
	for _, s := range core {
		pkgs = append(pkgs, "./services/"+s)
	}
	cmd := exec.Command("go", append([]string{"build", "-o", dir + string(os.PathSeparator)}, pkgs...)...)
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return dir
}

// newStack builds, migrates with the product's own command, and starts
// every service.
func newStack(t *testing.T) *stack {
	t.Helper()
	cfg := need(t, "TEST_DATABASE_ADMIN_URL", "TEST_REDIS_URL", "TEST_S3_ENDPOINT", "TEST_S3_BUCKET", "TEST_S3_ACCESS_KEY", "TEST_S3_SECRET_KEY")
	// A fresh database with the template's schemas and roles, and nothing of
	// the product's yet: the product's own command makes those.
	dbURL := dbtest.New(t)
	s := &stack{t: t, bin: build(t), dbURL: dbURL, prefix: "e2e" + strings.ReplaceAll(uuid.NewString()[:8], "-", ""), procs: map[string]*proc{}}

	migrate := exec.Command(filepath.Join(s.bin, exe("projects-migrate")), "setup")
	migrate.Env = append(os.Environ(), "DATABASE_ADMIN_URL="+dbURL, "DATABASE_URL="+dbURL, "DB_LOCAL_PASSWORDS=true")
	if out, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("projects-migrate setup: %v\n%s", err, out)
	}

	for _, name := range services {
		s.procs[name] = &proc{name: name, port: freePort(t), log: filepath.Join(t.TempDir(), name+".log")}
	}
	logs := t.TempDir()
	env := map[string]string{
		"DATABASE_URL": dbURL, "DB_LOCAL_PASSWORDS": "true", "ENVIRONMENT": "local", "LOG_LEVEL": "warn",
		"AUTH_ISSUER": "e2e-issuer", "AUTH_JWKS_URL": s.url("identity") + "/v1/jwks",
		"REDIS_URL": cfg["TEST_REDIS_URL"], "REDIS_PREFIX": s.prefix,
		"SERVICE_TOKEN_URL": s.url("identity"), "LOCAL_SERVICE_TOKENS": "true",
		"S3_ENDPOINT": cfg["TEST_S3_ENDPOINT"], "S3_REGION": "us-east-1", "S3_PATH_STYLE": "true", "S3_BUCKET": cfg["TEST_S3_BUCKET"],
		"S3_ACCESS_KEY": cfg["TEST_S3_ACCESS_KEY"], "S3_SECRET_KEY": cfg["TEST_S3_SECRET_KEY"],
		"KMS_PROVIDER": "file", "KMS_FILE": filepath.Join(logs, "master.json"),
		"APP_ORIGIN_ACCOUNT": "http://localhost:5173", "APP_ORIGIN_ADMIN": "http://localhost:5174", "APP_ORIGIN_PLATFORM": "http://localhost:5175",
		"ALLOWED_ORIGINS":     "http://localhost:5173,http://localhost:5174,http://localhost:5175",
		"IDENTITY_PUBLIC_URL": s.url("identity"), "NOTIFICATION_PUBLIC_URL": s.url("notification"), "SECURE_COOKIES": "false",
		"CAPTCHA_PROVIDER": "off", "EMAIL_TRANSPORT": "smtp", "SMTP_ADDR": fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		"EMAIL_FROM": "E2E <no-reply@example.test>", "NOTIFICATION_LINK_KEY": "e2e-notification-link-key",
	}
	for _, name := range services {
		env[strings.ToUpper(name)+"_URL"] = s.url(name)
	}
	// What a deployment sets for the product, from the product's own
	// declarations: DATA_OWNERS on every service, the permission group on the
	// authorization service, the category on the notification service, the
	// ladder with its projects caps on every service that reads plans, its
	// onboarding step on the organization service.
	productEnv := product.Env()
	env["DATA_OWNERS"] = productEnv["DATA_OWNERS"]
	for _, p := range s.procs {
		mine := map[string]string{"PORT": strconv.Itoa(p.port)}
		switch p.name {
		case "authorization":
			mine["PERMISSION_GROUPS"] = productEnv["PERMISSION_GROUPS"]
		case "notification":
			mine["NOTIFICATION_CATEGORIES"] = productEnv["NOTIFICATION_CATEGORIES"]
		case "organization", "user", "billing", "identity":
			mine["PLANS"] = productEnv["PLANS"]
		}
		if p.name == "organization" {
			mine["ONBOARDING_STEPS"] = productEnv["ONBOARDING_STEPS"]
		}
		p.env = os.Environ()
		for k, v := range env {
			p.env = append(p.env, k+"="+v)
		}
		for k, v := range mine {
			p.env = append(p.env, k+"="+v)
		}
	}
	t.Cleanup(s.stopAll)
	for _, name := range services {
		s.start(name)
	}
	for _, name := range services {
		s.waitReady(name)
	}
	return s
}

func (s *stack) url(name string) string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.procs[name].port)
}

func (s *stack) start(name string) {
	s.t.Helper()
	p := s.procs[name]
	log, err := os.OpenFile(p.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(s.bin, exe(name)))
	cmd.Env = p.env
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		s.t.Fatalf("start %s: %v", name, err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		log.Close()
		close(done)
	}()
	s.mu.Lock()
	p.cmd, p.done = cmd, done
	s.mu.Unlock()
}

func (s *stack) stop(name string) {
	s.mu.Lock()
	p := s.procs[name]
	cmd, done := p.cmd, p.done
	s.mu.Unlock()
	if cmd == nil {
		return
	}
	_ = cmd.Process.Kill()
	<-done
}

func (s *stack) stopAll() {
	for _, name := range services {
		s.stop(name)
	}
	if s.t.Failed() {
		for _, name := range services {
			s.t.Logf("---- %s log (tail)\n%s", name, tail(s.procs[name].log, 40))
		}
	}
}

// restart is a service's process ending and starting again: what a deploy
// or a crash does, and what runs a service's start-of-day passes now.
func (s *stack) restart(name string) {
	s.t.Helper()
	s.stop(name)
	s.start(name)
	s.waitReady(name)
}

func (s *stack) waitReady(name string) {
	s.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.procs[name].done:
			s.t.Fatalf("%s exited at start:\n%s", name, tail(s.procs[name].log, 40))
		default:
		}
		resp, err := http.Get(s.url(name) + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("%s is not ready:\n%s", name, tail(s.procs[name].log, 40))
}

func tail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return err.Error()
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

// reply is one answer: its status, its body decoded, and its headers.
type reply struct {
	status int
	body   map[string]any
	raw    []byte
	header http.Header
}

func (r reply) String() string { return fmt.Sprintf("%d %s", r.status, r.raw) }

// code is the error envelope's code.
func (r reply) code() string { s, _ := r.body["code"].(string); return s }

func (r reply) str(key string) string { s, _ := r.body[key].(string); return s }

// call sends a JSON request with a bearer token and, when key is not
// empty, an idempotency key.
func (s *stack) call(method, url, token string, body any, key ...string) reply {
	s.t.Helper()
	var in io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.t.Fatal(err)
		}
		in = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, in)
	if err != nil {
		s.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if len(key) > 0 && key[0] != "" {
		req.Header.Set("Idempotency-Key", key[0])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := reply{status: resp.StatusCode, raw: raw, header: resp.Header}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

// token is one from the identity service's local token endpoint, as the
// local stack mints them.
func (s *stack) token(claims map[string]any) (string, int) {
	s.t.Helper()
	r := s.call(http.MethodPost, s.url("identity")+"/token", "", claims)
	return r.str("access_token"), r.status
}

func (s *stack) serviceToken(name string) string {
	s.t.Helper()
	tok, status := s.token(map[string]any{"service": name})
	if status != http.StatusOK {
		s.t.Fatalf("a token for %s: %d", name, status)
	}
	return tok
}

// person is someone with a membership in an org, and their token.
type person struct {
	membership, user, org uuid.UUID
	token                 string
}

func (s *stack) personToken(p *person) {
	s.t.Helper()
	tok, status := s.token(map[string]any{"user_id": p.user.String(), "org_id": p.org.String(), "membership_id": p.membership.String()})
	if status != http.StatusOK {
		s.t.Fatalf("person token: %d", status)
	}
	p.token = tok
}

// org is an organization made by a platform operator, on the plan asked
// for, with people in it made the way an invite makes them.
func (s *stack) org(operator, name, band string) uuid.UUID {
	s.t.Helper()
	r := s.call(http.MethodPost, s.url("organization")+"/v1/organizations", operator,
		map[string]any{"name": name, "time_zone": "UTC"}, "e2e-org-"+name)
	if r.status != http.StatusCreated {
		s.t.Fatalf("create %s: %s", name, r)
	}
	id := uuid.MustParse(r.str("org_id"))
	if band != "free" {
		if r := s.call(http.MethodPut, s.url("organization")+"/v1/organizations/"+id.String()+"/plan", operator, map[string]any{"plan": band}); r.status != http.StatusOK {
			s.t.Fatalf("plan %s: %s", band, r)
		}
	}
	return id
}

func (s *stack) member(org uuid.UUID, email, role string) *person {
	s.t.Helper()
	body := map[string]any{"org_id": org.String(), "email": email, "name": strings.Split(email, "@")[0], "source": "invite", "role": role}
	if role == "owner" {
		body = map[string]any{"org_id": org.String(), "email": email, "source": "owner"}
	}
	r := s.call(http.MethodPost, s.url("user")+"/v1/internal/memberships", s.serviceToken("identity"), body, "e2e-member-"+email)
	if r.status != http.StatusCreated || r.str("status") != "active" {
		s.t.Fatalf("membership for %s: %s", email, r)
	}
	user, _ := r.body["user"].(map[string]any)
	p := &person{membership: uuid.MustParse(r.str("id")), user: uuid.MustParse(user["id"].(string)), org: org}
	s.personToken(p)
	return p
}

// eventually retries check until it says it is done, or fails after a
// while with what it last said.
func eventually(t *testing.T, what string, check func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	last := ""
	for time.Now().Before(deadline) {
		var ok bool
		if ok, last = check(); ok {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s: never happened; last: %s", what, last)
}
