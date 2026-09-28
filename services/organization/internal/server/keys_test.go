package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
)

// testWrapper is a file-backed master key in a temp dir, one per test.
func testWrapper(t *testing.T) *filekms.KMS {
	t.Helper()
	k, err := filekms.Open(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The org's first key, made the way org creation will make it.
func ensureKey(t *testing.T, cluster *db.Cluster, srv keyEnsurer, org string) {
	t.Helper()
	ctx := db.WithActor(context.Background(), db.SystemActor("organization"))
	err := cluster.Tx(ctx, org, func(tx pgx.Tx) error {
		return srv.EnsureDataKey(ctx, tx, uuid.MustParse(org))
	})
	if err != nil {
		t.Fatal(err)
	}
}

type keyEnsurer interface {
	EnsureDataKey(context.Context, pgx.Tx, uuid.UUID) error
}

func TestOnlyDecryptingServicesMayFetchAKey(t *testing.T) {
	h, cluster, issuer, srv := newAPIWithServer(t)
	ensureKey(t, cluster, srv, testOrg)
	path := "/v1/internal/organizations/" + testOrg + "/data-keys/current"

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"identity", tokenForService(t, issuer, "identity"), http.StatusOK},
		{"billing", tokenForService(t, issuer, "billing"), http.StatusForbidden},
		{"organization itself", tokenForService(t, issuer, "organization"), http.StatusForbidden},
		{"a member of the org", tokenFor(t, issuer, testOrg), http.StatusForbidden},
		{"nobody", "", http.StatusUnauthorized},
	}
	for _, c := range cases {
		status, body := get(t, h, path, c.token)
		if status != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, status, body, c.want)
		}
		if status == http.StatusOK && (body["wrapped_key"] == "" || body["version"].(float64) != 1) {
			t.Errorf("%s: key body %v", c.name, body)
		}
	}
}

// The whole loop a decrypting service runs: fetch the wrapped key through the
// API, unwrap it with KMS, seal and open a secret. Another org cannot read it.
func TestASecretRoundTripsThroughTheOrganizationService(t *testing.T) {
	h, cluster, issuer, srv := newAPIWithServer(t)
	otherOrg := "01922b5e-0000-7000-8000-0000000000ee"
	ensureKey(t, cluster, srv, testOrg)
	ensureKey(t, cluster, srv, otherOrg)
	api := httptest.NewServer(h)
	defer api.Close()

	// The service and the organization service share the master key: locally
	// one file, deployed one Cloud KMS key.
	keys := envelope.OrgKeys(api.URL, auth.StaticToken(tokenForService(t, issuer, "identity")), api.Client())
	ring := envelope.New(keys, srv.Wrapper())
	ctx := context.Background()

	blob, err := ring.Encrypt(ctx, testOrg, []byte("sso-client-secret"), "provider_credentials")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ring.Decrypt(ctx, testOrg, blob, "provider_credentials")
	if err != nil || string(got) != "sso-client-secret" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ring.Decrypt(ctx, otherOrg, blob, "provider_credentials"); err == nil {
		t.Fatal("another org decrypted the secret")
	}

	// A service that may not decrypt cannot even fetch the key.
	denied := envelope.New(envelope.OrgKeys(api.URL, auth.StaticToken(tokenForService(t, issuer, "billing")), api.Client()), srv.Wrapper())
	if _, err := denied.Decrypt(ctx, testOrg, blob, "provider_credentials"); err == nil {
		t.Fatal("the billing service decrypted a secret")
	}
}

func TestRotationKeepsOldVersionsReadable(t *testing.T) {
	h, cluster, issuer, srv := newAPIWithServer(t)
	ensureKey(t, cluster, srv, testOrg)
	api := httptest.NewServer(h)
	defer api.Close()
	ring := envelope.New(envelope.OrgKeys(api.URL, auth.StaticToken(tokenForService(t, issuer, "identity")), api.Client()), srv.Wrapper())
	ctx := context.Background()

	before, _ := ring.Encrypt(ctx, testOrg, []byte("old"), "p")

	req, _ := http.NewRequest(http.MethodPost, api.URL+"/v1/internal/organizations/"+testOrg+"/data-keys/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+tokenForService(t, issuer, "organization"))
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var rotated map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rotated)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || rotated["version"].(float64) != 2 {
		t.Fatalf("rotate: %d %v", resp.StatusCode, rotated)
	}

	after, _ := ring.Encrypt(ctx, testOrg, []byte("new"), "p")
	if v, _ := envelope.KeyVersion(after); v != 2 {
		t.Fatalf("new secrets use version %d", v)
	}
	for _, c := range []struct {
		blob []byte
		want string
	}{{before, "old"}, {after, "new"}} {
		if got, err := ring.Decrypt(ctx, testOrg, c.blob, "p"); err != nil || string(got) != c.want {
			t.Fatalf("%q %v", got, err)
		}
	}

	// A person cannot rotate.
	req, _ = http.NewRequest(http.MethodPost, api.URL+"/v1/internal/organizations/"+testOrg+"/data-keys/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, issuer, testOrg))
	if resp, err := api.Client().Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a member rotating: %v %d", err, resp.StatusCode)
	}
}

// Done criterion: a master key rotation re-wraps every org key without
