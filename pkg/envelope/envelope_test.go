package envelope_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/filekms"
)

const (
	orgA = "01922b5e-0000-7000-8000-0000000000a1"
	orgB = "01922b5e-0000-7000-8000-0000000000b1"
)

// fakeSource is the organization service in miniature: wrapped keys per org
// and version, with rotation.
type fakeSource struct {
	wrapper kms.Wrapper
	keys    map[string][]envelope.WrappedKey
}

func newSource(t *testing.T, wrapper kms.Wrapper, orgs ...string) *fakeSource {
	t.Helper()
	s := &fakeSource{wrapper: wrapper, keys: map[string][]envelope.WrappedKey{}}
	for _, org := range orgs {
		s.rotate(t, org)
	}
	return s
}

func (s *fakeSource) rotate(t *testing.T, org string) {
	t.Helper()
	dataKey, err := envelope.NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _, err := s.wrapper.Wrap(context.Background(), dataKey)
	if err != nil {
		t.Fatal(err)
	}
	s.keys[org] = append(s.keys[org], envelope.WrappedKey{OrgID: org, Version: uint32(len(s.keys[org]) + 1), Wrapped: wrapped})
}

func (s *fakeSource) Current(_ context.Context, org string) (envelope.WrappedKey, error) {
	if len(s.keys[org]) == 0 {
		return envelope.WrappedKey{}, errors.New("no key for org")
	}
	return s.keys[org][len(s.keys[org])-1], nil
}

func (s *fakeSource) Version(_ context.Context, org string, version uint32) (envelope.WrappedKey, error) {
	for _, k := range s.keys[org] {
		if k.Version == version {
			return k, nil
		}
	}
	return envelope.WrappedKey{}, errors.New("no such version")
}

func local(t *testing.T) *filekms.KMS {
	t.Helper()
	k, err := filekms.Open(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	master := local(t)
	ring := envelope.New(newSource(t, master, orgA), master)
	ctx := context.Background()

	blob, err := ring.Encrypt(ctx, orgA, []byte("lk_api_secret_123"), "provider_credentials")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("lk_api_secret")) {
		t.Fatal("plaintext visible in the blob")
	}
	got, err := ring.Decrypt(ctx, orgA, blob, "provider_credentials")
	if err != nil || string(got) != "lk_api_secret_123" {
		t.Fatalf("%q %v", got, err)
	}
	if v, ok := envelope.KeyVersion(blob); !ok || v != 1 {
		t.Fatalf("key version %d %v", v, ok)
	}
}

// Done criterion: a stored credential can only be decrypted through its own
// org's key.
func TestCrossOrgDecryptFails(t *testing.T) {
	master := local(t)
	source := newSource(t, master, orgA, orgB)
	ring := envelope.New(source, master)
	ctx := context.Background()

	blob, err := ring.Encrypt(ctx, orgA, []byte("secret"), "provider_credentials")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Decrypt(ctx, orgB, blob, "provider_credentials"); !errors.Is(err, envelope.ErrCannotDecrypt) {
		t.Fatalf("org B read org A's secret: %v", err)
	}
	// Even with org B's key swapped for org A's, the org id is bound in.
	source.keys[orgB] = source.keys[orgA]
	if _, err := ring.Decrypt(ctx, orgB, blob, "provider_credentials"); !errors.Is(err, envelope.ErrCannotDecrypt) {
		t.Fatalf("same key, other org: %v", err)
	}
}

func TestPurposeAndIntegrityAreBound(t *testing.T) {
	master := local(t)
	ring := envelope.New(newSource(t, master, orgA), master)
	ctx := context.Background()
	blob, _ := ring.Encrypt(ctx, orgA, []byte("secret"), "webhook_secret")

	if _, err := ring.Decrypt(ctx, orgA, blob, "provider_credentials"); !errors.Is(err, envelope.ErrCannotDecrypt) {
		t.Fatalf("read as another purpose: %v", err)
	}
	tampered := append([]byte{}, blob...)
	tampered[len(tampered)-1] ^= 1
	if _, err := ring.Decrypt(ctx, orgA, tampered, "webhook_secret"); !errors.Is(err, envelope.ErrCannotDecrypt) {
		t.Fatalf("tampered blob: %v", err)
	}
	if _, err := ring.Decrypt(ctx, orgA, []byte("nope"), "webhook_secret"); !errors.Is(err, envelope.ErrCannotDecrypt) {
		t.Fatalf("garbage: %v", err)
	}
}

// After a per-org rotation, old blobs still open and new ones use the new
// version, so re-encryption can happen gradually.
func TestOrgKeyRotation(t *testing.T) {
	master := local(t)
	source := newSource(t, master, orgA)
	ring := envelope.New(source, master)
	ctx := context.Background()

	old, _ := ring.Encrypt(ctx, orgA, []byte("before"), "p")
	source.rotate(t, orgA)
	fresh, _ := ring.Encrypt(ctx, orgA, []byte("after"), "p")

	if v, _ := envelope.KeyVersion(old); v != 1 {
		t.Fatalf("old version %d", v)
	}
	if v, _ := envelope.KeyVersion(fresh); v != 2 {
		t.Fatalf("new version %d", v)
	}
	for _, c := range []struct {
		blob []byte
		want string
	}{{old, "before"}, {fresh, "after"}} {
		got, err := ring.Decrypt(ctx, orgA, c.blob, "p")
		if err != nil || string(got) != c.want {
			t.Fatalf("%q %v", got, err)
		}
	}
}

// Done criterion: a master key rotation re-wraps every org key without
// downtime. Blobs open before, during and after; nothing is re-encrypted.
func TestMasterKeyRotationRewrapsWithoutDowntime(t *testing.T) {
	master := local(t)
	source := newSource(t, master, orgA, orgB)
	ring := envelope.New(source, master)
	ctx := context.Background()
	blob, _ := ring.Encrypt(ctx, orgA, []byte("secret"), "p")

	if _, err := master.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Not yet re-wrapped: the old master version still unwraps it.
	if got, err := ring.Decrypt(ctx, orgA, blob, "p"); err != nil || string(got) != "secret" {
		t.Fatalf("during rotation: %q %v", got, err)
	}

	// The re-wrap pass: unwrap under the old version, wrap under the new.
	for org, keys := range source.keys {
		for i, k := range keys {
			dataKey, err := master.Unwrap(ctx, k.Wrapped)
			if err != nil {
				t.Fatal(err)
			}
			rewrapped, version, err := master.Wrap(ctx, dataKey)
			if err != nil || version != "2" {
				t.Fatalf("rewrap: %s %v", version, err)
			}
			source.keys[org][i].Wrapped = rewrapped
		}
	}
	if got, err := ring.Decrypt(ctx, orgA, blob, "p"); err != nil || string(got) != "secret" {
		t.Fatalf("after re-wrap: %q %v", got, err)
	}
}

func TestFileKMS(t *testing.T) {
	k := local(t)
	ctx := context.Background()
	wrapped, version, err := k.Wrap(ctx, bytes.Repeat([]byte{7}, kms.DataKeySize))
	if err != nil || version != "1" {
		t.Fatal(err)
	}
	if v, _ := k.Version(ctx); v != "1" {
		t.Fatalf("version %s", v)
	}
	got, err := k.Unwrap(ctx, wrapped)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{7}, kms.DataKeySize)) {
		t.Fatalf("%x %v", got, err)
	}
	other := local(t)
	if _, err := other.Unwrap(ctx, wrapped); !errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("another master key unwrapped it: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 1
	if _, err := k.Unwrap(ctx, wrapped); !errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("tampered wrap: %v", err)
	}
}
