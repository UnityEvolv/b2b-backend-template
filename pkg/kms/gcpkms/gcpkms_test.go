package gcpkms_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms/gcpkms"
)

// Against the real master key, with the developer's own credentials. Needs
// TEST_KMS_KEY_NAME (the full crypto key name); skipped without it.
func TestWrapAndUnwrapAgainstCloudKMS(t *testing.T) {
	name := os.Getenv("TEST_KMS_KEY_NAME")
	if name == "" {
		t.Skip("TEST_KMS_KEY_NAME is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	k, err := gcpkms.Open(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	dataKey := bytes.Repeat([]byte{42}, kms.DataKeySize)
	wrapped, version, err := k.Wrap(ctx, dataKey)
	if err != nil || version == "" {
		t.Fatalf("wrap: %s %v", version, err)
	}
	if bytes.Contains(wrapped, dataKey) {
		t.Fatal("data key visible in the wrap")
	}
	current, err := k.Version(ctx)
	if err != nil || current != version {
		t.Fatalf("primary %s, wrapped under %s: %v", current, version, err)
	}
	got, err := k.Unwrap(ctx, wrapped)
	if err != nil || !bytes.Equal(got, dataKey) {
		t.Fatalf("unwrap: %x %v", got, err)
	}
	wrapped[len(wrapped)-1] ^= 1
	if _, err := k.Unwrap(ctx, wrapped); !errors.Is(err, kms.ErrUnwrap) {
		t.Fatalf("tampered: %v", err)
	}
}
