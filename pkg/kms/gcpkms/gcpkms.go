// Package gcpkms is the master key in Google Cloud KMS: an HSM-backed key
// that is never exported. Wrap and Unwrap are one KMS call each; every call
// lands in the cloud audit log with the calling service's identity, and the
// key's IAM policy decides which services may unwrap at all.
package gcpkms

import (
	"context"
	"fmt"
	"strings"

	kmsapi "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
)

// KMS is one crypto key, named in full:
// projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>.
type KMS struct {
	client *kmsapi.KeyManagementClient
	key    string
}

// Open connects with the process's own credentials (a service's identity when
// deployed, the developer's application default credentials otherwise).
func Open(ctx context.Context, keyName string) (*KMS, error) {
	if !strings.HasPrefix(keyName, "projects/") {
		return nil, fmt.Errorf("gcpkms: %q is not a full crypto key name", keyName)
	}
	client, err := kmsapi.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: %w", err)
	}
	return &KMS{client: client, key: keyName}, nil
}

// Close releases the connection.
func (k *KMS) Close() error { return k.client.Close() }

// Wrap encrypts dataKey under the key's primary version. KMS records the
// version inside the ciphertext, so Unwrap needs nothing else.
func (k *KMS) Wrap(ctx context.Context, dataKey []byte) ([]byte, string, error) {
	resp, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{Name: k.key, Plaintext: dataKey})
	if err != nil {
		return nil, "", fmt.Errorf("gcpkms: wrap: %w", err)
	}
	return resp.Ciphertext, versionOf(resp.Name), nil
}

// Unwrap decrypts a wrapped key. Refused by KMS IAM for a service that may
// not decrypt, which is the point.
func (k *KMS) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	resp, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{Name: k.key, Ciphertext: wrapped})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", kms.ErrUnwrap, err)
	}
	return resp.Plaintext, nil
}

// Version is the key's primary version.
func (k *KMS) Version(ctx context.Context) (string, error) {
	key, err := k.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: k.key})
	if err != nil {
		return "", fmt.Errorf("gcpkms: %w", err)
	}
	if key.Primary == nil {
		return "", fmt.Errorf("gcpkms: %s has no primary version", k.key)
	}
	return versionOf(key.Primary.Name), nil
}

// versionOf is the short version of a cryptoKeyVersions resource name.
func versionOf(name string) string {
	if i := strings.LastIndex(name, "/cryptoKeyVersions/"); i >= 0 {
		return name[i+len("/cryptoKeyVersions/"):]
	}
	return name
}
