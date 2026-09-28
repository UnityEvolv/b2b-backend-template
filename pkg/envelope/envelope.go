// Package envelope encrypts a customer's secrets under that customer's own
// key (UO-45).
//
// Each org has a data key, generated when the org is created and stored
// wrapped by the KMS master key in the organization service. A service that
// needs to read a secret asks the organization service for the wrapped key,
// unwraps it through KMS (which is where IAM decides whether it may) and uses
// it in memory for the length of the request. Nothing caches a plaintext key.
//
//	blob, err := keyring.Encrypt(ctx, orgID, plaintext, "provider_credentials")
//	plaintext, err := keyring.Decrypt(ctx, orgID, blob, "provider_credentials")
//
// The org id is bound into every ciphertext, so a blob decrypted under another
// org's key fails, whatever the key.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
)

// WrappedKey is one version of an org's data key, as the organization
// service holds it.
type WrappedKey struct {
	OrgID   string
	Version uint32
	Wrapped []byte
}

// KeySource is where wrapped keys come from: the organization service's
// internal API, or a fake in tests.
type KeySource interface {
	// Current is the org's current key version, the one new secrets use.
	Current(ctx context.Context, orgID string) (WrappedKey, error)
	// Version is one specific version, for a secret written under it.
	Version(ctx context.Context, orgID string, version uint32) (WrappedKey, error)
}

// Keyring encrypts and decrypts for any org.
type Keyring struct {
	keys    KeySource
	wrapper kms.Wrapper
}

// New is a keyring over keys, unwrapping with wrapper.
func New(keys KeySource, wrapper kms.Wrapper) *Keyring {
	return &Keyring{keys: keys, wrapper: wrapper}
}

// ErrCannotDecrypt means the blob is not this org's, was written under a key
// this service cannot reach, or was changed.
var ErrCannotDecrypt = errors.New("envelope: cannot decrypt")

const (
	formatV1  = 1
	nonceSize = 12
	headerLen = 1 + 4 // format, key version
)

// Encrypt seals plaintext for orgID under its current key. purpose says what
// the blob is (a provider credential, a webhook secret); the same purpose is
// needed to decrypt, so a blob cannot be read back as something else.
func (k *Keyring) Encrypt(ctx context.Context, orgID string, plaintext []byte, purpose string) ([]byte, error) {
	if orgID == "" {
		return nil, errors.New("envelope: an org is required")
	}
	key, err := k.keys.Current(ctx, orgID)
	if err != nil {
		return nil, err
	}
	g, err := k.open(ctx, key)
	if err != nil {
		return nil, err
	}
	header := binary.BigEndian.AppendUint32([]byte{formatV1}, key.Version)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	blob := append(header, nonce...)
	return g.Seal(blob, nonce, plaintext, aad(orgID, purpose, header)), nil
}

// Decrypt opens a blob for orgID with the purpose it was sealed for.
func (k *Keyring) Decrypt(ctx context.Context, orgID string, blob []byte, purpose string) ([]byte, error) {
	if len(blob) < headerLen+nonceSize || blob[0] != formatV1 {
		return nil, ErrCannotDecrypt
	}
	header := blob[:headerLen]
	version := binary.BigEndian.Uint32(header[1:])
	key, err := k.keys.Version(ctx, orgID, version)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCannotDecrypt, err)
	}
	g, err := k.open(ctx, key)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := blob[headerLen:headerLen+nonceSize], blob[headerLen+nonceSize:]
	plaintext, err := g.Open(nil, nonce, ciphertext, aad(orgID, purpose, header))
	if err != nil {
		return nil, ErrCannotDecrypt
	}
	return plaintext, nil
}

// KeyVersion is the key version a blob was sealed under, for re-encrypting
// after a rotation.
func KeyVersion(blob []byte) (uint32, bool) {
	if len(blob) < headerLen || blob[0] != formatV1 {
		return 0, false
	}
	return binary.BigEndian.Uint32(blob[1:headerLen]), true
}

func (k *Keyring) open(ctx context.Context, key WrappedKey) (cipher.AEAD, error) {
	dataKey, err := k.wrapper.Unwrap(ctx, key.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCannotDecrypt, err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds the org, the purpose and the header into the ciphertext.
func aad(orgID, purpose string, header []byte) []byte {
	return append([]byte(orgID+"|"+purpose+"|"), header...)
}

// NewDataKey is a fresh random data key, for the organization service to
// wrap when an org is created or its key rotated.
func NewDataKey() ([]byte, error) {
	b := make([]byte, kms.DataKeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
