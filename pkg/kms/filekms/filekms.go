// Package filekms is the local stand-in for a cloud KMS: master key versions
// in one file on the developer's machine, git-ignored, created on first use.
// Never used anywhere but a laptop; the compose stack points every service at
// the same file.
package filekms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
)

type file struct {
	Primary  int               `json:"primary"`
	Versions map[string][]byte `json:"versions"`
}

// KMS is a file-backed master key.
type KMS struct {
	path string
	mu   sync.Mutex
}

// Open is the master key stored at path, created if there is nothing there.
func Open(path string) (*KMS, error) {
	k := &KMS{path: path}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := k.write(&file{Primary: 1, Versions: map[string][]byte{"1": random()}}); err != nil {
			return nil, err
		}
	}
	if _, err := k.read(); err != nil {
		return nil, err
	}
	return k, nil
}

func random() []byte {
	b := make([]byte, kms.DataKeySize)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func (k *KMS) read() (*file, error) {
	raw, err := os.ReadFile(k.path)
	if err != nil {
		return nil, fmt.Errorf("filekms: %w", err)
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil || f.Primary == 0 || len(f.Versions) == 0 {
		return nil, fmt.Errorf("filekms: %s is not a key file", k.path)
	}
	return &f, nil
}

func (k *KMS) write(f *file) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(k.path, raw, 0o600)
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Wrap encrypts dataKey under the primary version: version(4) | nonce | ciphertext.
func (k *KMS) Wrap(_ context.Context, dataKey []byte) ([]byte, string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.read()
	if err != nil {
		return nil, "", err
	}
	version := strconv.Itoa(f.Primary)
	g, err := aead(f.Versions[version])
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(f.Primary))
	out = append(out, nonce...)
	out = g.Seal(out, nonce, dataKey, out[:4])
	return out, version, nil
}

// Unwrap decrypts a wrapped key under the version it names.
func (k *KMS) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.read()
	if err != nil {
		return nil, err
	}
	if len(wrapped) < 4+12 {
		return nil, kms.ErrUnwrap
	}
	version := strconv.Itoa(int(binary.BigEndian.Uint32(wrapped[:4])))
	master, ok := f.Versions[version]
	if !ok {
		return nil, fmt.Errorf("%w: no master key version %s", kms.ErrUnwrap, version)
	}
	g, err := aead(master)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := wrapped[4:4+g.NonceSize()], wrapped[4+g.NonceSize():]
	dataKey, err := g.Open(nil, nonce, ciphertext, wrapped[:4])
	if err != nil {
		return nil, kms.ErrUnwrap
	}
	return dataKey, nil
}

// Version is the primary version.
func (k *KMS) Version(context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.read()
	if err != nil {
		return "", err
	}
	return strconv.Itoa(f.Primary), nil
}

// Rotate adds a new primary version. Old versions stay, so keys wrapped under
// them still unwrap until they are re-wrapped.
func (k *KMS) Rotate() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, err := k.read()
	if err != nil {
		return "", err
	}
	f.Primary++
	f.Versions[strconv.Itoa(f.Primary)] = random()
	if err := k.write(f); err != nil {
		return "", err
	}
	return strconv.Itoa(f.Primary), nil
}
