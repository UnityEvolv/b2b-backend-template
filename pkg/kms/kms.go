// Package kms wraps and unwraps per-org data keys under a master key that
// never leaves the key management service.
//
// Nothing else calls KMS directly. The organization service wraps a new org's
// data key; the services allowed to decrypt (identity, and any
// product service that keeps secrets) unwrap it, and KMS IAM on each service's identity is what makes
// that list true. Locally a file-backed stub stands in behind the same
// interface, so no developer needs cloud credentials.
package kms

import (
	"context"
	"errors"
)

// Wrapper is a master key.
type Wrapper interface {
	// Wrap encrypts a data key under the current master key version.
	Wrap(ctx context.Context, dataKey []byte) (wrapped []byte, version string, err error)
	// Unwrap decrypts a wrapped data key. The version it was wrapped under is
	// recorded with it; the master key knows its own versions.
	Unwrap(ctx context.Context, wrapped []byte) (dataKey []byte, err error)
	// Version is the current master key version, so a wrapped key under an
	// older one can be re-wrapped.
	Version(ctx context.Context) (string, error)
}

// ErrUnwrap means the wrapped key could not be unwrapped: wrong master key,
// wrong version, or tampered data.
var ErrUnwrap = errors.New("kms: cannot unwrap")

// DataKeySize is the size of every org data key: AES-256.
const DataKeySize = 32
