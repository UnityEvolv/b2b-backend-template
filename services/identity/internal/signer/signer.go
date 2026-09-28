// Package signer issues the platform's tokens and publishes the keys every
// service verifies them with. The private key is generated here, wrapped by
// the KMS master key for the database, and lives unwrapped only in memory.
package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/kms"
	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/store"
)

// Signer holds the active key and the published set.
type Signer struct {
	issuer, audience string
	mu               sync.RWMutex
	active           jwk.Key
	public           jwk.Set
}

// Load reads the signing keys, unwrapping the active one, and makes the
// first key when there is none yet. Called at start.
func Load(ctx context.Context, cluster *db.Cluster, wrapper kms.Wrapper, issuer, audience string) (*Signer, error) {
	s := &Signer{issuer: issuer, audience: audience}
	ctx = db.WithActor(ctx, db.SystemActor("identity"))
	err := cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		keys, err := q.ListSigningKeys(ctx)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			made, err := generate(ctx, q, wrapper)
			if err != nil {
				return err
			}
			keys = []store.SigningKey{made}
		}
		return s.load(ctx, keys, wrapper)
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func generate(ctx context.Context, q *store.Queries, wrapper kms.Wrapper) (store.SigningKey, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return store.SigningKey{}, err
	}
	// The P-256 private scalar is 32 bytes: exactly a data key's size, so
	// the KMS wraps it as it wraps any other.
	scalar := make([]byte, 32)
	raw.D.FillBytes(scalar)
	wrapped, version, err := wrapper.Wrap(ctx, scalar)
	if err != nil {
		return store.SigningKey{}, fmt.Errorf("wrap signing key: %w", err)
	}
	public, err := jwk.Import(&raw.PublicKey)
	if err != nil {
		return store.SigningKey{}, err
	}
	kid := uuid.NewString()
	if err := public.Set(jwk.KeyIDKey, kid); err != nil {
		return store.SigningKey{}, err
	}
	if err := public.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		return store.SigningKey{}, err
	}
	if err := public.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return store.SigningKey{}, err
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return store.SigningKey{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.SigningKey{}, err
	}
	return q.InsertSigningKey(ctx, store.InsertSigningKeyParams{
		ID: id, Kid: kid, Algorithm: "ES256", WrappedPrivate: wrapped, KmsKeyVersion: version, PublicJwk: publicJSON,
	})
}

func (s *Signer) load(ctx context.Context, keys []store.SigningKey, wrapper kms.Wrapper) error {
	set := jwk.NewSet()
	var active jwk.Key
	for _, k := range keys {
		public, err := jwk.ParseKey(k.PublicJwk)
		if err != nil {
			return fmt.Errorf("signing key %s: %w", k.Kid, err)
		}
		if err := set.AddKey(public); err != nil {
			return err
		}
		if k.State != "active" || active != nil {
			continue
		}
		scalar, err := wrapper.Unwrap(ctx, k.WrappedPrivate)
		if err != nil {
			return fmt.Errorf("unwrap signing key %s: %w", k.Kid, err)
		}
		priv := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(scalar)}
		priv.PublicKey.Curve = elliptic.P256()
		priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(scalar)
		private, err := jwk.Import(priv)
		if err != nil {
			return err
		}
		if err := private.Set(jwk.KeyIDKey, k.Kid); err != nil {
			return err
		}
		if err := private.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
			return err
		}
		active = private
	}
	if active == nil {
		return errors.New("signer: no active signing key")
	}
	s.mu.Lock()
	s.active, s.public = active, set
	s.mu.Unlock()
	return nil
}

// PublicKeys is the JWKS.
func (s *Signer) PublicKeys() jwk.Set {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.public
}

// Issue is a signed access token for c, valid for ttl. The claims are the
// ones pkg/auth verifies: sub is the user, org and mbr the active
// membership, sid the session.
func (s *Signer) Issue(c auth.Caller, ttl time.Duration) (string, error) {
	now := time.Now()
	subject := c.UserID
	if c.Service != "" {
		subject = "service:" + c.Service
	}
	b := jwt.NewBuilder().
		Issuer(s.issuer).
		Audience([]string{s.audience}).
		Subject(subject).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(ttl)).
		JwtID(uuid.NewString())
	if c.Service != "" {
		b = b.Claim(auth.ClaimService, c.Service)
	}
	if c.OrgID != "" {
		b = b.Claim(auth.ClaimOrg, c.OrgID).Claim(auth.ClaimMembership, c.MembershipID)
	}
	if c.SessionID != "" {
		b = b.Claim(auth.ClaimSession, c.SessionID)
	}
	token, err := b.Build()
	if err != nil {
		return "", err
	}
	s.mu.RLock()
	key := s.active
	s.mu.RUnlock()
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), key))
	return string(signed), err
}

// ServiceTokens is a token source for this service's own calls: it signs
// for itself rather than asking anyone. Deployed, other services get theirs
// from the service-token endpoint; this process is the issuer.
func (s *Signer) ServiceTokens(service string) auth.TokenSource {
	return &selfSigned{signer: s, service: service}
}

type selfSigned struct {
	signer  *Signer
	service string
	mu      sync.Mutex
	token   string
	expires time.Time
}

func (t *selfSigned) Token(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && time.Until(t.expires) > time.Minute {
		return t.token, nil
	}
	raw, err := t.signer.Issue(auth.Caller{Service: t.service}, time.Hour)
	if err != nil {
		return "", err
	}
	t.token, t.expires = raw, time.Now().Add(time.Hour)
	return raw, nil
}
