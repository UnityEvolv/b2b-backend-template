package notify

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// WebPush sends to browsers with the Web Push protocol (RFC 8030), our own
// VAPID keys (RFC 8292) and the payload encrypted for the browser (RFC 8291),
// straight to the browser vendor's endpoint.
type WebPush struct {
	key     *ecdsa.PrivateKey
	public  []byte
	subject string
	http    *http.Client
	now     func() time.Time
}

// Subscription is what a browser's PushManager hands over, as JSON.
type Subscription struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

var b64 = base64.RawURLEncoding

// NewWebPush is web push signed with the VAPID private key, a P-256 scalar in
// base64url or standard base64 (as Terraform's random bytes are). subject is
// a mailto: or https: contact for the push services.
func NewWebPush(privateKey, subject string, client *http.Client) (*WebPush, error) {
	d, err := b64.DecodeString(strings.TrimRight(privateKey, "="))
	if err != nil {
		d, err = base64.StdEncoding.DecodeString(privateKey)
	}
	if err != nil || len(d) != 32 {
		return nil, errors.New("webpush: the VAPID private key is 32 bytes of base64url")
	}
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("webpush: %w", err)
	}
	pub := priv.PublicKey().Bytes()
	key := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(d)}
	key.Curve = elliptic.P256()
	key.X = new(big.Int).SetBytes(pub[1:33])
	key.Y = new(big.Int).SetBytes(pub[33:])
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &WebPush{key: key, public: pub, subject: subject, http: client, now: time.Now}, nil
}

// PublicKey is the application server key a browser subscribes with.
func (w *WebPush) PublicKey() string { return b64.EncodeToString(w.public) }

// GenerateVAPID is a fresh key pair: the private scalar and the public key,
// both base64url. For setting up an environment, not for running one.
func GenerateVAPID() (private, public string, err error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return b64.EncodeToString(k.Bytes()), b64.EncodeToString(k.PublicKey().Bytes()), nil
}

// Push encrypts p for the subscription in token and posts it.
func (w *WebPush) Push(ctx context.Context, token string, p Payload) error {
	var sub Subscription
	if err := json.Unmarshal([]byte(token), &sub); err != nil || sub.Endpoint == "" {
		return ErrInvalidToken
	}
	endpoint, err := url.Parse(sub.Endpoint)
	if err != nil || endpoint.Scheme != "https" {
		return ErrInvalidToken
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	body, err := encrypt(sub, plain)
	if err != nil {
		return ErrInvalidToken
	}
	jwt, err := w.vapid(endpoint.Scheme + "://" + endpoint.Host)
	if err != nil {
		return err
	}
	ttl := int(p.TTL(w.now()) / time.Second)
	if ttl <= 0 {
		// Lapsed before it left: a push that expired is not delivered.
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("TTL", strconv.Itoa(ttl))
	req.Header.Set("Urgency", "high")
	if p.Collapse != "" {
		sum := sha256.Sum256([]byte(p.Collapse))
		req.Header.Set("Topic", b64.EncodeToString(sum[:24]))
	}
	req.Header.Set("Authorization", "vapid t="+jwt+", k="+w.PublicKey())
	resp, err := w.http.Do(req)
	if err != nil {
		return ErrTransient
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return ErrInvalidToken
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	case resp.StatusCode >= 500:
		return ErrTransient
	default:
		return fmt.Errorf("webpush: answered %d", resp.StatusCode)
	}
}

// vapid is the ES256 token that says this server sent the push.
func (w *WebPush) vapid(audience string) (string, error) {
	header := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(map[string]any{"aud": audience, "exp": w.now().Add(12 * time.Hour).Unix(), "sub": w.subject})
	if err != nil {
		return "", err
	}
	signing := header + "." + b64.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, w.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64.EncodeToString(sig), nil
}

// encrypt is RFC 8291 over RFC 8188's aes128gcm, one record.
func encrypt(sub Subscription, plain []byte) ([]byte, error) {
	uaPublic, err := b64.DecodeString(strings.TrimRight(sub.Keys.P256dh, "="))
	if err != nil {
		return nil, err
	}
	authSecret, err := b64.DecodeString(strings.TrimRight(sub.Keys.Auth, "="))
	if err != nil || len(authSecret) != 16 {
		return nil, errors.New("webpush: auth secret")
	}
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil {
		return nil, err
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()

	mac := hmac.New(sha256.New, authSecret)
	mac.Write(shared)
	prkKey := mac.Sum(nil)
	info := append(append([]byte("WebPush: info\x00"), uaPublic...), asPublic...)
	ikm := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prkKey, info), ikm); err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	prk := hkdf.Extract(sha256.New, ikm, salt)
	cek := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("Content-Encoding: aes128gcm\x00")), cek); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("Content-Encoding: nonce\x00")), nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The last (and only) record ends with the delimiter 2 and no padding.
	sealed := gcm.Seal(nil, nonce, append(plain, 2), nil)

	var out bytes.Buffer
	out.Write(salt)
	_ = binary.Write(&out, binary.BigEndian, uint32(4096))
	out.WriteByte(byte(len(asPublic)))
	out.Write(asPublic)
	out.Write(sealed)
	return out.Bytes(), nil
}
