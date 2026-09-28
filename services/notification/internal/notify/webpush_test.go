package notify

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

// decrypt is what the browser does with an aes128gcm push (RFC 8291).
func decrypt(t *testing.T, ua *ecdh.PrivateKey, auth, body []byte) []byte {
	t.Helper()
	salt := body[:16]
	if rs := binary.BigEndian.Uint32(body[16:20]); rs != 4096 {
		t.Fatalf("record size %d", rs)
	}
	idlen := int(body[20])
	asPublic := body[21 : 21+idlen]
	sealed := body[21+idlen:]
	as, err := ecdh.P256().NewPublicKey(asPublic)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ua.ECDH(as)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, auth)
	mac.Write(shared)
	info := append(append([]byte("WebPush: info\x00"), ua.PublicKey().Bytes()...), asPublic...)
	ikm := make([]byte, 32)
	io.ReadFull(hkdf.Expand(sha256.New, mac.Sum(nil), info), ikm)
	prk := hkdf.Extract(sha256.New, ikm, salt)
	cek, nonce := make([]byte, 16), make([]byte, 12)
	io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("Content-Encoding: aes128gcm\x00")), cek)
	io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("Content-Encoding: nonce\x00")), nonce)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if plain[len(plain)-1] != 2 {
		t.Fatal("no last-record delimiter")
	}
	return plain[:len(plain)-1]
}

func TestWebPush(t *testing.T) {
	private, public, err := GenerateVAPID()
	if err != nil {
		t.Fatal(err)
	}
	ua, _ := ecdh.P256().GenerateKey(rand.Reader)
	auth := make([]byte, 16)
	rand.Read(auth)

	var got struct {
		headers http.Header
		body    []byte
	}
	status := http.StatusCreated
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.headers = r.Header.Clone()
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	defer srv.Close()

	w, err := NewWebPush(private, "mailto:ops@example.org", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if w.PublicKey() != public {
		t.Fatal("the public key is derived from the private one")
	}
	sub := Subscription{Endpoint: srv.URL + "/push/abc"}
	sub.Keys.P256dh = b64.EncodeToString(ua.PublicKey().Bytes())
	sub.Keys.Auth = b64.EncodeToString(auth)
	token, _ := json.Marshal(sub)

	p := Payload{Title: "Ana mentioned you", Body: "in Design", Category: Mention, Link: "/chat/c1", Collapse: "conv:c1", Expires: time.Now().Add(time.Minute)}
	if err := w.Push(context.Background(), string(token), p); err != nil {
		t.Fatal(err)
	}
	var back Payload
	if err := json.Unmarshal(decrypt(t, ua, auth, got.body), &back); err != nil || back.Title != p.Title || back.Link != p.Link {
		t.Fatalf("decrypted %+v %v", back, err)
	}
	if got.headers.Get("Content-Encoding") != "aes128gcm" || got.headers.Get("Topic") == "" {
		t.Errorf("headers %v", got.headers)
	}
	if ttl := got.headers.Get("TTL"); ttl == "" || ttl == "0" || len(ttl) > 2 {
		t.Errorf("the knock's expiry is the time to live: %q", ttl)
	}
	if a := got.headers.Get("Authorization"); !strings.HasPrefix(a, "vapid t=") || !strings.HasSuffix(a, "k="+public) {
		t.Errorf("authorization %q", a)
	}

	// A lapsed push is never sent; a gone subscription is an invalid token.
	got.body = nil
	if err := w.Push(context.Background(), string(token), Payload{Title: "x", Expires: time.Now().Add(-time.Second)}); err != nil || got.body != nil {
		t.Errorf("expired: %v %v", err, got.body)
	}
	status = http.StatusGone
	if err := w.Push(context.Background(), string(token), p); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("gone: %v", err)
	}
	status = http.StatusTooManyRequests
	if err := w.Push(context.Background(), string(token), p); !errors.Is(err, ErrRateLimited) {
		t.Errorf("limited: %v", err)
	}
}
