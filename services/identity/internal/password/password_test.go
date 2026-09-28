package password_test

import (
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/services/identity/internal/password"
)

func TestHashAndVerify(t *testing.T) {
	h, err := password.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Errorf("encoded form: %s", h)
	}
	if ok, err := password.Verify(h, "correct horse battery staple"); err != nil || !ok {
		t.Errorf("the right password: %v %v", ok, err)
	}
	if ok, err := password.Verify(h, "correct horse battery stapler"); err != nil || ok {
		t.Errorf("a wrong password: %v %v", ok, err)
	}
	// A second hash of the same password differs (fresh salt) and still checks.
	h2, _ := password.Hash("correct horse battery staple")
	if h2 == h {
		t.Error("two hashes are the same: no salt")
	}
	if ok, _ := password.Verify(h2, "correct horse battery staple"); !ok {
		t.Error("second hash does not check")
	}
	// A truncated hash, and other things that are not ours, are errors.
	for _, bad := range []string{"", "plain", "$bcrypt$x$y$z$w", "$argon2id$v=18$m=1,t=1,p=1$YQ$YQ",
		"$argon2id$v=19$m=8192,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$", "$argon2id$v=19$m=8192,t=0,p=1$c2FsdHNhbHRzYWx0c2FsdA$c2FsdHNhbHRzYWx0c2FsdA"} {
		if _, err := password.Verify(bad, "x"); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	if ok, _ := password.Verify(password.Dummy, "nobody-has-this-password"); !ok {
		t.Error("the dummy hash does not check its own password")
	}
}

func TestPolicy(t *testing.T) {
	for _, c := range []struct {
		candidate, email string
		ok               bool
	}{
		{"short", "a@b.c", false},
		{"twelve chars", "a@b.c", true},
		{"ada@example.com", "ada@example.com", false},
		{"ADA@example.com ", "ada@example.com", false},
		{strings.Repeat("x", 201), "a@b.c", false},
		{"            ", "a@b.c", false},
	} {
		err := password.Check(c.candidate, c.email)
		if (err == nil) != c.ok {
			t.Errorf("%q: %v", c.candidate, err)
		}
	}
}
