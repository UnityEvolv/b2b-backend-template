package storage_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
)

// A product's purposes, registered the way a product registers its own.
var (
	projectFile = storage.Default.Register(storage.Purpose{Name: "project-file", ContentTypes: []string{"application/pdf", "image/png", "image/jpeg"}, MaxBytes: 1 << 20, Retention: 30 * 24 * time.Hour})
	anyFile     = storage.Default.Register(storage.Purpose{Name: "any-file", MaxBytes: 10 << 20})
)

func TestPurposeValidation(t *testing.T) {
	p := storage.ProfilePhoto
	if err := p.Validate("image/png", 1000); err != nil {
		t.Errorf("png refused: %v", err)
	}
	if err := p.Validate("IMAGE/JPEG; charset=binary", 1000); err != nil {
		t.Errorf("case and parameters should not matter: %v", err)
	}
	for _, c := range []struct {
		ct   string
		size int64
	}{{"text/html", 10}, {"image/svg+xml", 10}, {"image/png", 0}, {"image/png", p.MaxBytes + 1}, {"", 10}} {
		if err := p.Validate(c.ct, c.size); !errors.Is(err, storage.ErrNotAllowed) {
			t.Errorf("%q %d accepted: %v", c.ct, c.size, err)
		}
	}
	// A purpose with no type list takes anything, still bounded by size.
	if err := anyFile.Validate("application/octet-stream", 5); err != nil {
		t.Error(err)
	}
	if err := anyFile.Validate("application/octet-stream", anyFile.MaxBytes+1); err == nil {
		t.Error("oversize attachment accepted")
	}
}

func TestKeysAreOrgFirstAndRoundTrip(t *testing.T) {
	org := uuid.Must(uuid.NewV7()).String()
	k, err := storage.NewKey(org, projectFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k.String(), "orgs/"+org+"/project-file/") {
		t.Errorf("key %q does not lead with the org", k)
	}
	back, err := storage.ParseKey(k.String())
	if err != nil || back != k {
		t.Errorf("round trip: %+v %v", back, err)
	}
	for _, bad := range []string{"", "orgs/" + org, "orgs/not-a-uuid/p/" + k.ID, "other/" + org + "/p/" + k.ID, "orgs/" + org + "//" + k.ID, "orgs/" + org + "/p/../" + k.ID} {
		if _, err := storage.ParseKey(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := storage.NewKey("", storage.ProfilePhoto); err == nil {
		t.Error("key without an org")
	}
}

// The rest needs a real bucket: RustFS from docker compose locally, a RustFS
// container in CI. Without TEST_S3_ENDPOINT they skip.
func client(t *testing.T) *storage.Client {
	t.Helper()
	endpoint := os.Getenv("TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("TEST_S3_ENDPOINT is not set")
	}
	c, err := storage.New(storage.Config{
		Endpoint: endpoint, Bucket: os.Getenv("TEST_S3_BUCKET"),
		AccessKey: os.Getenv("TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("TEST_S3_SECRET_KEY"),
		PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("bucket unreachable: %v", err)
	}
	return c
}

func TestPutGetDelete(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7()).String()
	k, _ := storage.NewKey(org, storage.ProfilePhoto)
	body := []byte("not really a png")
	if err := c.Put(ctx, org, k, "image/png", int64(len(body)), bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	r, ct, err := c.Get(ctx, org, k)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, body) || ct != "image/png" {
		t.Errorf("got %q %q", got, ct)
	}
	if err := c.Delete(ctx, org, k); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Get(ctx, org, k); err == nil {
		t.Error("deleted object still readable")
	}
	// Deleting again is fine: the caller may retry.
	if err := c.Delete(ctx, org, k); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

// Every operation takes the org explicitly and refuses a key from another
// org, before any request is made.
func TestAnotherOrgsKeyIsRefused(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	mine := uuid.Must(uuid.NewV7()).String()
	theirs := uuid.Must(uuid.NewV7()).String()
	k, _ := storage.NewKey(theirs, storage.ProfilePhoto)
	body := []byte("x")
	if err := c.Put(ctx, theirs, k, "image/png", 1, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Delete(ctx, theirs, k) })

	if err := c.Put(ctx, mine, k, "image/png", 1, bytes.NewReader(body)); !errors.Is(err, storage.ErrWrongOrg) {
		t.Errorf("put: %v", err)
	}
	if _, _, err := c.Get(ctx, mine, k); !errors.Is(err, storage.ErrWrongOrg) {
		t.Errorf("get: %v", err)
	}
	if err := c.Delete(ctx, mine, k); !errors.Is(err, storage.ErrWrongOrg) {
		t.Errorf("delete: %v", err)
	}
	if _, err := c.ReadURL(ctx, mine, k, time.Minute); !errors.Is(err, storage.ErrWrongOrg) {
		t.Errorf("read url: %v", err)
	}
	if _, err := c.UploadURL(ctx, mine, k, "image/png", 1, time.Minute); !errors.Is(err, storage.ErrWrongOrg) {
		t.Errorf("upload url: %v", err)
	}
	// And the object is still there for its owner.
	if _, _, err := c.Get(ctx, theirs, k); err != nil {
		t.Errorf("owner lost access: %v", err)
	}
}

// A browser uploads with a signed PUT and reads with a signed GET; both
// expire, and the signed PUT is bound to the declared type and size.
func TestSignedURLs(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7()).String()
	k, _ := storage.NewKey(org, projectFile)
	body := []byte("background bytes")
	t.Cleanup(func() { c.Delete(ctx, org, k) })

	up, err := c.UploadURL(ctx, org, k, "image/jpeg", int64(len(body)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	put := func(ct string, b []byte) int {
		req, _ := http.NewRequest(http.MethodPut, up.String(), bytes.NewReader(b))
		req.Header.Set("Content-Type", ct)
		req.ContentLength = int64(len(b))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := put("text/html", body); code == http.StatusOK {
		t.Error("signed upload accepted a different content type")
	}
	if code := put("image/jpeg", append(body, []byte(" and more")...)); code == http.StatusOK {
		t.Error("signed upload accepted a different size")
	}
	if code := put("image/jpeg", body); code != http.StatusOK {
		t.Fatalf("signed upload refused: %d", code)
	}

	// The bucket is private: a bare URL is refused, a signed one works.
	bare := *up
	bare.RawQuery = ""
	if res, err := http.Get(bare.String()); err != nil {
		t.Fatal(err)
	} else if res.Body.Close(); res.StatusCode == http.StatusOK {
		t.Error("object readable without a signature")
	}
	rd, err := c.ReadURL(ctx, org, k, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(rd.String())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Equal(got, body) {
		t.Errorf("signed read: %d %q", res.StatusCode, got)
	}

	// An expired signature is refused: sign for one second and wait it out.
	short, err := c.ReadURL(ctx, org, k, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if res, err := http.Get(short.String()); err != nil {
		t.Fatal(err)
	} else if res.Body.Close(); res.StatusCode == http.StatusOK {
		t.Error("expired signature honoured")
	}
}

func TestDeleteAllForAnOrg(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7()).String()
	other := uuid.Must(uuid.NewV7()).String()
	put := func(o string, p storage.Purpose) storage.Key {
		k, _ := storage.NewKey(o, p)
		if err := c.Put(ctx, o, k, "image/png", 1, strings.NewReader("x")); err != nil {
			t.Fatal(err)
		}
		return k
	}
	put(org, storage.ProfilePhoto)
	put(org, storage.ProfilePhoto)
	bg := put(org, projectFile)
	theirs := put(other, storage.ProfilePhoto)
	t.Cleanup(func() { c.DeleteAll(ctx, other, "") })

	if n, err := c.DeleteAll(ctx, org, storage.ProfilePhoto.Name); err != nil || n != 2 {
		t.Fatalf("by purpose: %d %v", n, err)
	}
	if _, _, err := c.Get(ctx, org, bg); err != nil {
		t.Error("other purpose was deleted too")
	}
	if n, err := c.DeleteAll(ctx, org, ""); err != nil || n != 1 {
		t.Fatalf("whole org: %d %v", n, err)
	}
	if _, _, err := c.Get(ctx, other, theirs); err != nil {
		t.Error("another org's object was deleted")
	}
	if _, err := c.DeleteAll(ctx, "", ""); err == nil {
		t.Error("delete-all without an org")
	}
}

// The template keeps only its own purposes; a product's is enforced like
// them: its types, its size, and nothing stored under a purpose nobody
// registered.
func TestProductPurposeIsEnforced(t *testing.T) {
	var names []string
	for _, p := range storage.NewRegistry().Purposes() {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "profile-photo,data-export" {
		t.Errorf("template purposes: %v", names)
	}
	if p, ok := storage.Default.Lookup("project-file"); !ok || p.MaxBytes != 1<<20 {
		t.Errorf("lookup: %+v %v", p, ok)
	}
	if err := projectFile.Validate("application/pdf", 1<<20); err != nil {
		t.Errorf("pdf at the ceiling: %v", err)
	}
	if err := projectFile.Validate("application/pdf", 1<<20+1); !errors.Is(err, storage.ErrNotAllowed) {
		t.Errorf("oversize: %v", err)
	}
	if err := projectFile.Validate("text/html", 10); !errors.Is(err, storage.ErrNotAllowed) {
		t.Errorf("html: %v", err)
	}
	org := uuid.Must(uuid.NewV7()).String()
	unregistered := storage.Purpose{Name: "banner-image", MaxBytes: 5 << 20}
	if _, err := storage.NewKey(org, unregistered); !errors.Is(err, storage.ErrUnknownPurpose) {
		t.Errorf("unregistered purpose: %v", err)
	}

	// Retention: a file is past it thirty days on, not before; a purpose
	// with none keeps its files.
	k, err := storage.NewKey(org, projectFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if projectFile.Expired(k, now.Add(29*24*time.Hour)) || !projectFile.Expired(k, now.Add(31*24*time.Hour)) {
		t.Error("retention not applied at thirty days")
	}
	photo, _ := storage.NewKey(org, storage.ProfilePhoto)
	if storage.ProfilePhoto.Expired(photo, now.Add(10*365*24*time.Hour)) || projectFile.Expired(photo, now.Add(365*24*time.Hour)) {
		t.Error("a file with no retention expired")
	}
}

func TestBadPurposesPanic(t *testing.T) {
	for name, p := range map[string]storage.Purpose{
		"empty name":   {MaxBytes: 1},
		"slash":        {Name: "a/b", MaxBytes: 1},
		"upper case":   {Name: "Photos", MaxBytes: 1},
		"no ceiling":   {Name: "things"},
		"negative":     {Name: "things", MaxBytes: 1, Retention: -time.Hour},
		"already here": {Name: "profile-photo", MaxBytes: 1},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			storage.NewRegistry().Register(p)
		}()
	}
}

// The sweep removes an org's files past their purpose's retention and
// nothing else: not younger ones, not another purpose's, not another org's.
func TestDeleteExpired(t *testing.T) {
	c := client(t)
	ctx := context.Background()
	org := uuid.Must(uuid.NewV7()).String()
	other := uuid.Must(uuid.NewV7()).String()
	put := func(o string, p storage.Purpose) storage.Key {
		k, _ := storage.NewKey(o, p)
		if err := c.Put(ctx, o, k, "image/png", 1, strings.NewReader("x")); err != nil {
			t.Fatal(err)
		}
		return k
	}
	put(org, projectFile)
	put(org, projectFile)
	photo := put(org, storage.ProfilePhoto)
	theirs := put(other, projectFile)
	t.Cleanup(func() { c.DeleteAll(ctx, org, ""); c.DeleteAll(ctx, other, "") })

	if n, err := c.DeleteExpired(ctx, org, projectFile, time.Now()); err != nil || n != 0 {
		t.Fatalf("nothing is old yet: %d %v", n, err)
	}
	later := time.Now().Add(31 * 24 * time.Hour)
	if n, err := c.DeleteExpired(ctx, org, projectFile, later); err != nil || n != 2 {
		t.Fatalf("past retention: %d %v", n, err)
	}
	if n, err := c.DeleteExpired(ctx, org, storage.ProfilePhoto, later); err != nil || n != 0 {
		t.Fatalf("no retention: %d %v", n, err)
	}
	if _, _, err := c.Get(ctx, org, photo); err != nil {
		t.Error("another purpose's file was deleted")
	}
	if _, _, err := c.Get(ctx, other, theirs); err != nil {
		t.Error("another org's file was deleted")
	}
}
