# File upload and object storage

Files people upload (profile photos, office backgrounds, chat attachments)
live in one private bucket behind the S3 API, reached only through
[pkg/storage](../pkg/storage/storage.go). No service holds a bucket client of
its own, and no object is ever public.

```go
store, err := storage.New(storage.Config{
    Endpoint: env.String("S3_ENDPOINT", ""), Region: env.String("S3_REGION", ""),
    Bucket: env.Required("S3_BUCKET"),
    AccessKey: env.Required("S3_ACCESS_KEY"), SecretKey: env.Required("S3_SECRET_KEY"),
    PathStyle: env.Bool("S3_PATH_STYLE", false), PublicEndpoint: env.String("S3_PUBLIC_ENDPOINT", ""),
})

// A handler that accepts an upload: check, name, sign.
if err := storage.ProfilePhoto.Validate(contentType, size); err != nil { /* 400 */ }
key, _ := storage.NewKey(orgID, storage.ProfilePhoto)
uploadURL, _ := store.UploadURL(ctx, orgID, key, contentType, size, 10*time.Minute)
// ... store key.String() on the record; the browser PUTs to uploadURL.

// A handler that shows it.
readURL, _ := store.ReadURL(ctx, orgID, key, time.Hour)
```

## The rules

- **Keys lead with the org**: `orgs/<org_id>/<purpose>/<uuidv7>`. The package
  composes every key; a handler never builds one from strings. Every call
  takes the org explicitly and refuses a key from another org with
  `ErrWrongOrg` before any request leaves the process.
- **A purpose decides what is allowed.** `ProfilePhoto`, `OfficeBackground`
  and `ChatAttachment` each carry their content types and size ceiling.
  `Validate` runs in the handler before anything is signed; the signed
  upload URL is then bound to that exact type and size, so a browser that
  changes either is refused by the bucket. A new kind of upload adds a
  `Purpose`, not a rule in a handler.
- **Every URL expires.** Uploads get minutes, reads get up to an hour. The
  bucket refuses unsigned requests; there is no public read.
- **Deletion follows the record.** Removing a user or an office deletes its
  objects with `Delete`; offboarding an org calls `DeleteAll(orgID, "")`.
  A key is only ever referenced from a row in the owning service's schema.
- **Plan limits are read at the moment of the action**, as everywhere:
  a purpose is the platform ceiling, and the handler tightens it from the
  org's plan before validating.

## Images

[pkg/storage/images](../pkg/storage/images/images.go) decodes JPEG, PNG and
WebP with a 40 megapixel ceiling checked from the header before anything is
allocated, fits an image within bounds, crops to a square, makes a 256 px
thumbnail, and encodes as JPEG or PNG. SVG is stored as uploaded and never
decoded server-side; the office background story sanitises it.

## Environments

| where | store | configuration |
| --- | --- | --- |
| a laptop | RustFS from `docker compose`, console at `localhost:9001/rustfs/console/` | `S3_ENDPOINT=http://s3:9000`, `S3_PUBLIC_ENDPOINT=http://localhost:9000`, `S3_PATH_STYLE=true`, bucket `b2bapp`, keys `b2bapp` / `b2bapp-local` |
| CI | a RustFS container started in the workflow | `TEST_S3_*` in [go.yml](../.github/workflows/go.yml) |
| deployed | a Google Cloud Storage bucket through its S3-compatible endpoint, HMAC key per service | `S3_ENDPOINT=https://storage.googleapis.com`, `S3_REGION=europe-west2`; the key is in the secret manager |

The bucket is private with uniform access; nothing is served from it directly.
Running the storage tests locally:

```sh
TEST_S3_ENDPOINT=http://localhost:9000 TEST_S3_BUCKET=b2bapp \
TEST_S3_ACCESS_KEY=b2bapp TEST_S3_SECRET_KEY=b2bapp-local go test ./pkg/storage/...
```

Without `TEST_S3_ENDPOINT` they skip.
