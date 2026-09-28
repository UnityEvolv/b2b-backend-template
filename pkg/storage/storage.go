// Package storage is the object store every service uses for files people
// upload (UO-80): profile photos, office backgrounds, chat attachments.
//
// It speaks the S3 API, which is what keeps it portable: RustFS on a laptop,
// Google Cloud Storage's S3-compatible endpoint deployed, and any S3-shaped
// store for a customer-hosted data plane. Every object key starts with the
// org, so one org can never reach another's files, and a URL that lets a
// browser upload or read expires.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// Config is where the bucket is and how to reach it, from configuration.
type Config struct {
	// Endpoint is the S3 API, such as http://s3:9000 locally or
	// https://storage.googleapis.com deployed. Empty means AWS itself.
	Endpoint string
	Region   string
	Bucket   string
	// AccessKey and SecretKey are HMAC credentials for the endpoint.
	AccessKey string
	SecretKey string
	// PathStyle addresses the bucket in the path (a local store) rather than the host.
	PathStyle bool
	// PublicEndpoint is what a browser reaches, when it differs from what
	// this process reaches (localhost vs. a container name). Pre-signed URLs
	// are made for it.
	PublicEndpoint string
}

// Client is one bucket.
type Client struct {
	s3        *s3.Client
	presigner *s3.PresignClient
	bucket    string
}

// New connects to the bucket in cfg.
func New(cfg Config) (*Client, error) {
	if cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("storage: bucket and credentials are required")
	}
	region := cfg.Region
	if region == "" {
		region = "auto"
	}
	client := s3.New(s3.Options{
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		UsePathStyle: cfg.PathStyle,
		BaseEndpoint: nonEmpty(cfg.Endpoint),
	})
	// The pre-signer signs for the address a browser will use.
	presignEndpoint := cfg.PublicEndpoint
	if presignEndpoint == "" {
		presignEndpoint = cfg.Endpoint
	}
	presignClient := s3.New(s3.Options{
		Region:       region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		UsePathStyle: cfg.PathStyle,
		BaseEndpoint: nonEmpty(presignEndpoint),
	})
	return &Client{s3: client, presigner: s3.NewPresignClient(presignClient), bucket: cfg.Bucket}, nil
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return aws.String(s)
}

// Purpose is what a file is for. It decides the allowed types and the size
// ceiling, so a story that adds a kind of upload adds a Purpose, not a rule
// somewhere in a handler.
type Purpose struct {
	Name string
	// ContentTypes allowed, exactly. Nothing else is stored.
	ContentTypes []string
	// MaxBytes for one file.
	MaxBytes int64
}

// The purposes every consumer starts from.
var (
	ProfilePhoto     = Purpose{Name: "profile-photo", ContentTypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxBytes: 5 << 20}
	OfficeBackground = Purpose{Name: "office-background", ContentTypes: []string{"image/jpeg", "image/png", "image/webp"}, MaxBytes: 5 << 20}
	ChatAttachment   = Purpose{Name: "chat-attachment", ContentTypes: nil, MaxBytes: 10 << 20} // any type; the plan decides the ceiling
	// DataExport is an org or personal export (UO-184): written by the
	// organization service, never uploaded by a person.
	DataExport = Purpose{Name: "data-export", ContentTypes: []string{"application/zip"}, MaxBytes: 10 << 30}
)

// ErrNotAllowed means the type or size does not fit the purpose.
var ErrNotAllowed = errors.New("storage: not allowed for this purpose")

// Validate checks a proposed upload against p.
func (p Purpose) Validate(contentType string, size int64) error {
	if size <= 0 || size > p.MaxBytes {
		return fmt.Errorf("%w: size %d is not within 1..%d bytes", ErrNotAllowed, size, p.MaxBytes)
	}
	if p.ContentTypes == nil {
		return nil
	}
	base := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	for _, t := range p.ContentTypes {
		if t == base {
			return nil
		}
	}
	return fmt.Errorf("%w: type %q", ErrNotAllowed, contentType)
}

// Key names an object: the org first, always, then the purpose, then an id
// this package chose. A caller never composes one, so a key can never point
// outside its org.
type Key struct {
	OrgID   string
	Purpose string
	ID      string
}

// NewKey is a fresh key for a file of purpose p in org orgID.
func NewKey(orgID string, p Purpose) (Key, error) {
	if uuid.Validate(orgID) != nil {
		return Key{}, errors.New("storage: an org id is required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Key{}, err
	}
	return Key{OrgID: orgID, Purpose: p.Name, ID: id.String()}, nil
}

// String is the object key.
func (k Key) String() string { return path.Join("orgs", k.OrgID, k.Purpose, k.ID) }

// ParseKey is the key behind an object name, refusing anything not of the
// shape this package writes.
func ParseKey(s string) (Key, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 4 || parts[0] != "orgs" || uuid.Validate(parts[1]) != nil || uuid.Validate(parts[3]) != nil || parts[2] == "" {
		return Key{}, fmt.Errorf("storage: %q is not an object key", s)
	}
	return Key{OrgID: parts[1], Purpose: parts[2], ID: parts[3]}, nil
}

// ErrWrongOrg means a key was used for an org it does not belong to.
var ErrWrongOrg = errors.New("storage: object belongs to another org")

func (k Key) check(orgID string) error {
	if !strings.EqualFold(k.OrgID, orgID) {
		return ErrWrongOrg
	}
	return nil
}

// Put stores body under key. The org is passed explicitly and must match the
// key: a service never reaches another org's objects, even by mistake.
func (c *Client) Put(ctx context.Context, orgID string, key Key, contentType string, size int64, body io.Reader) error {
	if err := key.check(orgID); err != nil {
		return err
	}
	_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key.String()),
		Body: body, ContentLength: aws.Int64(size), ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("storage: put: %w", err)
	}
	return nil
}

// Get reads the object under key. The caller closes the body.
func (c *Client) Get(ctx context.Context, orgID string, key Key) (io.ReadCloser, string, error) {
	if err := key.check(orgID); err != nil {
		return nil, "", err
	}
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key.String())})
	if err != nil {
		return nil, "", fmt.Errorf("storage: get: %w", err)
	}
	return out.Body, aws.ToString(out.ContentType), nil
}

// Delete removes the object under key. Removing a user or an office deletes
// their files this way, so nothing is orphaned.
func (c *Client) Delete(ctx context.Context, orgID string, key Key) error {
	if err := key.check(orgID); err != nil {
		return err
	}
	if _, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key.String())}); err != nil {
		return fmt.Errorf("storage: delete: %w", err)
	}
	return nil
}

// DeleteAll removes every object of one purpose in an org, or every object
// in the org when purpose is empty: the org offboarding path.
func (c *Client) DeleteAll(ctx context.Context, orgID, purpose string) (int, error) {
	if uuid.Validate(orgID) != nil {
		return 0, errors.New("storage: an org id is required")
	}
	prefix := path.Join("orgs", orgID, purpose) + "/"
	deleted := 0
	var token *string
	for {
		page, err := c.s3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(c.bucket), Prefix: aws.String(prefix), ContinuationToken: token})
		if err != nil {
			return deleted, fmt.Errorf("storage: list: %w", err)
		}
		for _, o := range page.Contents {
			if _, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(c.bucket), Key: o.Key}); err != nil {
				return deleted, fmt.Errorf("storage: delete: %w", err)
			}
			deleted++
		}
		if !aws.ToBool(page.IsTruncated) {
			return deleted, nil
		}
		token = page.NextContinuationToken
	}
}

// UploadURL is a pre-signed PUT a browser can use once, for ttl, to upload
// exactly this type and size. The bucket never takes an unsigned upload.
func (c *Client) UploadURL(ctx context.Context, orgID string, key Key, contentType string, size int64, ttl time.Duration) (*url.URL, error) {
	if err := key.check(orgID); err != nil {
		return nil, err
	}
	req, err := c.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket), Key: aws.String(key.String()),
		ContentType: aws.String(contentType), ContentLength: aws.Int64(size),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return nil, fmt.Errorf("storage: sign upload: %w", err)
	}
	return url.Parse(req.URL)
}

// ReadURL is a pre-signed GET, good for ttl. Every read by a browser goes
// through one of these; the bucket is never public.
func (c *Client) ReadURL(ctx context.Context, orgID string, key Key, ttl time.Duration) (*url.URL, error) {
	if err := key.check(orgID); err != nil {
		return nil, err
	}
	req, err := c.presigner.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key.String())}, s3.WithPresignExpires(ttl))
	if err != nil {
		return nil, fmt.Errorf("storage: sign read: %w", err)
	}
	return url.Parse(req.URL)
}

// Ping checks the bucket is reachable, for a readiness probe.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(c.bucket)})
	return err
}
