package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/png" // decode: a frame is PNG or WebP
	"io"
	"net/url"
	"strings"
	"time"

	_ "golang.org/x/image/webp"

	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage/images"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// An org's own frame images (UO-147): uploaded straight to the bucket with a
// pre-signed PUT, then fetched and checked here before the frame that names
// them is created. Nothing unchecked is ever shown.

// framePurpose is what an uploaded frame image is.
//
// TODO(UO-147): move to pkg/storage beside OfficeBackground as
// storage.OfficeFrame. It is declared here only because this story may not
// change pkg/; its own name keeps frame images apart from backgrounds, so
// removing one kind of file never removes the other.
var framePurpose = storage.Purpose{Name: "office-frame", ContentTypes: []string{"image/png", "image/webp"}, MaxBytes: 5 << 20}

const (
	// frameUploadTTL is how long an upload link works.
	frameUploadTTL = 15 * time.Minute
	// frameReadTTL is how long a link to an org frame's image works. An
	// office open longer than this asks for the frame again.
	frameReadTTL = time.Hour
)

// Error codes an image can be refused with. The shape and resolution codes
// are the office background's, so a client handles both alike.
const (
	codeImageShape          = "image.wrong_shape"
	codeImageResolution     = "image.resolution"
	codeImageTooLarge       = "image.too_large"
	codeImageUnsupported    = "image.unsupported"
	codeImageNotTransparent = "image.not_transparent"
	codeImageNotUploaded    = "image.not_uploaded"
	codeImageUnavailable    = "image.storage_unavailable"
)

// FrameFiles is object storage, as frames use it.
type FrameFiles interface {
	UploadURL(ctx context.Context, orgID string, key storage.Key, contentType string, size int64, ttl time.Duration) (*url.URL, error)
	Get(ctx context.Context, orgID string, key storage.Key) (io.ReadCloser, string, error)
	Delete(ctx context.Context, orgID string, key storage.Key) error
	ReadURL(ctx context.Context, orgID string, key storage.Key, ttl time.Duration) (*url.URL, error)
}

// WithFrames is s with storage for the org's own frame images.
func (s *Server) WithFrames(files FrameFiles) *Server {
	s.frames = files
	return s
}

// frameBounds is each canvas shape's exact ratio and resolution bounds: the
// same as a background's (the office service's template images), since a
// frame is drawn over one, edge to edge.
var frameBounds = map[string]struct {
	ratioW, ratioH     int
	minW, minH         int
	maxW, maxH         int
	label, resolutions string
}{
	"landscape": {16, 9, 1920, 1080, 3840, 2160, "16:9", "1920×1080 to 3840×2160"},
	"square":    {1, 1, 1080, 1080, 2160, 2160, "1:1", "1080×1080 to 2160×2160"},
	"portrait":  {3, 4, 1080, 1440, 2160, 2880, "3:4", "1080×1440 to 2160×2880"},
}

// storedImage is one checked upload, as org_frames.images records it.
type storedImage struct {
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
}

type storedVariants struct {
	Light storedImage  `json:"light"`
	Dark  *storedImage `json:"dark,omitempty"`
}

// storedImages is org_frames.images: shape => its light and dark image.
type storedImages map[string]storedVariants

func imagesOf(f store.OrgFrame) (storedImages, error) {
	var out storedImages
	if err := json.Unmarshal(f.Images, &out); err != nil {
		return nil, fmt.Errorf("frame %s: images: %w", f.ID, err)
	}
	return out, nil
}

// imageRefusal is why an upload cannot be a frame image.
type imageRefusal struct {
	code, message string
}

// checkFrameImage fetches the upload named raw and checks it can be the
// shape image of a frame of org: this org's upload of a frame image, a PNG
// or WebP within the size cap, of the shape's exact ratio and resolution,
// and with transparency.
func (s *Server) checkFrameImage(ctx context.Context, org, shape, raw string) (storedImage, *imageRefusal, error) {
	key, err := storage.ParseKey(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(key.OrgID, org) || key.Purpose != framePurpose.Name {
		return storedImage{}, &imageRefusal{codeImageNotUploaded, "Not an upload from this organization's frame upload links."}, nil
	}
	body, _, err := s.frames.Get(ctx, org, key)
	if err != nil {
		return storedImage{}, &imageRefusal{codeImageNotUploaded, "Nothing has been uploaded with this link yet."}, nil
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, framePurpose.MaxBytes+1))
	if err != nil {
		return storedImage{}, nil, fmt.Errorf("read frame image: %w", err)
	}
	if int64(len(data)) > framePurpose.MaxBytes {
		return storedImage{}, &imageRefusal{codeImageTooLarge, fmt.Sprintf("A frame image must be at most %d MB.", framePurpose.MaxBytes>>20)}, nil
	}
	return checkFrameBytes(shape, key.String(), data)
}

// checkFrameBytes is checkFrameImage's work on the bytes themselves.
func checkFrameBytes(shape, key string, data []byte) (storedImage, *imageRefusal, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "webp") {
		return storedImage{}, &imageRefusal{codeImageUnsupported, "A frame image is a PNG or WebP with a transparent middle."}, nil
	}
	b := frameBounds[shape]
	w, h := config.Width, config.Height
	if w*b.ratioH != h*b.ratioW {
		return storedImage{}, &imageRefusal{codeImageShape, fmt.Sprintf("A %s frame needs a %s image; this one is %d×%d.", shape, b.label, w, h)}, nil
	}
	if w < b.minW || h < b.minH || w > b.maxW || h > b.maxH {
		return storedImage{}, &imageRefusal{codeImageResolution, fmt.Sprintf("A %s frame image must be %s; this one is %d×%d.", shape, b.resolutions, w, h)}, nil
	}
	img, _, err := images.Decode(bytes.NewReader(data))
	if errors.Is(err, images.ErrTooLarge) {
		return storedImage{}, &imageRefusal{codeImageResolution, "That image is far larger than any frame needs."}, nil
	}
	if err != nil {
		return storedImage{}, &imageRefusal{codeImageUnsupported, "The image could not be read."}, nil
	}
	if !hasTransparency(img) {
		return storedImage{}, &imageRefusal{codeImageNotTransparent, "A frame image needs transparency, or it would hide the office."}, nil
	}
	return storedImage{Key: key, ContentType: "image/" + format}, nil, nil
}

// hasTransparency is whether any pixel of img is not fully opaque.
func hasTransparency(img image.Image) bool {
	if o, ok := img.(interface{ Opaque() bool }); ok {
		return !o.Opaque()
	}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0xffff {
				return true
			}
		}
	}
	return false
}
