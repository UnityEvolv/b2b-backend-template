// Package images resizes what people upload: a profile photo to a square,
// any other image to a bounded size, and a thumbnail of either. Decoding is
// bounded, so a crafted image cannot exhaust memory.
package images

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // decode only; output is JPEG or PNG
)

// MaxPixels is the largest image decoded: 40 megapixels, about 160 MB raw.
const MaxPixels = 40_000_000

// ErrTooLarge means the image's dimensions exceed MaxPixels.
var ErrTooLarge = errors.New("images: too many pixels")

// Decode reads an image, refusing one whose dimensions are unreasonable
// before allocating for it.
func Decode(r io.Reader) (image.Image, string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("images: not an image: %w", err)
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width*config.Height > MaxPixels {
		return nil, "", ErrTooLarge
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("images: %w", err)
	}
	return img, format, nil
}

// Fit scales img down so it fits within maxWidth×maxHeight, keeping its
// shape. An image already small enough is returned as is.
func Fit(img image.Image, maxWidth, maxHeight int) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= maxWidth && h <= maxHeight {
		return img
	}
	scale := min(float64(maxWidth)/float64(w), float64(maxHeight)/float64(h))
	out := image.NewRGBA(image.Rect(0, 0, max(1, int(float64(w)*scale)), max(1, int(float64(h)*scale))))
	draw.CatmullRom.Scale(out, out.Bounds(), img, b, draw.Over, nil)
	return out
}

// Square crops img to its centre square and scales it to size×size: a
// profile photo.
func Square(img image.Image, size int) image.Image {
	b := img.Bounds()
	side := min(b.Dx(), b.Dy())
	x0 := b.Min.X + (b.Dx()-side)/2
	y0 := b.Min.Y + (b.Dy()-side)/2
	out := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(out, out.Bounds(), img, image.Rect(x0, y0, x0+side, y0+side), draw.Over, nil)
	return out
}

// Encode writes img as JPEG (quality 85) unless it has transparency, then
// PNG. Returns the bytes and the content type.
func Encode(img image.Image, preferPNG bool) ([]byte, string, error) {
	var buf bytes.Buffer
	if preferPNG {
		if err := png.Encode(&buf, img); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "image/png", nil
	}
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "image/jpeg", nil
}

// Thumbnail is img fitted within 256×256.
func Thumbnail(img image.Image) image.Image { return Fit(img, 256, 256) }
