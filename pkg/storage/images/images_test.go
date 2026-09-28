package images_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/storage/images"
)

func pngOf(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		img.Set(x, 0, color.RGBA{R: 255, A: 255})
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func TestDecodeFitSquareEncode(t *testing.T) {
	img, format, err := images.Decode(bytes.NewReader(pngOf(800, 400)))
	if err != nil || format != "png" {
		t.Fatal(format, err)
	}
	fit := images.Fit(img, 200, 200)
	if b := fit.Bounds(); b.Dx() != 200 || b.Dy() != 100 {
		t.Errorf("fit %v", b)
	}
	if images.Fit(img, 1000, 1000) != img {
		t.Error("small enough image was copied")
	}
	sq := images.Square(img, 64)
	if b := sq.Bounds(); b.Dx() != 64 || b.Dy() != 64 {
		t.Errorf("square %v", b)
	}
	if b := images.Thumbnail(img).Bounds(); b.Dx() != 256 || b.Dy() != 128 {
		t.Errorf("thumbnail %v", b)
	}
	for _, preferPNG := range []bool{false, true} {
		data, ct, err := images.Encode(fit, preferPNG)
		if err != nil || len(data) == 0 {
			t.Fatal(ct, err)
		}
		if _, f, err := images.Decode(bytes.NewReader(data)); err != nil || "image/"+f != ct {
			t.Errorf("encoded as %q decodes as %q: %v", ct, f, err)
		}
	}
}

func TestDecodeRefusesGarbageAndHugeDimensions(t *testing.T) {
	if _, _, err := images.Decode(bytes.NewReader([]byte("<svg/>"))); err == nil {
		t.Error("non-image decoded")
	}
	// A PNG header claiming 100000 by 100000 is refused from its header
	// alone, before 40 GB would be allocated. Width and height live at bytes
	// 16..24 of the IHDR chunk.
	huge := pngOf(1, 1)
	copy(huge[16:24], []byte{0, 1, 0x86, 0xa0, 0, 1, 0x86, 0xa0})
	binary.BigEndian.PutUint32(huge[29:33], crc32.ChecksumIEEE(huge[12:29])) // the chunk CRC covers type and data
	if _, _, err := images.Decode(bytes.NewReader(huge)); !errors.Is(err, images.ErrTooLarge) {
		t.Errorf("huge image: %v", err)
	}
}
