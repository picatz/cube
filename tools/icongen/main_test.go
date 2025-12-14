package main

import (
	"image"
	"testing"
)

func TestRenderIconSizes(t *testing.T) {
	for _, size := range []int{16, 32, 48, 128} {
		img := RenderIcon(size, 4)
		b := img.Bounds()
		if b.Dx() != size || b.Dy() != size {
			t.Fatalf("size %d: got %dx%d", size, b.Dx(), b.Dy())
		}
		if !hasAnyNonTransparentPixel(img) {
			t.Fatalf("size %d: image appears fully transparent", size)
		}
	}
}

func hasAnyNonTransparentPixel(img image.Image) bool {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := img.At(x, y).RGBA()
			if a != 0 {
				return true
			}
		}
	}
	return false
}

