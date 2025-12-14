// Command icongen generates the CUBE extension icon set.
//
// The output is a Rubik's-cube-inspired mark designed to remain legible at small
// sizes (16px) while looking crisp at larger sizes (128px). The generator uses
// simple vector-style geometry rendered at a higher resolution and box-filtered
// down for anti-aliasing.
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type vec struct {
	x float64
	y float64
}

func main() {
	var (
		outDir = flag.String("outdir", "icons", "output directory for icon PNGs")
		sizes  = flag.String("sizes", "16,32,48,128", "comma-separated icon sizes")
		scale  = flag.Int("scale", 4, "supersampling scale factor")
	)
	flag.Parse()

	sz, err := parseSizes(*sizes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid -sizes:", err)
		os.Exit(2)
	}
	if len(sz) == 0 {
		fmt.Fprintln(os.Stderr, "no sizes provided")
		os.Exit(2)
	}
	if *scale < 1 || *scale > 12 {
		fmt.Fprintln(os.Stderr, "scale must be between 1 and 12")
		os.Exit(2)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}

	for _, size := range sz {
		img := RenderIcon(size, *scale)
		name := fmt.Sprintf("icon%d.png", size)
		path := filepath.Join(*outDir, name)
		if err := writePNG(path, img); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
	}
}

func parseSizes(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	seen := map[int]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		if n < 8 || n > 512 {
			return nil, fmt.Errorf("size %d out of range", n)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		return err
	}
	return f.Close()
}

// RenderIcon renders the CUBE mark at the given output size.
func RenderIcon(size int, supersample int) image.Image {
	if supersample < 1 {
		supersample = 1
	}
	hi := size * supersample
	src := image.NewNRGBA(image.Rect(0, 0, hi, hi))

	// Geometry in normalized coordinates (0..1).
	pTop := vec{0.50, 0.12}
	pTR := vec{0.82, 0.28}
	pMid := vec{0.50, 0.44}
	pTL := vec{0.18, 0.28}
	pBR := vec{0.82, 0.70}
	pBot := vec{0.50, 0.86}
	pBL := vec{0.18, 0.70}

	// Colors: keep it "cube" without copying the classic Rubik palette.
	colTop := hexNRGBA("9a86ff", 0xff)
	colLeft := hexNRGBA("ff5c7c", 0xff)
	colRight := hexNRGBA("2dd4bf", 0xff)

	shadow := color.NRGBA{R: 0, G: 0, B: 0, A: 72}
	edge := color.NRGBA{R: 0, G: 0, B: 0, A: 110}
	grid := color.NRGBA{R: 255, G: 255, B: 255, A: 44}

	// Shadow silhouette (slight down/right offset; AA comes from supersampling).
	off := vec{0.0, 0.018}
	fillPoly(src, scalePoly([]vec{pTop, pTR, pBR, pBot, pBL, pTL}, off), shadow)

	// Faces.
	faceTop := []vec{pTop, pTR, pMid, pTL}
	faceLeft := []vec{pTL, pMid, pBot, pBL}
	faceRight := []vec{pMid, pTR, pBR, pBot}
	fillPoly(src, scalePoly(faceLeft, vec{}), colLeft)
	fillPoly(src, scalePoly(faceRight, vec{}), colRight)
	fillPoly(src, scalePoly(faceTop, vec{}), colTop)

	// Grid lines: 3x3 vibe (2 lines each direction).
	drawGrid(src, faceTop, grid, float64(hi)*0.007)
	drawGrid(src, faceLeft, grid, float64(hi)*0.007)
	drawGrid(src, faceRight, grid, float64(hi)*0.007)

	// Outline edges (slightly thicker than grid).
	w := float64(hi) * 0.012
	drawPolyStroke(src, []vec{pTop, pTR, pBR, pBot, pBL, pTL}, edge, w)
	drawLine(src, pTL, pMid, edge, w)
	drawLine(src, pTR, pMid, edge, w)
	drawLine(src, pMid, pBot, edge, w)

	if supersample == 1 {
		return src
	}
	return downsampleBox(src, supersample)
}

func hexNRGBA(hex string, a uint8) color.NRGBA {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return color.NRGBA{A: a}
	}
	r, _ := strconv.ParseUint(hex[0:2], 16, 8)
	g, _ := strconv.ParseUint(hex[2:4], 16, 8)
	b, _ := strconv.ParseUint(hex[4:6], 16, 8)
	return color.NRGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: a}
}

func scalePoly(poly []vec, offset vec) []vec {
	out := make([]vec, len(poly))
	for i, p := range poly {
		out[i] = vec{p.x + offset.x, p.y + offset.y}
	}
	return out
}

func px(img *image.NRGBA, p vec) vec {
	w := float64(img.Bounds().Dx())
	h := float64(img.Bounds().Dy())
	return vec{p.x * (w - 1), p.y * (h - 1)}
}

func fillPoly(img *image.NRGBA, poly []vec, c color.NRGBA) {
	if len(poly) < 3 {
		return
	}
	pts := make([]vec, len(poly))
	for i, p := range poly {
		pts[i] = px(img, p)
	}

	minY := pts[0].y
	maxY := pts[0].y
	for _, p := range pts[1:] {
		if p.y < minY {
			minY = p.y
		}
		if p.y > maxY {
			maxY = p.y
		}
	}

	y0 := int(math.Floor(minY))
	y1 := int(math.Ceil(maxY))
	if y0 < 0 {
		y0 = 0
	}
	if y1 > img.Bounds().Dy()-1 {
		y1 = img.Bounds().Dy() - 1
	}

	for y := y0; y <= y1; y++ {
		scanY := float64(y) + 0.5
		var xs []float64
		for i := 0; i < len(pts); i++ {
			a := pts[i]
			b := pts[(i+1)%len(pts)]
			if a.y == b.y {
				continue
			}
			// Half-open interval to avoid double-counting vertices.
			min := a.y
			max := b.y
			if min > max {
				min, max = max, min
			}
			if scanY < min || scanY >= max {
				continue
			}
			t := (scanY - a.y) / (b.y - a.y)
			xs = append(xs, a.x+t*(b.x-a.x))
		}
		if len(xs) < 2 {
			continue
		}
		sort.Float64s(xs)
		for i := 0; i+1 < len(xs); i += 2 {
			x0 := int(math.Floor(xs[i]))
			x1 := int(math.Ceil(xs[i+1]))
			if x0 < 0 {
				x0 = 0
			}
			if x1 > img.Bounds().Dx()-1 {
				x1 = img.Bounds().Dx() - 1
			}
			for x := x0; x <= x1; x++ {
				blendNRGBA(img, x, y, c)
			}
		}
	}
}

func drawPolyStroke(img *image.NRGBA, poly []vec, c color.NRGBA, width float64) {
	if len(poly) < 2 {
		return
	}
	for i := 0; i < len(poly); i++ {
		drawLine(img, poly[i], poly[(i+1)%len(poly)], c, width)
	}
}

func drawLine(img *image.NRGBA, a, b vec, c color.NRGBA, width float64) {
	p0 := px(img, a)
	p1 := px(img, b)

	minX := math.Min(p0.x, p1.x) - width
	maxX := math.Max(p0.x, p1.x) + width
	minY := math.Min(p0.y, p1.y) - width
	maxY := math.Max(p0.y, p1.y) + width

	x0 := clampInt(int(math.Floor(minX)), 0, img.Bounds().Dx()-1)
	x1 := clampInt(int(math.Ceil(maxX)), 0, img.Bounds().Dx()-1)
	y0 := clampInt(int(math.Floor(minY)), 0, img.Bounds().Dy()-1)
	y1 := clampInt(int(math.Ceil(maxY)), 0, img.Bounds().Dy()-1)

	r2 := (width * 0.5) * (width * 0.5)
	for y := y0; y <= y1; y++ {
		for x := x0; x <= x1; x++ {
			d2 := distPointToSeg2(float64(x)+0.5, float64(y)+0.5, p0.x, p0.y, p1.x, p1.y)
			if d2 <= r2 {
				blendNRGBA(img, x, y, c)
			}
		}
	}
}

func drawGrid(img *image.NRGBA, face []vec, c color.NRGBA, width float64) {
	if len(face) != 4 {
		return
	}
	a, b, d, e := face[0], face[1], face[3], face[2]
	// Lines parallel to a->b
	for _, t := range []float64{1.0 / 3.0, 2.0 / 3.0} {
		p0 := lerp(a, d, t)
		p1 := lerp(b, e, t)
		drawLine(img, p0, p1, c, width)
	}
	// Lines parallel to a->d
	for _, t := range []float64{1.0 / 3.0, 2.0 / 3.0} {
		p0 := lerp(a, b, t)
		p1 := lerp(d, e, t)
		drawLine(img, p0, p1, c, width)
	}
}

func lerp(a, b vec, t float64) vec {
	return vec{a.x + (b.x-a.x)*t, a.y + (b.y-a.y)*t}
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func distPointToSeg2(px, py, x0, y0, x1, y1 float64) float64 {
	vx := x1 - x0
	vy := y1 - y0
	wx := px - x0
	wy := py - y0
	c1 := vx*wx + vy*wy
	if c1 <= 0 {
		dx := px - x0
		dy := py - y0
		return dx*dx + dy*dy
	}
	c2 := vx*vx + vy*vy
	if c2 <= c1 {
		dx := px - x1
		dy := py - y1
		return dx*dx + dy*dy
	}
	t := c1 / c2
	projX := x0 + t*vx
	projY := y0 + t*vy
	dx := px - projX
	dy := py - projY
	return dx*dx + dy*dy
}

func blendNRGBA(img *image.NRGBA, x, y int, src color.NRGBA) {
	if src.A == 0 {
		return
	}
	i := img.PixOffset(x, y)
	dr := float64(img.Pix[i+0]) / 255.0
	dg := float64(img.Pix[i+1]) / 255.0
	db := float64(img.Pix[i+2]) / 255.0
	da := float64(img.Pix[i+3]) / 255.0

	sr := float64(src.R) / 255.0
	sg := float64(src.G) / 255.0
	sb := float64(src.B) / 255.0
	sa := float64(src.A) / 255.0

	outA := sa + da*(1.0-sa)
	if outA <= 0 {
		img.Pix[i+0] = 0
		img.Pix[i+1] = 0
		img.Pix[i+2] = 0
		img.Pix[i+3] = 0
		return
	}

	outR := (sr*sa + dr*da*(1.0-sa)) / outA
	outG := (sg*sa + dg*da*(1.0-sa)) / outA
	outB := (sb*sa + db*da*(1.0-sa)) / outA

	img.Pix[i+0] = uint8(clamp01(outR) * 255.0)
	img.Pix[i+1] = uint8(clamp01(outG) * 255.0)
	img.Pix[i+2] = uint8(clamp01(outB) * 255.0)
	img.Pix[i+3] = uint8(clamp01(outA) * 255.0)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func downsampleBox(src *image.NRGBA, factor int) *image.NRGBA {
	if factor <= 1 {
		dst := image.NewNRGBA(image.Rect(0, 0, src.Bounds().Dx(), src.Bounds().Dy()))
		copy(dst.Pix, src.Pix)
		return dst
	}

	w := src.Bounds().Dx() / factor
	h := src.Bounds().Dy() / factor
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))

	n := float64(factor * factor)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, b, a float64
			for oy := 0; oy < factor; oy++ {
				for ox := 0; ox < factor; ox++ {
					sx := x*factor + ox
					sy := y*factor + oy
					i := src.PixOffset(sx, sy)
					r += float64(src.Pix[i+0])
					g += float64(src.Pix[i+1])
					b += float64(src.Pix[i+2])
					a += float64(src.Pix[i+3])
				}
			}
			di := dst.PixOffset(x, y)
			dst.Pix[di+0] = uint8(math.Round(r / n))
			dst.Pix[di+1] = uint8(math.Round(g / n))
			dst.Pix[di+2] = uint8(math.Round(b / n))
			dst.Pix[di+3] = uint8(math.Round(a / n))
		}
	}
	return dst
}

