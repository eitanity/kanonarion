package domain_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/tinygo/domain"
)

const hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAssetName(t *testing.T) {
	for _, tc := range []struct{ version, goos, goarch, want string }{
		{"0.42.0", "linux", "amd64", "tinygo0.42.0.linux-amd64.tar.gz"},
		{"v0.42.0", "darwin", "arm64", "tinygo0.42.0.darwin-arm64.tar.gz"},
		{"0.42.0", "windows", "amd64", "tinygo0.42.0.windows-amd64.zip"},
	} {
		if got := domain.AssetName(tc.version, tc.goos, tc.goarch); got != tc.want {
			t.Errorf("AssetName(%s, %s, %s) = %s, want %s", tc.version, tc.goos, tc.goarch, got, tc.want)
		}
	}
	if got := domain.Tag(" 0.42.0 "); got != "v0.42.0" {
		t.Errorf("Tag = %s", got)
	}
}

func TestOutcome_Kept(t *testing.T) {
	for o, want := range map[domain.Outcome]bool{
		domain.DigestMatched: true, domain.DigestMismatch: true,
		domain.NoDigest: true, domain.AssetAbsent: true, domain.Unavailable: false,
	} {
		if o.Kept() != want {
			t.Errorf("%s.Kept() = %v, want %v", o, !want, want)
		}
	}
}

func TestMeasurement_Validate(t *testing.T) {
	at := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	good := domain.Measurement{Version: "0.42.0", Asset: "a", MeasuredAt: at, Outcome: domain.DigestMatched,
		Manifest: []domain.ManifestEntry{{Path: "x", SHA256: hexA}}}
	if err := good.Validate(); err != nil {
		t.Errorf("a complete measurement is refused: %v", err)
	}
	mismatch := good
	mismatch.Outcome, mismatch.Manifest = domain.DigestMismatch, nil
	if err := mismatch.Validate(); err != nil {
		t.Errorf("a mismatch without a manifest is refused: %v", err)
	}
	for name, m := range map[string]domain.Measurement{
		"zero":                     {},
		"no time":                  {Version: "0.42.0", Asset: "a"},
		"no version":               {Asset: "a", MeasuredAt: at},
		"a match without manifest": {Version: "0.42.0", Asset: "a", MeasuredAt: at, Outcome: domain.DigestMatched},
		"a mismatch with manifest": {Version: "0.42.0", Asset: "a", MeasuredAt: at, Outcome: domain.DigestMismatch, Manifest: good.Manifest},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, m)
		} else if name == "zero" && !errors.Is(err, domain.ErrIncomplete) {
			t.Errorf("zero: err = %v, want ErrIncomplete", err)
		}
	}
}

func TestManifest_RoundTrip(t *testing.T) {
	entries := []domain.ManifestEntry{{Path: "z/b.go", SHA256: hexA}, {Path: "a.S", SHA256: strings.Repeat("b", 64)}}
	text := domain.FormatManifest(entries)
	if want := strings.Repeat("b", 64) + "  a.S\n" + hexA + "  z/b.go\n"; text != want {
		t.Errorf("FormatManifest = %q, want %q", text, want)
	}
	if entries[0].Path != "z/b.go" {
		t.Error("FormatManifest reordered its argument")
	}
	back, err := domain.ParseManifest(text)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	want := []domain.ManifestEntry{{Path: "a.S", SHA256: strings.Repeat("b", 64)}, {Path: "z/b.go", SHA256: hexA}}
	if !reflect.DeepEqual(back, want) {
		t.Errorf("round trip = %+v, want %+v", back, want)
	}
	m := domain.Measurement{Manifest: back}
	if got := m.ManifestMap(); got["z/b.go"] != hexA || len(got) != 2 {
		t.Errorf("ManifestMap = %v", got)
	}
	if (domain.Measurement{}).ManifestMap() != nil {
		t.Error("an empty manifest maps to something")
	}
	if got, err := domain.ParseManifest(""); err != nil || got != nil {
		t.Errorf("ParseManifest(\"\") = %v, %v", got, err)
	}
	for _, bad := range []string{"nohash\n", "abc  path\n", hexA + "  \n"} {
		if _, err := domain.ParseManifest(bad); err == nil {
			t.Errorf("ParseManifest(%q) accepted it", bad)
		}
	}
}

func TestSortManifest_TiesOnPathOrderByDigest(t *testing.T) {
	e := []domain.ManifestEntry{{Path: "a", SHA256: "2"}, {Path: "a", SHA256: "1"}}
	domain.SortManifest(e)
	if e[0].SHA256 != "1" {
		t.Errorf("SortManifest = %+v", e)
	}
}

func TestPublishedSHA256(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"sha256:ABCDEF", "abcdef"},
		{" sha256:abc ", "abc"},
		{"sha512:abc", ""},
		{"", ""},
	} {
		if got := domain.PublishedSHA256(tc.in); got != tc.want {
			t.Errorf("PublishedSHA256(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
