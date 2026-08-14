package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/domain"
)

func TestParseFamily_PathForMajor(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		major int
		want  map[int]string
	}{
		{
			name:  "standard suffix",
			path:  "github.com/golang-jwt/jwt/v4",
			major: 4,
			want:  map[int]string{5: "github.com/golang-jwt/jwt/v5", 2: "github.com/golang-jwt/jwt/v2"},
		},
		{
			name:  "bare path",
			path:  "github.com/sony/sonyflake",
			major: 0,
			want:  map[int]string{2: "github.com/sony/sonyflake/v2", 1: "github.com/sony/sonyflake"},
		},
		{
			// gopkg.in encodes the major as ".vN"; rebuilding it with "/v" would
			// query gopkg.in/yaml.v2/v3, a path that cannot exist.
			name:  "gopkg.in dot suffix",
			path:  "gopkg.in/yaml.v2",
			major: 2,
			want:  map[int]string{3: "gopkg.in/yaml.v3"},
		},
		{
			// A ".v2" outside gopkg.in is part of the name, not a major suffix.
			name:  "dot suffix off gopkg.in is not a major",
			path:  "example.com/proto.v2",
			major: 0,
			want:  map[int]string{2: "example.com/proto.v2/v2"},
		},
		{
			// "/v1" is not a legal major suffix in Go, so it is part of the name.
			name:  "v1 suffix is not a major suffix",
			path:  "example.com/mod/v1",
			major: 0,
			want:  map[int]string{2: "example.com/mod/v1/v2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fam := domain.ParseFamily(tc.path)
			if fam.Major() != tc.major {
				t.Errorf("Major() = %d, want %d", fam.Major(), tc.major)
			}
			for n, want := range tc.want {
				if got := fam.PathForMajor(n); got != want {
					t.Errorf("PathForMajor(%d) = %q, want %q", n, got, want)
				}
			}
		})
	}
}

func TestProbeStartMajor(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		version string
		want    int
	}{
		{"suffixed path", "github.com/golang-jwt/jwt/v4", "v4.5.1", 5},
		{"bare path at v1", "github.com/sony/sonyflake", "v1.0.0", 2},
		{"bare path at v0", "example.com/mod", "v0.3.0", 2},
		{
			// The case a suffix-derived probe gets wrong: the major is carried by
			// the VERSION, not the path. Starting at /v2 would find nothing (v2
			// was never published under a suffixed path), stop on that gap, and
			// never reach the /v3 that exists.
			name:    "incompatible pin on a bare path starts above the version major",
			path:    "github.com/Masterminds/sprig",
			version: "v2.22.0+incompatible",
			want:    3,
		},
		{"no pin falls back to the path", "github.com/foo/bar/v6", "", 7},
		{"no pin on a bare path probes v2", "github.com/foo/bar", "", 2},
		{"unparseable version falls back to the path", "github.com/foo/bar/v3", "garbage", 4},
		{"gopkg.in", "gopkg.in/yaml.v2", "v2.4.0", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ProbeStartMajor(tc.path, tc.version); got != tc.want {
				t.Errorf("ProbeStartMajor(%q, %q) = %d, want %d", tc.path, tc.version, got, tc.want)
			}
		})
	}
}

// TestProbeStartMajor_NeverBelowPinned is the invariant the ticket names
// explicitly: the probe never looks below the major already in use.
func TestProbeStartMajor_NeverBelowPinned(t *testing.T) {
	for _, path := range []string{
		"github.com/foo/bar", "github.com/foo/bar/v2", "github.com/foo/bar/v9",
		"gopkg.in/yaml.v3",
	} {
		for _, version := range []string{"", "v0.1.0", "v1.0.0", "v4.0.0+incompatible", "v9.9.9"} {
			fam := domain.ParseFamily(path)
			start := domain.ProbeStartMajor(path, version)
			if start <= fam.Major() {
				t.Errorf("%s@%s: start %d is not above the path major %d", path, version, start, fam.Major())
			}
			if start < 2 {
				t.Errorf("%s@%s: start %d is below v2, which is not a suffixed path", path, version, start)
			}
		}
	}
}

func TestRecord_FreshAt(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	rec := domain.Record{LookedUpAt: now.Add(-30 * time.Minute)}

	if !rec.FreshAt(now, time.Hour) {
		t.Error("a 30-minute-old row must be fresh under a 1h TTL")
	}
	if rec.FreshAt(now, 10*time.Minute) {
		t.Error("a 30-minute-old row must be stale under a 10m TTL")
	}
	if rec.FreshAt(now, 0) {
		t.Error("a zero TTL must never serve")
	}
	if (domain.Record{}).FreshAt(now, time.Hour) {
		t.Error("a row with no lookup time must never serve")
	}
}

func TestNewerMajor_Exists(t *testing.T) {
	if (domain.NewerMajor{Probed: false, Path: "example.com/mod/v2"}).Exists() {
		t.Error("an unprobed record must not report a newer major even if a path is set")
	}
	if (domain.NewerMajor{Probed: true}).Exists() {
		t.Error("a probed record with no path is a recorded negative, not an existence")
	}
	if !(domain.NewerMajor{Probed: true, Path: "example.com/mod/v2"}).Exists() {
		t.Error("a probed record with a path must report the newer major")
	}
}

// TestComparePin_PlacesAPinAheadOfLatestAsAhead covers the three shapes a pin
// ahead of @latest actually takes in a real store, measured across 541
// comparable coordinates: a pre-modules +incompatible major above the newest
// version the unsuffixed path serves, a pseudo-version taken after the last
// tag, and a plain tag above the newest one the proxy will answer with.
//
// String equality could only say "different", which the callers read as
// "behind", so each of these named a DOWNGRADE as the upgrade target.
func TestComparePin_PlacesAPinAheadOfLatestAsAhead(t *testing.T) {
	tests := []struct {
		name   string
		pinned string
		latest string
		want   domain.PinPosition
	}{
		{
			name:   "incompatible major above a vN-less latest",
			pinned: "v3.3.4+incompatible",
			latest: "v1.5.5",
			want:   domain.PinAhead,
		},
		{
			name:   "incompatible major above an incompatible latest",
			pinned: "v3.1.2+incompatible",
			latest: "v2.4.0+incompatible",
			want:   domain.PinAhead,
		},
		{
			name:   "pseudo-version taken after the last tag",
			pinned: "v1.0.1-0.20181226105442-5d4384ee4fb2",
			latest: "v1.0.0",
			want:   domain.PinAhead,
		},
		{
			name:   "pseudo-version after the last tag, both incompatible",
			pinned: "v2.0.3-0.20180322193309-b565731e1464+incompatible",
			latest: "v2.0.2+incompatible",
			want:   domain.PinAhead,
		},
		{
			name:   "a plain tag above the latest one published",
			pinned: "v1.1.5",
			latest: "v0.5.5",
			want:   domain.PinAhead,
		},
		{
			name:   "an incompatible major above a pseudo-version latest",
			pinned: "v3.12.0+incompatible",
			latest: "v0.0.0-20231103204413-ee089084f347",
			want:   domain.PinAhead,
		},
		{
			name:   "genuinely behind",
			pinned: "v1.19.0",
			latest: "v1.19.2",
			want:   domain.PinBehind,
		},
		{
			name:   "behind across a digit-count boundary, where string order disagrees",
			pinned: "v1.9.0",
			latest: "v1.10.0",
			want:   domain.PinBehind,
		},
		{
			name:   "level",
			pinned: "v1.6.0",
			latest: "v1.6.0",
			want:   domain.PinLevel,
		},
		{
			name:   "build metadata is not ordering information, so these are level",
			pinned: "v2.0.0+incompatible",
			latest: "v2.0.0",
			want:   domain.PinLevel,
		},
		{
			name:   "an unreadable pin cannot be claimed to be ahead",
			pinned: "not-a-version",
			latest: "v1.0.0",
			want:   domain.PinBehind,
		},
		{
			name:   "an unreadable latest cannot be claimed to be behind or ahead, so the proxy's answer stands",
			pinned: "v1.0.0",
			latest: "whatever-the-proxy-said",
			want:   domain.PinBehind,
		},
		{
			name:   "two identical unreadable strings are still level",
			pinned: "not-a-version",
			latest: "not-a-version",
			want:   domain.PinLevel,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domain.ComparePin(tt.pinned, tt.latest); got != tt.want {
				t.Errorf("ComparePin(%q, %q) = %d, want %d", tt.pinned, tt.latest, got, tt.want)
			}
		})
	}
}
