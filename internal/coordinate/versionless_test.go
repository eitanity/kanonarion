package coordinate_test

import (
	"encoding/json"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestNewPathOnlyCoordinate covers the versionless form and its one rejection.
// A path-only coordinate names a module but pins no content, so the only thing
// left to check is that it names something.
func TestNewPathOnlyCoordinate(t *testing.T) {
	c, err := coordinate.NewPathOnlyCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewPathOnlyCoordinate: %v", err)
	}
	if c.Path() != "example.com/mod" || c.Version() != "" {
		t.Errorf("got %q@%q, want example.com/mod at no version", c.Path(), c.Version())
	}
	if _, err := coordinate.NewPathOnlyCoordinate(""); err == nil {
		t.Error("NewPathOnlyCoordinate(\"\") succeeded; a coordinate naming neither a path nor a version names nothing")
	}
}

// TestHasVersion pins the distinction the fetch path turns on: a versionless
// coordinate can be compared and grouped, but there is no version to fetch at.
func TestHasVersion(t *testing.T) {
	versioned, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	pathOnly, err := coordinate.NewPathOnlyCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewPathOnlyCoordinate: %v", err)
	}
	cases := []struct {
		name string
		c    coordinate.ModuleCoordinate
		want bool
	}{
		{"tagged", versioned, true},
		{"path only", pathOnly, false},
		{"stdlib sentinel", coordinate.NewStdlibCoordinate(), false},
		{"zero", coordinate.ModuleCoordinate{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.HasVersion(); got != tc.want {
				t.Errorf("HasVersion() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestUnmarshalJSON_LegacyObjectForm covers the decode leg that unexporting the
// fields would otherwise have broken silently.
//
// MarshalJSON emits the canonical "path@version" string, but records written
// before it did carry the object form, and encoding/json cannot set unexported
// fields — without the shim such a record would decode to the zero coordinate
// and read back as a measurement of nothing. It deliberately does not
// re-validate: a row already in the store must round-trip to what was written.
func TestUnmarshalJSON_LegacyObjectForm(t *testing.T) {
	var c coordinate.ModuleCoordinate
	if err := json.Unmarshal([]byte(`{"Path":"example.com/mod","Version":"v1.2.3"}`), &c); err != nil {
		t.Fatalf("Unmarshal(object form): %v", err)
	}
	if c.Path() != "example.com/mod" || c.Version() != "v1.2.3" {
		t.Fatalf("object form decoded to %q@%q, want example.com/mod@v1.2.3", c.Path(), c.Version())
	}

	// A stored object the constructor would reject still round-trips, because
	// refusing it here would turn a read of old data into a read failure.
	var legacy coordinate.ModuleCoordinate
	if err := json.Unmarshal([]byte(`{"Path":"example.com/mod","Version":"not-semver"}`), &legacy); err != nil {
		t.Fatalf("Unmarshal(unvalidated object form): %v", err)
	}
	if legacy.Version() != "not-semver" {
		t.Errorf("stored version = %q, want it preserved verbatim", legacy.Version())
	}

	var bad coordinate.ModuleCoordinate
	if err := json.Unmarshal([]byte(`{"Path":42}`), &bad); err == nil {
		t.Error("Unmarshal of a malformed object succeeded; a decode failure must be reported")
	}

	// The string leg reports its own decode failures too. json.Unmarshal is
	// reached with data that opens as a string and is not one, which the outer
	// decoder does not catch because UnmarshalJSON is handed the raw bytes.
	if err := c.UnmarshalJSON([]byte(`"unterminated`)); err == nil {
		t.Error("Unmarshal of a malformed string succeeded; a decode failure must be reported")
	}
}
