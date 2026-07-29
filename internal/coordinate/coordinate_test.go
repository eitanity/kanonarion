package coordinate_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

func TestNewModuleCoordinate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		version string
		wantErr bool
	}{
		{"valid tagged", "github.com/gorilla/mux", "v1.8.1", false},
		{"valid pseudo", "github.com/foo/bar", "v0.0.0-20210101120000-abcdefabcdef", false},
		{"empty path", "", "v1.0.0", true},
		{"empty version", "github.com/foo/bar", "", true},
		{"invalid semver", "github.com/foo/bar", "1.0.0", true},
		{"synthetic local main module", "example.com/project", coordinate.LocalVersion, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := coordinate.NewModuleCoordinate(tt.path, tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewModuleCoordinate(%q, %q) err=%v, wantErr=%v", tt.path, tt.version, err, tt.wantErr)
			}
			if !tt.wantErr {
				if c.Path() != tt.path || c.Version() != tt.version {
					t.Errorf("got %v, want path=%s version=%s", c, tt.path, tt.version)
				}
			}
		})
	}
}

func TestModuleCoordinate_String(t *testing.T) {
	c := coordinatetest.MustNew("github.com/gorilla/mux", "v1.8.1")
	want := "github.com/gorilla/mux@v1.8.1"
	if got := c.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestModuleCoordinate_IsPseudoVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"v1.8.1", false},
		{"v0.0.0-20210101120000-abcdefabcdef", true},
		{"v1.2.3-0.20210101120000-abcdefabcdef", true},
		{"v1.0.0-beta", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			c := coordinatetest.MustNew("example.com/m", tt.version)
			if got := c.IsPseudoVersion(); got != tt.want {
				t.Errorf("IsPseudoVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The +incompatible suffix is the go command's annotation for a pre-modules
// major version; it never appears on a tag, so the ref-building spelling drops
// it while the coordinate itself keeps the version the build resolved.
func TestModuleCoordinate_GitTagVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"v2.22.0+incompatible", "v2.22.0"},
		{"v28.2.2+incompatible", "v28.2.2"},
		{"v1.8.1", "v1.8.1"},
		{"v0.0.0-20210101120000-abcdefabcdef", "v0.0.0-20210101120000-abcdefabcdef"},
		{"v1.0.0-beta", "v1.0.0-beta"},
		{coordinate.LocalVersion, coordinate.LocalVersion},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			c := coordinatetest.MustNew("example.com/m", tt.version)
			if got := c.GitTagVersion(); got != tt.want {
				t.Errorf("GitTagVersion() = %q, want %q", got, tt.want)
			}
			if c.Version() != tt.version {
				t.Errorf("Version() = %q, want the unmodified %q", c.Version(), tt.version)
			}
			if c.String() != "example.com/m@"+tt.version {
				t.Errorf("String() = %q, want the coordinate to keep its full version", c.String())
			}
		})
	}
}

func TestModuleCoordinate_ExtractCommitPrefix(t *testing.T) {
	tests := []struct {
		version    string
		wantPrefix string
		wantErr    bool
	}{
		{"v0.0.0-20210101120000-abcdefabcdef", "abcdefabcdef", false},
		{"v1.2.3-0.20210101120000-deadbeef1234", "deadbeef1234", false},
		{"v1.8.1", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			c := coordinatetest.MustNew("example.com/m", tt.version)
			got, err := c.ExtractCommitPrefix()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExtractCommitPrefix() err=%v, wantErr=%v", err, tt.wantErr)
			}
			if got != tt.wantPrefix {
				t.Errorf("got %q, want %q", got, tt.wantPrefix)
			}
		})
	}
}

func TestModuleCoordinate_UnmarshalJSON_StringForm(t *testing.T) {
	var c coordinate.ModuleCoordinate
	if err := c.UnmarshalJSON([]byte(`"example.com/m@v1.0.0"`)); err != nil {
		t.Fatalf("UnmarshalJSON string form: %v", err)
	}
	if c.Path() != "example.com/m" || c.Version() != "v1.0.0" {
		t.Errorf("got Path=%q Version=%q, want example.com/m v1.0.0", c.Path(), c.Version())
	}
}

func TestModuleCoordinate_UnmarshalJSON_ObjectForm(t *testing.T) {
	var c coordinate.ModuleCoordinate
	if err := c.UnmarshalJSON([]byte(`{"Path":"example.com/m","Version":"v1.0.0"}`)); err != nil {
		t.Fatalf("UnmarshalJSON object form: %v", err)
	}
	if c.Path() != "example.com/m" || c.Version() != "v1.0.0" {
		t.Errorf("got Path=%q Version=%q, want example.com/m v1.0.0", c.Path(), c.Version())
	}
}

func TestModuleCoordinate_UnmarshalJSON_InvalidString(t *testing.T) {
	var c coordinate.ModuleCoordinate
	if err := c.UnmarshalJSON([]byte(`"notavalidcoord"`)); err == nil {
		t.Fatal("expected error for invalid coordinate string")
	}
}

func TestModuleCoordinate_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var c coordinate.ModuleCoordinate
	if err := c.UnmarshalJSON([]byte(`{invalid`)); err == nil {
		t.Fatal("expected error for invalid JSON object")
	}
}
