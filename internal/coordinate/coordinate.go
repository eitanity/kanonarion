package coordinate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// LocalVersion is the synthetic version marking an unpublished local main
// module — the root of a project walk. It is not fetchable and carries no
// transparency-log guarantee; it exists only to anchor a walk record and SBOM
// subject at the local module's own coordinate. semver.IsValid rejects it, so
// NewModuleCoordinate (and therefore the JSON/text round-trip) accepts it as a
// deliberate special case.
const LocalVersion = "local"

// ModuleCoordinate uniquely identifies a Go module at a specific version.
// It is immutable; always construct via NewModuleCoordinate.
type ModuleCoordinate struct {
	// Path is the canonical module path, e.g. "github.com/gorilla/mux".
	Path string
	// Version is the semver or pseudo-version string, e.g. "v1.8.1".
	Version string
}

// NewModuleCoordinate validates and constructs a ModuleCoordinate.
func NewModuleCoordinate(path, version string) (ModuleCoordinate, error) {
	if path == "" {
		return ModuleCoordinate{}, errors.New("module path must not be empty")
	}
	if version == "" {
		return ModuleCoordinate{}, errors.New("module version must not be empty")
	}
	if version != LocalVersion && !semver.IsValid(version) {
		return ModuleCoordinate{}, fmt.Errorf("invalid semver version %q", version)
	}
	return ModuleCoordinate{Path: path, Version: version}, nil
}

// ParseModuleCoordinate parses a "path@version" string.
func ParseModuleCoordinate(s string) (ModuleCoordinate, error) {
	path, version, ok := strings.Cut(s, "@")
	if !ok {
		return ModuleCoordinate{}, fmt.Errorf("invalid module coordinate %q: missing @", s)
	}
	return NewModuleCoordinate(path, version)
}

// String returns the canonical "path@version" representation.
func (c ModuleCoordinate) String() string {
	return c.Path + "@" + c.Version
}

// IsLocal reports whether the coordinate pins the synthetic LocalVersion —
// the unpublished local main module rooting a project walk. Unlike a published
// semver, a local version does not pin content: the working tree mutates
// between runs, so cached records for a local coordinate are never
// authoritative and must be recomputed fresh on every run.
func (c ModuleCoordinate) IsLocal() bool {
	return c.Version == LocalVersion
}

// IsPseudoVersion reports whether the version is a Go pseudo-version
// (e.g. v0.0.0-20210101000000-abcdefabcdef).
func (c ModuleCoordinate) IsPseudoVersion() bool {
	return module.IsPseudoVersion(c.Version)
}

// ExtractCommitPrefix returns the 12-char commit hash embedded in a
// pseudo-version. Returns an error if the version is not a pseudo-version.
func (c ModuleCoordinate) ExtractCommitPrefix() (string, error) {
	rev, err := module.PseudoVersionRev(c.Version)
	if err != nil {
		return "", fmt.Errorf("extracting commit from pseudo-version %s: %w", c.Version, err)
	}
	return rev, nil
}

// MarshalJSON implements json.Marshaler.
// It emits the canonical "path@version" string form so that JSON output is
// consistent with MarshalText and easy to filter with jq.
func (c ModuleCoordinate) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(c.String())
	if err != nil {
		return nil, fmt.Errorf("marshal ModuleCoordinate: %w", err)
	}
	return b, nil
}

// UnmarshalJSON implements json.Unmarshaler.
// It accepts both a JSON string ("path@version") and a JSON object
// ({"Path":"...","Version":"..."}) so that map keys serialised via
// MarshalText round-trip correctly.
func (c *ModuleCoordinate) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("unmarshal ModuleCoordinate: %w", err)
		}
		return c.UnmarshalText([]byte(s))
	}
	type Alias ModuleCoordinate
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("unmarshal ModuleCoordinate: %w", err)
	}
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (c ModuleCoordinate) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (c *ModuleCoordinate) UnmarshalText(text []byte) error {
	coord, err := ParseModuleCoordinate(string(text))
	if err != nil {
		return err
	}
	*c = coord
	return nil
}
