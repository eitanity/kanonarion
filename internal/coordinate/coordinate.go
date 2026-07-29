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

// ErrZeroCoordinate is the invariant behind ModuleCoordinate, stated for the
// one value that can hold the type without holding the evidence: the zero
// coordinate, which names no module.
//
// The constructors are meant to be the only ways to obtain a coordinate, and
// for every value they return they are. But Go always permits the zero value —
// coordinate.ModuleCoordinate{} compiles anywhere, and so does var c
// ModuleCoordinate — so unexporting the fields closes the door on a HALF-built
// coordinate while leaving it open for an EMPTY one. Unexporting is what makes
// "a non-zero coordinate is a valid coordinate" true; this is what stops the
// zero one being mistaken for a module.
//
// It lives here rather than in an adapter so every store refuses on the same
// terms, and so callers can match the rule without importing the storage that
// happens to enforce it. A store that accepted it would key a row on the empty
// path at the empty version, which every later read treats as a genuine
// measurement of a module that does not exist; a read that accepted it would
// answer "nothing here" to a question that was never asked about anything.
var ErrZeroCoordinate = errors.New("zero module coordinate: names no module path and no version")

// StdlibPath is the synthetic module path standing for the Go standard
// library. It is not a fetchable module path, so a coordinate bearing it is
// built by NewStdlibCoordinate rather than by the validating constructor.
const StdlibPath = "stdlib"

// ModuleCoordinate uniquely identifies a Go module at a specific version.
//
// Its fields are unexported, so the only ways to obtain a non-zero value are
// the constructors below and the decoders — every one of which either
// validates or documents why it does not. Possessing a non-zero
// ModuleCoordinate is therefore itself the evidence that its path is non-empty
// and its version is semver, LocalVersion, or deliberately absent; no caller
// needs to re-check.
//
// The version is absent in exactly three forms, each with its own constructor
// rather than an undocumented exception: the standard-library sentinel every
// toolchain-tagged stdlib frame collapses onto, the `go mod graph` endpoint
// naming the main module, and a wildcard replace target that names a path and
// no version. Those forms are not fetchable, and code that fetches must reject
// them rather than assume a version it was never given.
//
// The struct stays comparable, so it remains usable as a map key.
type ModuleCoordinate struct {
	path    string
	version string
}

// Path returns the canonical module path, e.g. "github.com/gorilla/mux".
func (c ModuleCoordinate) Path() string { return c.path }

// Version returns the semver or pseudo-version string, e.g. "v1.8.1".
func (c ModuleCoordinate) Version() string { return c.version }

// IsZero reports whether the coordinate is the zero value — the one state the
// constructors cannot prevent, since Go always permits a zero struct. Code
// that accepts a coordinate from a caller and cannot tolerate an unset one
// should test this rather than compare against a fresh literal.
func (c ModuleCoordinate) IsZero() bool { return c.path == "" && c.version == "" }

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
	return ModuleCoordinate{path: path, version: version}, nil
}

// NewLocalCoordinate returns the coordinate for an unpublished local main
// module — path at LocalVersion. It is the constructor for the project walk's
// own target, so the "local is not semver" exception is named once here rather
// than restated at every command that roots a walk at the working tree.
func NewLocalCoordinate(path string) (ModuleCoordinate, error) {
	return NewModuleCoordinate(path, LocalVersion)
}

// NewPathOnlyCoordinate returns the coordinate naming a module path at no
// version. The path must be non-empty; nothing else is checked, because there
// is nothing else there.
//
// It exists so the version-less forms are constructed deliberately rather than
// by bypassing the version rule. A path-only coordinate names a module but
// pins no content: it can be compared, grouped and normalised by path, and it
// must never be fetched or recorded as a measurement of anything.
func NewPathOnlyCoordinate(path string) (ModuleCoordinate, error) {
	if path == "" {
		return ModuleCoordinate{}, errors.New("module path must not be empty")
	}
	return ModuleCoordinate{path: path}, nil
}

// HasVersion reports whether the coordinate pins a version — false for the
// path-only forms NewPathOnlyCoordinate and NewStdlibCoordinate build. Code
// about to fetch, hash or record a coordinate wants this.
func (c ModuleCoordinate) HasVersion() bool { return c.version != "" }

// NewStdlibCoordinate returns the version-less standard-library sentinel
// {StdlibPath, ""} — the key every toolchain-version-tagged stdlib frame
// collapses onto. Use NewStdlibCoordinateAt when the toolchain version is
// known and wanted.
func NewStdlibCoordinate() ModuleCoordinate {
	return ModuleCoordinate{path: StdlibPath}
}

// NewStdlibCoordinateAt returns the standard-library coordinate at a specific
// normalised toolchain version (e.g. "v1.24.5"). The version is validated as
// semver; an empty or malformed one yields an error rather than a coordinate
// that would silently sort and compare as a different module.
func NewStdlibCoordinateAt(version string) (ModuleCoordinate, error) {
	return NewModuleCoordinate(StdlibPath, version)
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
	return c.path + "@" + c.version
}

// IsLocal reports whether the coordinate pins the synthetic LocalVersion —
// the unpublished local main module rooting a project walk. Unlike a published
// semver, a local version does not pin content: the working tree mutates
// between runs, so cached records for a local coordinate are never
// authoritative and must be recomputed fresh on every run.
func (c ModuleCoordinate) IsLocal() bool {
	return c.version == LocalVersion
}

// IsPseudoVersion reports whether the version is a Go pseudo-version
// (e.g. v0.0.0-20210101000000-abcdefabcdef).
func (c ModuleCoordinate) IsPseudoVersion() bool {
	return module.IsPseudoVersion(c.version)
}

// incompatibleSuffix is the build-metadata suffix the go command appends to a
// major version 2+ resolved under the pre-modules rule — a module that reached
// v2 or higher without adopting Go modules, and so has neither a /vN path
// suffix nor a go.mod declaring one.
const incompatibleSuffix = "+incompatible"

// GitTagVersion returns the version as the repository spells it as a tag.
//
// That differs from Version only for a +incompatible coordinate. The suffix is
// the go command's own annotation, not part of the project's version: the tag
// behind github.com/Masterminds/sprig v2.22.0+incompatible is v2.22.0, and no
// ref can ever carry the suffix. Code building a "refs/tags/..." ref must use
// this rather than Version, or ls-remote is asked for a ref that cannot exist
// and the module degrades to checksum-database-only trust. The module proxy
// strips it the same way when it names the tag in its Origin metadata, so both
// resolution paths agree on the ref for the same coordinate.
//
// The rule lives on the coordinate rather than at the call site because the
// coordinate is what knows how its version is spelled; a second consumer that
// builds a ref must not have to rediscover it. This is for ref construction
// ONLY — the recorded coordinate, the content hash and the record identity all
// keep the full version, which is what the build actually resolved.
func (c ModuleCoordinate) GitTagVersion() string {
	return strings.TrimSuffix(c.version, incompatibleSuffix)
}

// ExtractCommitPrefix returns the 12-char commit hash embedded in a
// pseudo-version. Returns an error if the version is not a pseudo-version.
func (c ModuleCoordinate) ExtractCommitPrefix() (string, error) {
	rev, err := module.PseudoVersionRev(c.version)
	if err != nil {
		return "", fmt.Errorf("extracting commit from pseudo-version %s: %w", c.version, err)
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
	// The object form is the legacy encoding, written before MarshalJSON
	// emitted the canonical string. The fields are unexported, so encoding/json
	// cannot set them directly and a shim is required; without it a stored
	// object would decode silently to the zero coordinate. Like the pre-existing
	// object-form decode, this does not re-validate: a record already in the
	// store must round-trip to what was written, and rejecting it here would
	// turn a read of old data into a read failure.
	var obj struct {
		Path    string
		Version string
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("unmarshal ModuleCoordinate: %w", err)
	}
	c.path, c.version = obj.Path, obj.Version
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
