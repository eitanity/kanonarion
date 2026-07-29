package domain

import (
	"fmt"
	"strings"
)

// ModuleHash is the h1 hash of a module zip or go.mod file, as produced by
// golang.org/x/mod/sumdb/dirhash. The algorithm is always "h1" for current
// Go toolchain versions.
//
// Its fields are unexported so that the only ways to hold a non-zero hash are
// NewModuleHash and ParseModuleHash, both of which refuse a half-stated one.
// The exported-field version was bypassable by a struct literal, and a hash
// with an algorithm and no value serialises to a string the parser rejects —
// an unreadable value written by a writer that never had to say what it meant.
// Read it back through Algorithm, Value or String.
type ModuleHash struct {
	// algorithm is the hash scheme, currently always "h1".
	algorithm string
	// value is the base64-encoded hash digest.
	value string
}

// ZeroString is how the zero ModuleHash serialises: String concatenates
// Algorithm, ":" and Value, so an absent hash is persisted as the bare
// separator. It is a real value in every store written before hash absence was
// modelled explicitly, so the parser must be able to read it back.
const ZeroString = ":"

// NewModuleHash returns the hash naming an artefact under algorithm. Both parts
// are required: a hash is a claim about bytes, and half of one names nothing
// that can be looked up. The algorithm may not contain ":", which is the
// separator String writes and ParseModuleHash reads back.
//
// The zero hash is not constructed here. Absence is the zero value, reached by
// declaring one or by parsing ZeroString, and is tested with IsZero.
func NewModuleHash(algorithm, value string) (ModuleHash, error) {
	if algorithm == "" || value == "" {
		return ModuleHash{}, fmt.Errorf("invalid module hash %q:%q: both algorithm and value are required", algorithm, value)
	}
	if strings.Contains(algorithm, ":") {
		return ModuleHash{}, fmt.Errorf("invalid module hash algorithm %q: must not contain %q", algorithm, ":")
	}
	return ModuleHash{algorithm: algorithm, value: value}, nil
}

// ParseModuleHash parses an "h1:base64..." string into a ModuleHash.
//
// ZeroString parses to the zero ModuleHash rather than an error. A record whose
// module zip was never fetched persists its absent hash as ":", and absence must
// be testable with IsZero — the alternative is a string comparison against ":"
// at every call site, which collides every such record of every module into one
// bucket. Only that canonical spelling of absence is accepted: the empty string
// is still an error here, because an absent FIELD is a different thing from a
// recorded absence, and the identity path handles it explicitly.
func ParseModuleHash(s string) (ModuleHash, error) {
	if s == ZeroString {
		return ModuleHash{}, nil
	}
	algorithm, value, ok := strings.Cut(s, ":")
	if !ok {
		return ModuleHash{}, fmt.Errorf("invalid module hash %q: expected algorithm:value", s)
	}
	h, err := NewModuleHash(algorithm, value)
	if err != nil {
		return ModuleHash{}, fmt.Errorf("invalid module hash %q: expected algorithm:value", s)
	}
	return h, nil
}

// Algorithm is the hash scheme, currently always "h1".
func (h ModuleHash) Algorithm() string { return h.algorithm }

// Value is the base64-encoded hash digest.
func (h ModuleHash) Value() string { return h.value }

// String returns the canonical "algorithm:value" representation.
func (h ModuleHash) String() string {
	return h.algorithm + ":" + h.value
}

// Equal reports whether two hashes are equal.
func (h ModuleHash) Equal(other ModuleHash) bool {
	return h.algorithm == other.algorithm && h.value == other.value
}

// IsZero reports whether the hash is the zero value.
func (h ModuleHash) IsZero() bool {
	return h.algorithm == "" && h.value == ""
}
