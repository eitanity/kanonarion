package domain

import (
	"fmt"
	"strings"
)

// ModuleHash is the h1 hash of a module zip or go.mod file, as produced by
// golang.org/x/mod/sumdb/dirhash. The algorithm is always "h1" for current
// Go toolchain versions.
type ModuleHash struct {
	// Algorithm is the hash scheme, currently always "h1".
	Algorithm string
	// Value is the base64-encoded hash digest.
	Value string
}

// ParseModuleHash parses an "h1:base64..." string into a ModuleHash.
func ParseModuleHash(s string) (ModuleHash, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ModuleHash{}, fmt.Errorf("invalid module hash %q: expected algorithm:value", s)
	}
	return ModuleHash{Algorithm: parts[0], Value: parts[1]}, nil
}

// String returns the canonical "algorithm:value" representation.
func (h ModuleHash) String() string {
	return h.Algorithm + ":" + h.Value
}

// Equal reports whether two hashes are equal.
func (h ModuleHash) Equal(other ModuleHash) bool {
	return h.Algorithm == other.Algorithm && h.Value == other.Value
}

// IsZero reports whether the hash is the zero value.
func (h ModuleHash) IsZero() bool {
	return h.Algorithm == "" && h.Value == ""
}
