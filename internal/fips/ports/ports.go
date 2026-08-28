// Package ports declares the interfaces the fips application depends on.
// Adapters (source scanner, sqlite store, audit sink) implement them; the
// application never imports an adapter directly.
package ports

import (
	"context"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fips/domain"
)

// FIPSScanner scans a project's source tree (and any vendored dependency
// trees) for FIPS-relevant facts: the toolchain string, non-FIPS algorithm
// imports, direct crypto/rand usage, and cgo crypto dependencies. Pure
// scanning only — no classification or policy.
type FIPSScanner interface {
	// ScanProject reads the module rooted at goModPath, returning the raw
	// finding set, the project module path, and the raw toolchain string
	// (from the go.mod toolchain directive). An empty toolchain string is
	// recorded as such — never substituted with a guess.
	ScanProject(ctx context.Context, goModPath string) (domain.ParseResult, error)
}

// VendoredModuleLister answers which modules a project's vendor/modules.txt
// names. It is what lets a finding read from a vendored file be attributed to
// the module that published that file: modules.txt is the authoritative
// mapping from a directory under vendor/ to a module path, and nothing about
// the path itself carries that answer.
type VendoredModuleLister interface {
	// VendoredModulePaths returns the module paths vendor/modules.txt lists
	// for the project whose go.mod is at goModPath. A project with no
	// vendored tree yields (nil, nil): not vendored is an answer, not a
	// failure — such a project simply has no vendored file to attribute.
	VendoredModulePaths(ctx context.Context, goModPath string) ([]string, error)
}

// FIPSStore persists and retrieves project FIPS records.
type FIPSStore interface {
	PutFIPSRecord(ctx context.Context, r domain.Record) error
	// GetFIPSRecord returns the latest record for a project module path
	// under the current pipeline fingerprint. found is false when none is
	// stored (distinct from an error).
	GetFIPSRecord(ctx context.Context, projectModulePath string) (r domain.Record, found bool, err error)
}

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this
// narrow port, not on the factstore adapter.
type AuditSink interface {
	RecordEvent(audit.Event) error
}
