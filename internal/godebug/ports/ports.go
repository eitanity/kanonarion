// Package ports declares the interfaces the godebug application depends on.
// Adapters (source scanner, sqlite store, audit sink) implement them; the
// application never imports an adapter directly.
package ports

import (
	"context"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/godebug/domain"
)

// GoDebugScanner scans a project's source tree (and any vendored dependency
// trees) for `//go:debug name=value` directives, returning raw, unclassified
// settings with file/line provenance and the applied/not-applied flag. Pure
// scanning only — no classification or policy.
type GoDebugScanner interface {
	// ScanProject reads the module rooted at goModPath and walks its source
	// tree, returning the raw setting set and the project module path. A
	// directive in the main module's main package is Applied; one carried
	// by a vendored dependency is recorded Applied=false (it does not take
	// effect in the current build).
	ScanProject(ctx context.Context, goModPath string) (domain.ParseResult, error)
}

// VendoredModuleLister answers which modules a project's vendor/modules.txt
// names. It is what lets a directive found in a vendored file be attributed to
// the module that published it: modules.txt is the authoritative mapping from a
// directory under vendor/ to a module path, and nothing about the path itself
// carries that answer.
type VendoredModuleLister interface {
	// VendoredModulePaths returns the module paths vendor/modules.txt lists
	// for the project whose go.mod is at goModPath. A project with no
	// vendored tree yields (nil, nil): not vendored is an answer, not a
	// failure — such a project simply has no vendored file to attribute.
	VendoredModulePaths(ctx context.Context, goModPath string) ([]string, error)
}

// GoDebugStore persists and retrieves project godebug records.
type GoDebugStore interface {
	PutGoDebugRecord(ctx context.Context, r domain.Record) error
	// GetGoDebugRecord returns the latest record for a project module path.
	// found is false when none is stored (distinct from an error).
	GetGoDebugRecord(ctx context.Context, projectModulePath string) (r domain.Record, found bool, err error)
}

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this
// narrow port, not on the factstore adapter.
type AuditSink interface {
	RecordEvent(audit.Event) error
}
