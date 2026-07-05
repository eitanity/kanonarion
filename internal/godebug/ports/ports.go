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
	ScanProject(goModPath string) (domain.ParseResult, error)
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
