// Package ports declares the interfaces the directive application depends on.
// Adapters (modfile parser, sqlite store, audit sink) implement them; the
// application never imports an adapter directly.
package ports

import (
	"context"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/directive/domain"
)

// DirectiveParser parses a project's go.mod (and adjacent go.work, if any)
// into raw, unclassified directives carrying file/line provenance and the
// applied/not-applied flag (go.work precedence resolved). Pure parsing only —
// no classification or policy.
type DirectiveParser interface {
	// ParseProject reads goModPath and any go.work discovered upward from its
	// directory, returning the raw directive set, the project module path and
	// the resolved-version map for exclude classification.
	ParseProject(goModPath string) (domain.ParseResult, error)
}

// DirectiveStore persists and retrieves project directive scan records.
//
// each PutDirectiveRecord call persists a new scan (keyed by
// Record.ID) instead of overwriting the previous one. Scan history powers
// `directives-list`, `directives-show`, and `directives-diff`.
type DirectiveStore interface {
	PutDirectiveRecord(ctx context.Context, r domain.Record) error
	// GetDirectiveRecord returns the latest scan for a project module path.
	// found is false when none is stored (distinct from an error).
	GetDirectiveRecord(ctx context.Context, projectModulePath string) (r domain.Record, found bool, err error)
	// GetScanByID returns a specific scan by its ID. found is false when
	// no scan with that ID exists.
	GetScanByID(ctx context.Context, scanID string) (r domain.Record, found bool, err error)
	// ListScans returns scan summaries for a project module path, newest
	// first. limit 0 means "all"; offset skips that many scans before the
	// limit is applied, so a caller can page rather than re-read from the top.
	ListScans(ctx context.Context, projectModulePath string, limit, offset int) ([]domain.Record, error)
	// CountScans returns how many scans the store holds across every project.
	//
	// ListScans is keyed on a project, so a listing that came back empty can
	// only report that project's own history; it cannot tell a caller who
	// mistyped the path from one whose project has genuinely never been
	// scanned. Answering that needs a count the project does not bound, and
	// re-using the project-keyed read for it would report the whole store empty
	// on one project's evidence.
	CountScans(ctx context.Context) (int, error)
}

// AuditSink appends an audit event to the assurance log. The shared
// JSONL AuditLog satisfies this; the application depends only on
// this narrow port, not on the factstore adapter.
type AuditSink interface {
	RecordEvent(audit.Event) error
}
