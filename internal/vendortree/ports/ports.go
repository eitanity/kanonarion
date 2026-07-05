// Package ports declares the interfaces the vendor application depends on.
// Adapters (filesystem scanner, sqlite store, audit sink) implement them; the
// application never imports an adapter directly.
package ports

import (
	"context"
	"errors"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// ErrNotVendored is returned by VendorScanner.ScanProject when the project
// has no vendor/ + vendor/modules.txt. It is a distinct sentinel (not a
// finding): the caller decides whether absence of a vendored tree is an
// error for the requested mode.
var ErrNotVendored = errors.New("project is not vendored (no vendor/modules.txt)")

// VendorScanner reads a vendored project from the filesystem: it parses
// vendor/modules.txt, the main go.mod require set and go.sum, enumerates the
// module directories actually present under vendor/, and recomputes each
// vendored module's tree hash. Pure scanning only — no reconciliation or
// policy. vendorOnly asserts the airgapped contract: no proxy contact (OSS
// scope never contacts the proxy, so it is recorded, not enforced by I/O).
type VendorScanner interface {
	ScanProject(goModPath string, vendorOnly bool) (domain.ParseResult, error)
}

// VendorStore persists and retrieves project vendored-closure scan records.
type VendorStore interface {
	PutVendorRecord(ctx context.Context, r domain.Record) error
	// GetVendorRecord returns the latest record for a project module path.
	// found is false when none is stored (distinct from an error).
	GetVendorRecord(ctx context.Context, projectModulePath string) (r domain.Record, found bool, err error)
}

// AuditSink appends an audit event to the assurance log. The shared JSONL
// AuditLog satisfies this; the application depends only on this
// narrow port, not on the factstore adapter.
type AuditSink interface {
	RecordEvent(audit.Event) error
}
