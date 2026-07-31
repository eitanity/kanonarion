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
	ScanProject(ctx context.Context, goModPath string, vendorOnly bool) (domain.ParseResult, error)
}

// VerifiedModuleZipSource yields the published file set of the module zip
// kanonarion holds for a module version. It is the oracle the vendored tree is
// compared against: the zip is the complete published module, so it answers
// both "does vendor/ hold a file this module never published" and "do the bytes
// match".
//
// The lookup is by checksum rather than by coordinate on purpose. go.sum states
// the h1 the project trusts for path@version, and an artefact is addressed by
// what it is, so asking for the artefact with that h1 makes "verified against
// go.sum" a property of the lookup rather than a check someone has to remember
// to perform afterwards. The coordinate is passed only so the adapter can strip
// the "<path>@<version>/" prefix every zip entry carries.
//
// found is false when kanonarion holds no such zip — an absent oracle, which
// the domain surfaces as an unverified module rather than passing off as clean.
type VerifiedModuleZipSource interface {
	// PublishedFiles returns each file the held zip publishes, keyed by its
	// module-relative slash-separated path, mapped to its content digest in
	// the "sha256:<hex>" form the vendored side is measured in.
	PublishedFiles(ctx context.Context, modulePath, version, h1 string) (files map[string]string, found bool, err error)
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
