// Package storage is the single value through which the composition roots reach
// everything the pipeline persists: every record store, the blob store, the
// audit sink, the attestation store and the signer. A backend produces it; the
// roots consume it and never open a database or a blob directory themselves.
package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	callgraphports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	directiveports "github.com/eitanity/kanonarion/internal/directive/ports"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	fipsports "github.com/eitanity/kanonarion/internal/fips/ports"
	godebugports "github.com/eitanity/kanonarion/internal/godebug/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	nativeports "github.com/eitanity/kanonarion/internal/native/ports"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
	stalenessports "github.com/eitanity/kanonarion/internal/staleness/ports"
	stdlibports "github.com/eitanity/kanonarion/internal/stdlib/ports"
	vendorports "github.com/eitanity/kanonarion/internal/vendortree/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// Intent says whether a backend may bring a store into existence.
type Intent int

const (
	// IntentRead never creates anything on disk: an absent store is refused.
	IntentRead Intent = iota
	// IntentCreate may create the store, for a caller about to write into it.
	IntentCreate
)

// Request is what a backend is asked to open.
type Request struct {
	StoreRoot string
	Intent    Intent
	// SetAside is attached by the backend to every store that reports the
	// records it leaves out; nil logs them.
	SetAside recordseal.Reporter
	// Logger is the backend's diagnostics; nil means discard. Kept for the
	// blob-adoption warnings the CLI container's backend will log.
	Logger *slog.Logger
}

// Storage is everything the pipeline persists through, supplied as one value.
// It is a struct, not an interface: a consumer fills fields by name, so adding a
// field later breaks nobody. A nil required field is refused by Validate.
type Storage struct {
	Facts             fetchports.FactStore
	Attestations      fetchports.AttestationStore
	Audit             fetchports.AuditSink
	Blobs             fetchports.BlobStore
	Walks             walkports.WalkStore
	WalkPresence      vulnports.WalkPresence
	Licenses          licenseports.LicenseStore
	Interfaces        ifaceports.InterfaceStore
	CallGraphs        callgraphports.CallGraphStore
	CallGraphOutcomes callgraphports.CallGraphOutcomeReader
	Examples          exampleports.ExampleStore
	Extractions       extractports.ExtractionStore
	Vulnerabilities   vulnports.VulnerabilityStore
	SBOMs             sbomports.SBOMStore
	Directives        directiveports.DirectiveStore
	GoDebug           godebugports.GoDebugStore
	Vendor            vendorports.VendorStore
	FIPS              fipsports.FIPSStore
	Stdlib            stdlibports.Store
	Staleness         stalenessports.Ledger
	Native            nativeports.NativeStore

	// Signer nil means the no-op signer.
	Signer fetchports.Signer
	// Schema nil means the backend reports no schema state.
	Schema SchemaReporter
	// Writable nil means always writable; otherwise it wraps ErrStoreSchemaNewer
	// when it refuses.
	Writable func(context.Context) error
	// Close nil means there is nothing to close.
	Close func() error
}

// SchemaState is what a backend's schema bookkeeping says: how many migrations
// are applied, how many this build expects, and which applied ones it does not
// know.
type SchemaState struct {
	Applied, Expected int
	Unknown           []string
	// Location names the store in a refusal, in the backend's own terms: a
	// file path, a connection URL.
	Location string
}

// SchemaReporter is the optional capability a backend offers when it keeps a
// schema version.
type SchemaReporter interface {
	SchemaState(ctx context.Context) (SchemaState, error)
}

// ErrStoreSchemaNewer reports that the store carries schema migrations this build
// does not know, so it was last written by a newer kanonarion and must not be
// written to by this one.
//
// It is a sentinel rather than a bare message so a caller can route on it: the CLI
// maps it onto its precondition-failure exit code, and an embedding consumer can
// tell "upgrade the binary" apart from a corrupt or unreachable store.
var ErrStoreSchemaNewer = errors.New("store schema is newer than this build supports")

// Validate refuses a value with any required field unset, naming all of them
// at once so a consumer fixes the value in one pass.
func (s *Storage) Validate() error {
	if s == nil {
		return errors.New("storage: no storage value")
	}
	required := []struct {
		name  string
		unset bool
	}{
		{"Facts", s.Facts == nil},
		{"Attestations", s.Attestations == nil},
		{"Audit", s.Audit == nil},
		{"Blobs", s.Blobs == nil},
		{"Walks", s.Walks == nil},
		{"WalkPresence", s.WalkPresence == nil},
		{"Licenses", s.Licenses == nil},
		{"Interfaces", s.Interfaces == nil},
		{"CallGraphs", s.CallGraphs == nil},
		{"CallGraphOutcomes", s.CallGraphOutcomes == nil},
		{"Examples", s.Examples == nil},
		{"Extractions", s.Extractions == nil},
		{"Vulnerabilities", s.Vulnerabilities == nil},
		{"SBOMs", s.SBOMs == nil},
		{"Directives", s.Directives == nil},
		{"GoDebug", s.GoDebug == nil},
		{"Vendor", s.Vendor == nil},
		{"FIPS", s.FIPS == nil},
		{"Stdlib", s.Stdlib == nil},
		{"Staleness", s.Staleness == nil},
		{"Native", s.Native == nil},
	}
	var unset []string
	for _, f := range required {
		if f.unset {
			unset = append(unset, f.name)
		}
	}
	switch len(unset) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("storage: %s is unset", unset[0])
	default:
		return fmt.Errorf("storage: %s are unset", strings.Join(unset, ", "))
	}
}
