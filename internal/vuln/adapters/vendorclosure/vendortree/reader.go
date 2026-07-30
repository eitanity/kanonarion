// Package vendortree satisfies the vuln stage's VendoredClosureReader port from
// the vendor bounded context's filesystem scanner.
//
// The vuln stage needs one fact about a vendored project: which modules the
// tree under vendor/ actually holds. That fact is already produced by the
// vendor context, which owns the modules.txt parser, the nested-module
// attribution rule and the notion of a module being listed but absent. A second
// parser in the vuln stage would be a second answer to the same question, free
// to disagree with the one the vendor command reports — so this is an adapter,
// not a re-implementation.
//
// It deliberately reads only the closure. The vendor context's scanner also
// digests every vendored file against the go.sum-verified zip; that comparison
// is the vendor verifier's job and this port asks nothing of it, so the scanner
// is constructed with no zip source and the file evidence goes unused.
package vendortree

import (
	"context"
	"errors"
	"fmt"

	vendorports "github.com/eitanity/kanonarion/internal/vendortree/ports"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Reader implements ports.VendoredClosureReader over a vendor-context scanner.
type Reader struct {
	scanner vendorports.VendorScanner
}

// New returns a Reader backed by scanner. A nil scanner is not accepted: the
// caller that wires this has a scanner or should not wire the reader at all,
// and a reader that silently reports every project unvendored would turn a
// wiring mistake into a quiet loss of the vendored analysis surface.
func New(scanner vendorports.VendorScanner) *Reader { return &Reader{scanner: scanner} }

// VendoredClosure reads the vendored closure of the project rooted at goModPath.
//
// A project with no vendor/modules.txt yields a zero closure and a nil error:
// the vendor scanner reports that as a sentinel rather than a failure, and the
// vuln stage treats "not vendored" as the ordinary case it must handle, not as
// something that went wrong.
func (r *Reader) VendoredClosure(ctx context.Context, goModPath string) (ports.VendoredClosure, error) {
	if r == nil || r.scanner == nil {
		return ports.VendoredClosure{}, nil
	}
	parsed, err := r.scanner.ScanProject(ctx, goModPath, true)
	if err != nil {
		if errors.Is(err, vendorports.ErrNotVendored) {
			return ports.VendoredClosure{}, nil
		}
		return ports.VendoredClosure{}, fmt.Errorf("reading the vendored closure of %q: %w", goModPath, err)
	}

	listed := make(map[string]string, len(parsed.ModulesTxt))
	for _, m := range parsed.ModulesTxt {
		listed[m.Path] = m.Version
	}
	present := make(map[string]bool, len(parsed.PresentDirs))
	for p, ok := range parsed.PresentDirs {
		present[p] = ok
	}
	// The replacement→original mapping comes from the same parse of the same
	// lines the entries do. Without it a module reached through a replace
	// directive — vendored under its original path, but named by the
	// replacement coordinate in every resolved build list — appears in neither
	// Listed nor Present, and reads as a module the tree does not hold.
	replacedBy := make(map[string]string, len(parsed.Replacements))
	for replacement, original := range parsed.Replacements {
		replacedBy[replacement] = original
	}
	return ports.VendoredClosure{
		Vendored:   true,
		Listed:     listed,
		Present:    present,
		ReplacedBy: replacedBy,
	}, nil
}
