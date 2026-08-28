// Package vendortree adapts the vendor bounded context's scanner onto the fips
// context's VendoredModuleLister port, so a finding in a vendored file can name
// the module that published it without the fips context learning how
// modules.txt is read.
//
// There is deliberately one parser of vendor/modules.txt in the repo. fips
// previously answered this question from the path instead — the first two
// segments of a vendored path, which is a module path for almost none of them —
// and a second reading of those lines here would be free to disagree with the
// vendor report about the same file.
package vendortree

import (
	"context"
	"errors"
	"fmt"

	vendorports "github.com/eitanity/kanonarion/internal/vendortree/ports"
)

// Reader lists a project's vendored module paths through the vendor scanner.
type Reader struct {
	scanner vendorports.VendorScanner
}

// New constructs a Reader over the supplied scanner.
func New(scanner vendorports.VendorScanner) *Reader { return &Reader{scanner: scanner} }

// VendoredModulePaths returns the module paths vendor/modules.txt lists for the
// project at goModPath, in the order listed. A project with no vendored tree
// yields (nil, nil): there is no vendored file to attribute, so absence is the
// answer rather than a failure.
//
// The scan runs vendor-only: attributing a finding must never reach the
// network, least of all in the air-gapped case where the vendored tree IS the
// build.
func (r *Reader) VendoredModulePaths(ctx context.Context, goModPath string) ([]string, error) {
	parsed, err := r.scanner.ScanProject(ctx, goModPath, true)
	if err != nil {
		if errors.Is(err, vendorports.ErrNotVendored) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing the vendored modules at %s: %w", goModPath, err)
	}
	// The left-hand path of each modules.txt entry is the directory `go mod
	// vendor` wrote under vendor/, including for a replaced module — the
	// replacement's source lives under the original's name, so the original is
	// the prefix a vendored file path is matched against.
	out := make([]string, 0, len(parsed.ModulesTxt))
	for _, m := range parsed.ModulesTxt {
		out = append(out, m.Path)
	}
	return out, nil
}
