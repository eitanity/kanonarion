// Package vendortree adapts the vendor bounded context's scanner onto the SBOM
// context's VendorTreeReader port, so an SBOM can state its coverage of the
// vendored tree without the SBOM context learning how modules.txt is read.
//
// There is deliberately one parser of vendor/modules.txt in the repo. A second
// reading of those lines here would be free to disagree with the vendor
// report's about the same file, and the whole value of a scope statement is
// that the two documents describe the same population.
package vendortree

import (
	"context"
	"errors"
	"fmt"

	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	vendorports "github.com/eitanity/kanonarion/internal/vendortree/ports"
)

// Reader reads a project's vendored module entries through the vendor scanner.
type Reader struct {
	scanner vendorports.VendorScanner
}

// New constructs a Reader over the supplied scanner.
func New(scanner vendorports.VendorScanner) *Reader { return &Reader{scanner: scanner} }

// VendorTree returns the vendor/modules.txt entries for the project at
// goModPath. A project with no vendored tree yields (nil, nil): the SBOM then
// states no vendor scope, because there is no tree to state it over.
//
// The scan runs vendor-only: stating scope must never reach the network, least
// of all in the air-gapped case that makes the statement worth having.
func (r *Reader) VendorTree(ctx context.Context, goModPath string) ([]vendordomain.VendoredModule, error) {
	parsed, err := r.scanner.ScanProject(ctx, goModPath, true)
	if err != nil {
		if errors.Is(err, vendorports.ErrNotVendored) {
			return nil, nil
		}
		return nil, fmt.Errorf("scanning vendored tree at %s: %w", goModPath, err)
	}
	return parsed.ModulesTxt, nil
}
