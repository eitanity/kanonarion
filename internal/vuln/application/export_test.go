package application

import "github.com/eitanity/kanonarion/internal/vuln/domain"

// BuildSymbolRefs exposes the unexported buildSymbolRefs helper for testing.
var BuildSymbolRefs = buildSymbolRefs

// ComputeContentHash exposes the unexported content-hash computation for testing.
func (uc *ScanModuleUseCase) ComputeContentHash(r domain.VulnerabilityRecord) string {
	return uc.computeContentHash(r)
}
