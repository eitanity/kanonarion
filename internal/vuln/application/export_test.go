package application

import "github.com/eitanity/kanonarion/internal/vuln/domain"

// BuildSymbolRefs exposes the unexported buildSymbolRefs helper for testing.
var BuildSymbolRefs = buildSymbolRefs

// ComputeContentHash exposes the unexported content-hash computation for testing.
func (uc *ScanModuleUseCase) ComputeContentHash(r domain.VulnerabilityRecord) (string, error) {
	return uc.computeContentHash(r)
}

// ComputeContentHash exposes the unexported content-hash computation for testing.
func (uc *ScanWalkUseCase) ComputeContentHash(r domain.WalkScanRun) (string, error) {
	return uc.computeContentHash(r)
}
