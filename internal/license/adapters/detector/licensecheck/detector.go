// Package licensecheck wraps github.com/google/licensecheck as a
// ports.LicenseDetector. It is the default license detector for the license
// extraction pipeline.
package licensecheck

import (
	"context"
	"fmt"
	"runtime/debug"
	"sort"

	"github.com/eitanity/kanonarion/internal/license/ports"
	"github.com/google/licensecheck"
)

// minCoveragePercent is the minimum percentage of the file's text that must
// be covered by license matches for any detection to be reported. Below this
// threshold the content is considered non-license text.
const minCoveragePercent = 20.0

// Detector implements ports.LicenseDetector using the google/licensecheck
// built-in license corpus.
type Detector struct{}

// New returns a Detector ready for use.
func New() *Detector { return &Detector{} }

// Detect scans content for known license text and returns the best match.
// Returns an empty LicenseMatch (zero SPDX) when no license is identified.
// The context is checked before returning but licensecheck itself is
// synchronous and does not support mid-scan cancellation.
func (Detector) Detect(ctx context.Context, content []byte) (ports.LicenseMatch, error) {
	if err := ctx.Err(); err != nil {
		return ports.LicenseMatch{}, fmt.Errorf("license detection cancelled: %w", err)
	}

	cov := licensecheck.Scan(content)

	// Collect non-URL matches; URL references are navigational, not substantive.
	var spdxMatches []licensecheck.Match
	for _, m := range cov.Match {
		if !m.IsURL && m.ID != "" {
			spdxMatches = append(spdxMatches, m)
		}
	}
	if len(spdxMatches) == 0 {
		return ports.LicenseMatch{}, nil
	}

	// Sort by span (largest first) as a proxy for which license is the primary
	// subject of the file.
	sort.Slice(spdxMatches, func(i, j int) bool {
		spanI := spdxMatches[i].End - spdxMatches[i].Start
		spanJ := spdxMatches[j].End - spdxMatches[j].Start
		if spanI != spanJ {
			return spanI > spanJ
		}
		return spdxMatches[i].ID < spdxMatches[j].ID // stable tie-break
	})

	// Below the substantive coverage floor a known licence may still have been
	// recognised from a small distinctive fragment — e.g. a truncated AGPL-3.0
	// text where only the "how to apply" appendix matches. Do not classify
	// (SPDX stays empty, leaving the status Unclassified), but report the
	// fragment so callers can surface it as a low-confidence caveat rather than
	// silent absence.
	if cov.Percent < minCoveragePercent {
		return ports.LicenseMatch{
			LowConfidenceSPDX:     spdxMatches[0].ID,
			LowConfidenceCoverage: cov.Percent / 100.0,
		}, nil
	}

	primary := ports.LicenseMatch{
		SPDX:       spdxMatches[0].ID,
		Confidence: cov.Percent / 100.0,
	}

	if len(spdxMatches) > 1 {
		// Deduplicate: report each distinct SPDX identifier once.
		seen := map[string]bool{primary.SPDX: true}
		for _, m := range spdxMatches[1:] {
			if seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			primary.AltMatches = append(primary.AltMatches, ports.LicenseMatch{
				SPDX:       m.ID,
				Confidence: cov.Percent / 100.0,
			})
		}
	}

	return primary, nil
}

// DetectorMetadata returns metadata identifying this detector.
func (Detector) DetectorMetadata() ports.DetectorMetadata {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/google/licensecheck" {
				version = dep.Version
				break
			}
		}
	}

	return ports.DetectorMetadata{
		Name:           "licensecheck",
		Version:        version,
		DataSetVersion: "builtin",
	}
}

// Ensure Detector implements ports.LicenseDetector at compile time.
var _ ports.LicenseDetector = Detector{}
