package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// LicenseRecordHasher computes and embeds a content hash into a LicenseRecord.
// The hash covers the canonical JSON serialisation with ContentHash zeroed.
type LicenseRecordHasher struct{}

// canonical structs use sorted JSON-key field order for deterministic output.

type canonicalLicenseRecord struct {
	ContentHash       string                     `json:"content_hash"`
	Coordinate        canonicalCoord             `json:"coordinate"`
	CopyrightStatus   int                        `json:"copyright_status"`
	Ecosystem         string                     `json:"ecosystem"`
	Expression        string                     `json:"expression"`
	ExtractedAt       string                     `json:"extracted_at"`
	FailureDetail     string                     `json:"failure_detail"`
	LicenseFiles      []canonicalFileEntry       `json:"license_files"`
	OverallStatus     int                        `json:"overall_status"`
	PipelineVersion   string                     `json:"pipeline_version"`
	PrimaryConfidence float64                    `json:"primary_confidence"`
	PrimarySPDX       string                     `json:"primary_spdx"`
	Provenance        canonicalProvenanceSummary `json:"provenance"`
	// Role is omitted when empty so records that predate it (every dependency
	// record) keep their stored content hash verifiable.
	Role          string `json:"role,omitempty"`
	SchemaVersion string `json:"schema_version"`
}

type canonicalProvenanceSummary struct {
	Confidence int   `json:"confidence"`
	Signals    []int `json:"signals"`
}

type canonicalCoord struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

type canonicalFileEntry struct {
	AltMatches            []canonicalAltMatch           `json:"alt_matches"`
	Confidence            float64                       `json:"confidence"`
	CopyrightStatements   []canonicalCopyrightStatement `json:"copyright_statements"`
	FileHash              string                        `json:"file_hash"`
	FileSize              int64                         `json:"file_size"`
	IsPerFile             bool                          `json:"is_per_file"`
	IsVendored            bool                          `json:"is_vendored"`
	LowConfidenceCoverage float64                       `json:"low_confidence_coverage"`
	LowConfidenceSPDX     string                        `json:"low_confidence_spdx"`
	Path                  string                        `json:"path"`
	SPDX                  string                        `json:"spdx"`
}

type canonicalCopyrightStatement struct {
	Holders  []string `json:"holders"`
	Source   string   `json:"source"`
	Verbatim string   `json:"verbatim"`
	Years    string   `json:"years"`
}

type canonicalAltMatch struct {
	Confidence float64 `json:"confidence"`
	SPDX       string  `json:"spdx"`
}

// SetContentHash computes the canonical hash of r (with ContentHash zeroed),
// sets r.ContentHash, and returns the updated record.
func (LicenseRecordHasher) SetContentHash(r LicenseRecord) (LicenseRecord, error) {
	r.ContentHash = ""
	data, err := marshalCanonicalLicense(r)
	if err != nil {
		return LicenseRecord{}, fmt.Errorf("marshalling for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	r.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return r, nil
}

// VerifyContentHash re-computes the canonical hash and checks it matches
// r.ContentHash. Returns nil if valid.
func (LicenseRecordHasher) VerifyContentHash(r LicenseRecord) error {
	saved := r.ContentHash
	r.ContentHash = ""
	data, err := marshalCanonicalLicense(r)
	if err != nil {
		return fmt.Errorf("marshalling for verification: %w", err)
	}
	sum := sha256.Sum256(data)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if saved != expected {
		return fmt.Errorf("content hash mismatch: stored %q, computed %q", saved, expected)
	}
	return nil
}

// Marshal returns the canonical JSON bytes for a LicenseRecord, including its
// ContentHash field. Call SetContentHash before this.
func (LicenseRecordHasher) Marshal(r LicenseRecord) ([]byte, error) {
	return marshalCanonicalLicense(r)
}

// Unmarshal parses a LicenseRecord from its canonical JSON representation.
func (LicenseRecordHasher) Unmarshal(data []byte) (LicenseRecord, error) {
	var c canonicalLicenseRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return LicenseRecord{}, fmt.Errorf("unmarshalling canonical license record: %w", err)
	}
	if c.Ecosystem != fetchdomain.EcosystemGo {
		return LicenseRecord{}, fmt.Errorf("%w: got %q, want %q", fetchdomain.ErrUnsupportedEcosystem, c.Ecosystem, fetchdomain.EcosystemGo)
	}

	extractedAt, err := time.Parse(time.RFC3339, c.ExtractedAt)
	if err != nil {
		return LicenseRecord{}, fmt.Errorf("parsing extracted_at %q: %w", c.ExtractedAt, err)
	}

	coord, err := coordinate.NewModuleCoordinate(c.Coordinate.Path, c.Coordinate.Version)
	if err != nil {
		return LicenseRecord{}, fmt.Errorf("parsing coordinate: %w", err)
	}

	files := make([]LicenseFileEntry, len(c.LicenseFiles))
	for i, cf := range c.LicenseFiles {
		alts := make([]AltMatch, len(cf.AltMatches))
		for j, ca := range cf.AltMatches {
			alts[j] = AltMatch{SPDX: ca.SPDX, Confidence: ca.Confidence}
		}
		stmts := make([]CopyrightStatement, len(cf.CopyrightStatements))
		for j, cs := range cf.CopyrightStatements {
			stmts[j] = CopyrightStatement{
				Verbatim: cs.Verbatim,
				Holders:  cs.Holders,
				Years:    cs.Years,
				Source:   cs.Source,
			}
		}
		files[i] = LicenseFileEntry{
			Path:                  cf.Path,
			SPDX:                  cf.SPDX,
			Confidence:            cf.Confidence,
			FileHash:              cf.FileHash,
			FileSize:              cf.FileSize,
			IsVendored:            cf.IsVendored,
			IsPerFile:             cf.IsPerFile,
			AltMatches:            alts,
			CopyrightStatements:   stmts,
			LowConfidenceSPDX:     cf.LowConfidenceSPDX,
			LowConfidenceCoverage: cf.LowConfidenceCoverage,
		}
	}

	signals := make([]ProvenanceSignal, len(c.Provenance.Signals))
	for i, s := range c.Provenance.Signals {
		signals[i] = ProvenanceSignal(s)
	}
	if len(signals) == 0 {
		signals = nil
	}

	rec := LicenseRecord{
		SchemaVersion:     c.SchemaVersion,
		Ecosystem:         c.Ecosystem,
		Coordinate:        coord,
		Role:              c.Role,
		PrimarySPDX:       c.PrimarySPDX,
		Expression:        c.Expression,
		PrimaryConfidence: c.PrimaryConfidence,
		LicenseFiles:      files,
		OverallStatus:     LicenseStatus(c.OverallStatus),
		CopyrightStatus:   CopyrightStatus(c.CopyrightStatus),
		Provenance: ProvenanceSummary{
			Signals:    signals,
			Confidence: ChainOfTitleConfidence(c.Provenance.Confidence),
		},
		FailureDetail:   c.FailureDetail,
		ExtractedAt:     extractedAt.UTC(),
		PipelineVersion: c.PipelineVersion,
		ContentHash:     c.ContentHash,
	}
	rec.EffectiveSet = DeriveEffectiveLicenseSet(rec.LicenseFiles)
	rec.PackageLicenses = DerivePackageLicenses(rec.LicenseFiles)
	return rec, nil
}

func marshalCanonicalLicense(r LicenseRecord) ([]byte, error) {
	// Sort files before hashing to guarantee determinism even if caller
	// didn't call SortFiles.
	files := make([]LicenseFileEntry, len(r.LicenseFiles))
	copy(files, r.LicenseFiles)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	cFiles := make([]canonicalFileEntry, len(files))
	for i, f := range files {
		alts := make([]AltMatch, len(f.AltMatches))
		copy(alts, f.AltMatches)
		sort.Slice(alts, func(a, b int) bool {
			return alts[a].Confidence > alts[b].Confidence
		})
		cAlts := make([]canonicalAltMatch, len(alts))
		for j, a := range alts {
			cAlts[j] = canonicalAltMatch{Confidence: a.Confidence, SPDX: a.SPDX}
		}
		// Sort copyright statements by Verbatim for determinism.
		cstmts := make([]CopyrightStatement, len(f.CopyrightStatements))
		copy(cstmts, f.CopyrightStatements)
		sort.Slice(cstmts, func(a, b int) bool {
			return cstmts[a].Verbatim < cstmts[b].Verbatim
		})
		cCopyright := make([]canonicalCopyrightStatement, len(cstmts))
		for j, s := range cstmts {
			holders := s.Holders
			if holders == nil {
				holders = []string{}
			}
			cCopyright[j] = canonicalCopyrightStatement{
				Holders:  holders,
				Source:   s.Source,
				Verbatim: s.Verbatim,
				Years:    s.Years,
			}
		}
		cFiles[i] = canonicalFileEntry{
			AltMatches:            cAlts,
			Confidence:            f.Confidence,
			CopyrightStatements:   cCopyright,
			FileHash:              f.FileHash,
			FileSize:              f.FileSize,
			IsPerFile:             f.IsPerFile,
			IsVendored:            f.IsVendored,
			LowConfidenceCoverage: f.LowConfidenceCoverage,
			LowConfidenceSPDX:     f.LowConfidenceSPDX,
			Path:                  f.Path,
			SPDX:                  f.SPDX,
		}
	}

	cSignals := make([]int, len(r.Provenance.Signals))
	for i, s := range r.Provenance.Signals {
		cSignals[i] = int(s)
	}
	if len(cSignals) == 0 {
		cSignals = []int{}
	}

	c := canonicalLicenseRecord{
		ContentHash: r.ContentHash,
		Coordinate: canonicalCoord{
			Path:    r.Coordinate.Path,
			Version: r.Coordinate.Version,
		},
		CopyrightStatus:   int(r.CopyrightStatus),
		Ecosystem:         r.Ecosystem,
		Expression:        r.Expression,
		ExtractedAt:       r.ExtractedAt.UTC().Format(time.RFC3339),
		FailureDetail:     r.FailureDetail,
		LicenseFiles:      cFiles,
		OverallStatus:     int(r.OverallStatus),
		PipelineVersion:   r.PipelineVersion,
		PrimaryConfidence: r.PrimaryConfidence,
		PrimarySPDX:       r.PrimarySPDX,
		Provenance: canonicalProvenanceSummary{
			Confidence: int(r.Provenance.Confidence),
			Signals:    cSignals,
		},
		Role:          r.Role,
		SchemaVersion: r.SchemaVersion,
	}

	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshalling canonical license record: %w", err)
	}
	return b, nil
}
