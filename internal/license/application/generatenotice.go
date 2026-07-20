package application

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
)

// GenerateNoticeUseCase assembles a THIRD-PARTY-LICENSES attribution document
// from stored license records and verbatim license file content.
type GenerateNoticeUseCase struct {
	licenses                  licenseports.LicenseStore
	facts                     fetchports.FactStore
	blobs                     fetchports.BlobStore
	pipelineVersion           string
	fetchPipelineVersion      string
	localFetchPipelineVersion string
}

// NewGenerateNoticeUseCase constructs a GenerateNoticeUseCase.
func NewGenerateNoticeUseCase(
	licenses licenseports.LicenseStore,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	pipelineVersion string,
	fetchPipelineVersion string,
) *GenerateNoticeUseCase {
	return &GenerateNoticeUseCase{
		licenses:             licenses,
		facts:                facts,
		blobs:                blobs,
		pipelineVersion:      pipelineVersion,
		fetchPipelineVersion: fetchPipelineVersion,
	}
}

// WithLocalFetchPipelineVersion sets the pipeline version under which locally
// ingested modules (local-replace targets and the project-walk root) persist
// their FactRecord, enabling notice generation to read their license texts.
func (uc *GenerateNoticeUseCase) WithLocalFetchPipelineVersion(v string) *GenerateNoticeUseCase {
	uc.localFetchPipelineVersion = v
	return uc
}

// NoticeRequest is the input to Generate.
type NoticeRequest struct {
	Coordinates []coordinate.ModuleCoordinate
}

// NoticeResult is the output of Generate.
type NoticeResult struct {
	Entries     []licensedomain.NoticeEntry // sorted by module path
	ReviewItems []licensedomain.ReviewItem  // modules needing human review before inclusion
}

// Generate builds notice entries for each coordinate. Modules with
// Ambiguous/Multiple license status, missing copyright, or missing records are
// added to ReviewItems rather than Entries. Callers must treat a non-empty
// ReviewItems as requiring human intervention before the document is published.
func (uc *GenerateNoticeUseCase) Generate(ctx context.Context, req NoticeRequest) (NoticeResult, error) {
	var result NoticeResult
	for _, coord := range req.Coordinates {
		entry, review, err := uc.processModule(ctx, coord)
		if err != nil {
			return NoticeResult{}, fmt.Errorf("processing %s: %w", coord, err)
		}
		if review != nil {
			result.ReviewItems = append(result.ReviewItems, *review)
			continue
		}
		result.Entries = append(result.Entries, *entry)
	}
	licensedomain.SortNoticeEntries(result.Entries)
	return result, nil
}

func (uc *GenerateNoticeUseCase) processModule(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (*licensedomain.NoticeEntry, *licensedomain.ReviewItem, error) {
	rec, found, err := uc.licenses.GetLicenseRecord(ctx, coord, uc.pipelineVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("getting license record: %w", err)
	}
	if !found {
		return nil, &licensedomain.ReviewItem{
			Coordinate: coord,
			Reason:     "no license record: run 'kanonarion license' first",
		}, nil
	}

	// Statuses that block automated NOTICE generation per.
	// LicenseStatusMultiple is not blocked: verbatim inclusion of all root-level
	// license texts satisfies attribution for both single-file compound licenses
	// (e.g. yaml.v3 "MIT and Apache") and multi-file distributions.
	switch rec.OverallStatus {
	case licensedomain.LicenceStatusAmbiguous:
		return nil, &licensedomain.ReviewItem{Coordinate: coord, Reason: ambiguousReason(rec)}, nil
	case licensedomain.LicenseStatusNone:
		return nil, &licensedomain.ReviewItem{Coordinate: coord, Reason: "no license found"}, nil
	case licensedomain.LicenseStatusExtractionFailed:
		detail := rec.FailureDetail
		if detail == "" {
			detail = "unknown failure"
		}
		return nil, &licensedomain.ReviewItem{
			Coordinate: coord,
			Reason:     "license extraction failed: " + detail,
		}, nil
	}

	// Copyright must be present.
	if rec.CopyrightStatus != licensedomain.CopyrightStatusFound {
		return nil, &licensedomain.ReviewItem{
			Coordinate: coord,
			Reason:     "copyright not found (status: " + rec.CopyrightStatus.String() + ")",
		}, nil
	}

	// Read verbatim license text from the module blob.
	licenseTexts, embeddedComps, err := uc.readLicenseTexts(ctx, coord, rec)
	if err != nil {
		return nil, nil, fmt.Errorf("reading license texts for %s: %w", coord, err)
	}

	// Collect deduped, sorted copyright statements from root-level non-vendored files.
	seen := make(map[string]struct{})
	var copyrights []string
	for _, f := range rec.LicenseFiles {
		if f.IsVendored || !isRootLevel(f.Path) {
			continue
		}
		for _, s := range f.CopyrightStatements {
			if _, dup := seen[s.Verbatim]; dup {
				continue
			}
			seen[s.Verbatim] = struct{}{}
			copyrights = append(copyrights, s.Verbatim)
		}
	}
	sort.Strings(copyrights)

	return &licensedomain.NoticeEntry{
		Coordinate:         coord,
		SPDX:               rec.PrimarySPDX,
		LicenseTexts:       licenseTexts,
		Copyrights:         copyrights,
		EmbeddedComponents: embeddedComps,
	}, nil, nil
}

func (uc *GenerateNoticeUseCase) readLicenseTexts(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
	rec licensedomain.LicenseRecord,
) ([]licensedomain.NoticeLicenseFile, []licensedomain.NoticeEmbeddedComponent, error) {
	factRecord, err := uc.noticeRequireFetchRecord(ctx, coord)
	if err != nil {
		return nil, nil, err
	}

	handle := fetchports.BlobHandle(factRecord.ContentLocation)
	r, err := uc.blobs.Get(ctx, handle)
	if err != nil {
		return nil, nil, fmt.Errorf("opening blob: %w", err)
	}
	defer func() { _ = r.Close() }()

	zipData, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("reading blob: %w", err)
	}

	archive, err := ziparchive.New(zipData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing zip: %w", err)
	}

	zipPrefix := coord.Path + "@" + coord.Version + "/"

	// Root-level non-vendored license texts.
	var texts []licensedomain.NoticeLicenseFile
	for _, f := range rec.LicenseFiles {
		if f.IsVendored || !isRootLevel(f.Path) {
			continue
		}
		content, found, rerr := archive.ReadFile(zipPrefix + f.Path)
		if rerr != nil {
			return nil, nil, fmt.Errorf("reading %s from zip: %w", f.Path, rerr)
		}
		if !found {
			continue
		}
		texts = append(texts, licensedomain.NoticeLicenseFile{
			Path:    f.Path,
			Content: strings.TrimRight(string(content), "\n"),
		})
	}

	// Embedded component texts grouped by prefix.
	embeddedComps := collectEmbeddedComponentTexts(archive, zipPrefix, rec)

	return texts, embeddedComps, nil
}

// collectEmbeddedComponentTexts reads vendored license file content from the
// archive and groups it by component prefix using the record's EffectiveSet.
func collectEmbeddedComponentTexts(
	archive *ziparchive.Archive,
	zipPrefix string,
	rec licensedomain.LicenseRecord,
) []licensedomain.NoticeEmbeddedComponent {
	if len(rec.EffectiveSet.Components) == 0 {
		return nil
	}

	// Build a map from path prefix to component for quick lookup.
	type compEntry struct {
		spdxs []string
		texts []licensedomain.NoticeLicenseFile
	}
	compMap := make(map[string]*compEntry, len(rec.EffectiveSet.Components))
	for _, c := range rec.EffectiveSet.Components {
		cc := c // copy for map reference
		compMap[cc.PathPrefix] = &compEntry{spdxs: cc.SPDXs}
	}

	for _, f := range rec.LicenseFiles {
		if isRootLevel(f.Path) || f.SPDX == "" {
			continue
		}
		prefix := embeddedComponentPrefix(f.Path)
		comp, ok := compMap[prefix]
		if !ok {
			continue
		}
		content, found, err := archive.ReadFile(zipPrefix + f.Path)
		if err != nil || !found {
			continue
		}
		comp.texts = append(comp.texts, licensedomain.NoticeLicenseFile{
			Path:    f.Path,
			Content: strings.TrimRight(string(content), "\n"),
		})
	}

	// Assemble in prefix order (Components is already sorted).
	var result []licensedomain.NoticeEmbeddedComponent
	for _, c := range rec.EffectiveSet.Components {
		comp := compMap[c.PathPrefix]
		if len(comp.texts) == 0 {
			continue
		}
		sort.Slice(comp.texts, func(i, j int) bool {
			return comp.texts[i].Path < comp.texts[j].Path
		})
		result = append(result, licensedomain.NoticeEmbeddedComponent{
			PathPrefix:   c.PathPrefix,
			SPDXs:        c.SPDXs,
			LicenseTexts: comp.texts,
		})
	}
	return result
}

// embeddedComponentPrefix returns the directory portion of a vendored file path.
func embeddedComponentPrefix(relPath string) string {
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		return relPath[:idx]
	}
	return relPath
}

// ambiguousReason builds a human-readable review reason listing the competing
// SPDX identifiers found in the root license file.
func ambiguousReason(rec licensedomain.LicenseRecord) string {
	candidates := []string{rec.PrimarySPDX}
	for _, f := range rec.LicenseFiles {
		if f.IsVendored || !isRootLevel(f.Path) {
			continue
		}
		for _, a := range f.AltMatches {
			if a.SPDX != "" && a.SPDX != rec.PrimarySPDX {
				candidates = append(candidates, fmt.Sprintf("%s (%.0f%%)", a.SPDX, a.Confidence*100))
			}
		}
	}
	if len(candidates) == 1 {
		return "ambiguous license: " + candidates[0]
	}
	primary := fmt.Sprintf("%s (%.0f%%)", rec.PrimarySPDX, rec.PrimaryConfidence*100)
	return "ambiguous license: primary=" + primary + ", alts=[" + strings.Join(candidates[1:], ", ") + "]"
}

// noticeRequireFetchRecord looks up the FactRecord for coord, trying the
// fetch pipeline version first, then the local-ingest pipeline version, then
// the license pipeline version.
func (uc *GenerateNoticeUseCase) noticeRequireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (fetchdomain.FactRecord, error) {
	seen := map[string]bool{}
	for _, v := range []string{uc.fetchPipelineVersion, uc.localFetchPipelineVersion, uc.pipelineVersion} {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		r, ok, err := uc.facts.GetFetchRecord(ctx, coord, v)
		if err != nil {
			return fetchdomain.FactRecord{}, fmt.Errorf("checking fetch record (pipeline %s): %w", v, err)
		}
		if ok {
			return r, nil
		}
	}
	return fetchdomain.FactRecord{}, fmt.Errorf("%w: %s", licenseports.ErrModuleNotFetched, coord)
}
