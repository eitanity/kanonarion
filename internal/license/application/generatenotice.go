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
	licenses        licenseports.LicenseStore
	facts           fetchports.FactStore
	blobs           fetchports.BlobStore
	pipelineVersion string
}

// NewGenerateNoticeUseCase constructs a GenerateNoticeUseCase.
//
// pipelineVersion is the LICENCE pipeline version, which keys the licence records
// this use case reads. It takes no fetch pipeline version: the licence texts come
// from whatever measurement the fetch ledger holds, and which generation of the
// fetch pipeline took it is not a property of the module.
func NewGenerateNoticeUseCase(
	licenses licenseports.LicenseStore,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	pipelineVersion string,
) *GenerateNoticeUseCase {
	return &GenerateNoticeUseCase{
		licenses:        licenses,
		facts:           facts,
		blobs:           blobs,
		pipelineVersion: pipelineVersion,
	}
}

// NoticeRequest is the input to Generate.
type NoticeRequest struct {
	Coordinates []coordinate.ModuleCoordinate
	// Declarations carries the operator's recorded copyrights. It is an input
	// rather than a use-case dependency because it is a property of the
	// invocation's configuration, not of the store the use case reads. The zero
	// value never matches, so a caller that has none passes nothing.
	Declarations licensedomain.CopyrightDeclarationSet
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
		entry, review, err := uc.processModule(ctx, coord, req.Declarations)
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
	declarations licensedomain.CopyrightDeclarationSet,
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

	// Copyright must be present. Where extraction found none, an operator may
	// have read the upstream repository and recorded what they found; that
	// clears the gate, and the document says whose assertion it is. Where
	// extraction DID find one, the declaration is not consulted here at all —
	// it is attached below as corroboration and never displaces the measurement.
	declaration, declared := declarations.Resolve(coord)
	if rec.CopyrightStatus != licensedomain.CopyrightStatusFound && !declared {
		return nil, &licensedomain.ReviewItem{
			Coordinate:       coord,
			Reason:           "copyright not found (status: " + rec.CopyrightStatus.String() + ")",
			MissingCopyright: true,
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

	entry := &licensedomain.NoticeEntry{
		Coordinate:         coord,
		SPDX:               rec.PrimarySPDX,
		Expression:         rec.Expression,
		LicenseTexts:       licenseTexts,
		Copyrights:         copyrights,
		EmbeddedComponents: embeddedComps,
	}
	if declared {
		entry.Declaration = &declaration
	}
	return entry, nil, nil
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

	zipIdentity, hasZip, err := fetchports.ZipIdentity(factRecord)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving zip address for %s: %w", coord, err)
	}
	if !hasZip {
		return nil, nil, fmt.Errorf("%s carries no module zip to read licence texts from", coord)
	}
	r, err := uc.blobs.Get(ctx, zipIdentity)
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

	zipPrefix := coord.Path() + "@" + coord.Version() + "/"

	// Root-level non-vendored license texts.
	var texts []licensedomain.NoticeLicenseFile
	for _, f := range rec.LicenseFiles {
		if f.IsVendored || !isRootLevel(f.Path) {
			continue
		}
		nf, ok, rerr := noticeFileFor(archive, zipPrefix, f)
		if rerr != nil {
			return nil, nil, rerr
		}
		if !ok {
			continue
		}
		texts = append(texts, nf)
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
		if licensedomain.IsUnbuiltPath(c.PathPrefix) {
			continue
		}
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
			Path:           f.Path,
			Content:        strings.TrimRight(string(content), "\n"),
			SPDX:           f.SPDX,
			Classification: licensedomain.ClassificationLicence,
			FileSize:       f.FileSize,
			FileHash:       f.FileHash,
		})
	}

	// Assemble in prefix order (Components is already sorted).
	var result []licensedomain.NoticeEmbeddedComponent
	for _, c := range rec.EffectiveSet.Components {
		comp, kept := compMap[c.PathPrefix]
		if !kept || len(comp.texts) == 0 {
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

// noticeFileFor turns one root-level licence-named file into its attribution
// block, saying what the pipeline identified in it rather than borrowing the
// module's identifier.
//
// Three outcomes, and the difference between them is the point:
//
//   - the detector identified a licence: the file's OWN identifier labels the
//     block and the text is reproduced verbatim;
//   - the file is a NOTICE-style attribution document: reproduced verbatim,
//     labelled as a notice, never as a licence — it declares no grant, and
//     Apache-2.0 section 4(d) requires it to travel with the work;
//   - the detector identified nothing: the file is RECORDED — path, size,
//     hash, and any sub-threshold fragment — and its bytes are NOT reproduced.
//     Unidentified bytes are not a grant, and printing them under a licence
//     heading is what put scanner-fixture markup into the document.
//
// The second return is false when the file is absent from the archive.
func noticeFileFor(
	archive *ziparchive.Archive,
	zipPrefix string,
	f licensedomain.LicenseFileEntry,
) (licensedomain.NoticeLicenseFile, bool, error) {
	out := licensedomain.NoticeLicenseFile{
		Path:                  f.Path,
		SPDX:                  f.SPDX,
		FileSize:              f.FileSize,
		FileHash:              f.FileHash,
		LowConfidenceSPDX:     f.LowConfidenceSPDX,
		LowConfidenceCoverage: f.LowConfidenceCoverage,
	}

	switch {
	case f.SPDX != "":
		out.Classification = licensedomain.ClassificationLicence
	case licensedomain.IsNoticeFileName(f.Path):
		out.Classification = licensedomain.ClassificationNotice
	default:
		// Recorded, not reproduced. The archive is not read at all: there is
		// nothing this document is entitled to say about those bytes beyond
		// that they are there.
		out.Classification = licensedomain.ClassificationUnclassified
		return out, true, nil
	}

	content, found, err := archive.ReadFile(zipPrefix + f.Path)
	if err != nil {
		return licensedomain.NoticeLicenseFile{}, false, fmt.Errorf("reading %s from zip: %w", f.Path, err)
	}
	if !found {
		return licensedomain.NoticeLicenseFile{}, false, nil
	}
	out.Content = strings.TrimRight(string(content), "\n")
	return out, true, nil
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

// noticeRequireFetchRecord asks the ledger what it has measured about coord and
// returns the record composition serves, so the notice reads its licence text
// from the strongest measurement rather than from whichever fetch pipeline
// version a fallback list happened to name first.
func (uc *GenerateNoticeUseCase) noticeRequireFetchRecord(
	ctx context.Context,
	coord coordinate.ModuleCoordinate,
) (fetchdomain.FactRecord, error) {
	r, ok, err := fetchports.ComposedFetchRecord(ctx, uc.facts, coord)
	if err != nil {
		return fetchdomain.FactRecord{}, fmt.Errorf("checking fetch record: %w", err)
	}
	if !ok {
		return fetchdomain.FactRecord{}, fmt.Errorf("%w: %s", licenseports.ErrModuleNotFetched, coord)
	}
	return r.FactRecord, nil
}
