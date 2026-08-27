package domain_test

import (
	"math"
	"math/rand"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// makeTiedLicenseRecord builds a LicenseRecord whose every collection holds two
// DISTINCT elements that tie on the key the collection used to be ordered by.
// AltMatches is the one to look at: it was ordered on Confidence alone, a
// float64 the detector reports in coarse steps, so two candidates at equal
// coverage tie routinely.
func makeTiedLicenseRecord(t *testing.T) domain2.LicenseRecord {
	t.Helper()
	return domain2.LicenseRecord{
		SchemaVersion: domain2.LicenseSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    mustCoord(t, "example.com/mod", "v1.2.3"),
		PrimarySPDX:   "MIT",
		Expression:    "MIT",
		BundledSPDXs:  []string{"BSD-3-Clause", "Zlib"},
		LicenseFiles: []domain2.LicenseFileEntry{
			{
				Path:       "LICENSE",
				SPDX:       "MIT",
				Confidence: 0.99,
				FileHash:   "sha256:aa",
				FileSize:   1024,
				AltMatches: []domain2.AltMatch{
					{SPDX: "Apache-2.0", Confidence: 0.5},
					{SPDX: "BSD-3-Clause", Confidence: 0.5},
				},
				CopyrightStatements: []domain2.CopyrightStatement{
					{Verbatim: "Copyright 2020 Acme", Holders: []string{"Acme"}, Years: "2020", Source: "a.go"},
					{Verbatim: "Copyright 2020 Acme", Holders: []string{"Acme"}, Years: "2020", Source: "b.go"},
				},
			},
			// Two entries at one path: the same relative path reached through
			// two readings of the archive.
			{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.4, FileHash: "sha256:bb", FileSize: 2048},
		},
		OverallStatus:   domain2.LicenseStatusDetected,
		CopyrightStatus: domain2.CopyrightStatusFound,
		Provenance: domain2.ProvenanceSummary{
			Signals: []domain2.ProvenanceSignal{
				domain2.ProvenanceSignalAuthorsFile,
				domain2.ProvenanceSignalPatentsFile,
			},
		},
		ExtractedAt:     time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

func shuffleLicenseRecord(rng *rand.Rand, r *domain2.LicenseRecord) {
	rng.Shuffle(len(r.LicenseFiles), func(i, j int) {
		r.LicenseFiles[i], r.LicenseFiles[j] = r.LicenseFiles[j], r.LicenseFiles[i]
	})
	for i := range r.LicenseFiles {
		f := &r.LicenseFiles[i]
		rng.Shuffle(len(f.AltMatches), func(a, b int) { f.AltMatches[a], f.AltMatches[b] = f.AltMatches[b], f.AltMatches[a] })
		rng.Shuffle(len(f.CopyrightStatements), func(a, b int) {
			f.CopyrightStatements[a], f.CopyrightStatements[b] = f.CopyrightStatements[b], f.CopyrightStatements[a]
		})
	}
	rng.Shuffle(len(r.BundledSPDXs), func(i, j int) { r.BundledSPDXs[i], r.BundledSPDXs[j] = r.BundledSPDXs[j], r.BundledSPDXs[i] })
	s := r.Provenance.Signals
	rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

// TestLicenseRecord_ContentHashIsIndependentOfInputOrder is the determinism
// guard for the licence record.
func TestLicenseRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain2.LicenseRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedLicenseRecord(t)
		shuffleLicenseRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("shuffle %d: content hash %s, shuffle 0 gave %s: the canonical order is not a function of the record alone",
				i, sealed.ContentHash, want)
		}
	}
}

// TestLicenseRecord_SortFilesIsIndependentOfInputOrder checks the record's own
// SortFiles agrees with the hasher on the canonical order.
func TestLicenseRecord_SortFilesIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain2.LicenseRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedLicenseRecord(t)
		shuffleLicenseRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		r.SortFiles()
		got, err := h.Marshal(r)
		if err != nil {
			t.Fatalf("shuffle %d: Marshal: %v", i, err)
		}
		if i == 0 {
			want = string(got)
			continue
		}
		if string(got) != want {
			t.Fatalf("shuffle %d: SortFiles produced a different canonical rendering than shuffle 0", i)
		}
	}
}

// TestExtractCopyrightStatements_IsIndependentOfInputOrder guards the copyright
// extractor's own ordering, which reaches the record through the same slice.
func TestExtractCopyrightStatements_IsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	// Two distinct statements whose verbatim text is identical after trimming
	// differ only in the holder the parser read out of them.
	const text = "// Copyright (c) 2020 Acme Ltd\n// Copyright (c) 2020 Beta Inc\n// Copyright (c) 2020 Acme Ltd\n"
	first := domain2.ExtractCopyright("a.go", []byte(text))
	for i := range determinismShuffles {
		got := domain2.ExtractCopyright("a.go", []byte(text))
		if len(got) != len(first) {
			t.Fatalf("run %d: %d statements, first run gave %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].Verbatim != first[j].Verbatim || got[j].Years != first[j].Years {
				t.Fatalf("run %d: statement %d differs from the first run", i, j)
			}
		}
	}
}

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself. Together over
// every field the wire shape carries, that is what "total order" means: no two
// DISTINCT elements compare equal, so the sort has no tie to resolve.
func assertOrders[T any](t *testing.T, key string, less func(a, b T) bool, lower, upper T) {
	t.Helper()
	if !less(lower, upper) {
		t.Errorf("%s: the comparator does not order two elements differing only in this field", key)
	}
	if less(upper, lower) {
		t.Errorf("%s: the comparator is not antisymmetric", key)
	}
	if less(lower, lower) {
		t.Errorf("%s: the comparator reports an element less than itself", key)
	}
}

// TestOrdering_IsKeyedOnEveryWireField exercises each comparator against every
// field the canonical shape carries.
func TestOrdering_IsKeyedOnEveryWireField(t *testing.T) {
	t.Parallel()

	// Confidence orders HIGHEST first on alternatives, so the "lower" element
	// is the one with the greater confidence.
	assertOrders(t, "alt.confidence", domain2.AltMatchLess,
		domain2.AltMatch{Confidence: 0.9}, domain2.AltMatch{Confidence: 0.1})
	assertOrders(t, "alt.spdx", domain2.AltMatchLess,
		domain2.AltMatch{SPDX: "Apache-2.0"}, domain2.AltMatch{SPDX: "MIT"})

	assertOrders(t, "copyright.verbatim", domain2.CopyrightStatementLess,
		domain2.CopyrightStatement{Verbatim: "a"}, domain2.CopyrightStatement{Verbatim: "b"})
	assertOrders(t, "copyright.source", domain2.CopyrightStatementLess,
		domain2.CopyrightStatement{Source: "a.go"}, domain2.CopyrightStatement{Source: "b.go"})
	assertOrders(t, "copyright.years", domain2.CopyrightStatementLess,
		domain2.CopyrightStatement{Years: "2019"}, domain2.CopyrightStatement{Years: "2020"})
	assertOrders(t, "copyright.holders count", domain2.CopyrightStatementLess,
		domain2.CopyrightStatement{}, domain2.CopyrightStatement{Holders: []string{"Acme"}})
	assertOrders(t, "copyright.holders value", domain2.CopyrightStatementLess,
		domain2.CopyrightStatement{Holders: []string{"Acme"}}, domain2.CopyrightStatement{Holders: []string{"Beta"}})

	assertOrders(t, "file.path", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{Path: "a"}, domain2.LicenseFileEntry{Path: "b"})
	assertOrders(t, "file.spdx", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{SPDX: "Apache-2.0"}, domain2.LicenseFileEntry{SPDX: "MIT"})
	assertOrders(t, "file.confidence", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{Confidence: 0.1}, domain2.LicenseFileEntry{Confidence: 0.9})
	assertOrders(t, "file.file_hash", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{FileHash: "a"}, domain2.LicenseFileEntry{FileHash: "b"})
	assertOrders(t, "file.file_size", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{FileSize: 1}, domain2.LicenseFileEntry{FileSize: 2})
	assertOrders(t, "file.is_vendored", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{}, domain2.LicenseFileEntry{IsVendored: true})
	assertOrders(t, "file.is_per_file", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{}, domain2.LicenseFileEntry{IsPerFile: true})
	assertOrders(t, "file.low_confidence_spdx", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{LowConfidenceSPDX: "a"}, domain2.LicenseFileEntry{LowConfidenceSPDX: "b"})
	assertOrders(t, "file.low_confidence_coverage", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{LowConfidenceCoverage: 0.1}, domain2.LicenseFileEntry{LowConfidenceCoverage: 0.9})
	assertOrders(t, "file.alt_matches", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{}, domain2.LicenseFileEntry{AltMatches: []domain2.AltMatch{{SPDX: "MIT"}}})
	assertOrders(t, "file.copyright_statements", domain2.LicenseFileEntryLess,
		domain2.LicenseFileEntry{},
		domain2.LicenseFileEntry{CopyrightStatements: []domain2.CopyrightStatement{{Verbatim: "a"}}})

	assertOrders(t, "root.confidence", domain2.RootCandidateLess,
		domain2.LicenseFileEntry{Confidence: 0.9}, domain2.LicenseFileEntry{Confidence: 0.1})
	assertOrders(t, "root.path", domain2.RootCandidateLess,
		domain2.LicenseFileEntry{Path: "a"}, domain2.LicenseFileEntry{Path: "b"})
	assertOrders(t, "root.spdx", domain2.RootCandidateLess,
		domain2.LicenseFileEntry{SPDX: "Apache-2.0"}, domain2.LicenseFileEntry{SPDX: "MIT"})
}

// TestOrdering_NaNConfidenceIsOrdered pins the one float hazard. A detector
// that emitted a NaN would otherwise make the comparator answer "not less" for
// a pair in BOTH directions while claiming to have decided, which is not a
// strict weak ordering and which sort.Slice is entitled to do anything with.
func TestOrdering_NaNConfidenceIsOrdered(t *testing.T) {
	t.Parallel()

	nan := math.NaN()
	number := domain2.AltMatch{SPDX: "MIT", Confidence: 0.5}
	notANumber := domain2.AltMatch{SPDX: "MIT", Confidence: nan}
	if !domain2.AltMatchLess(number, notANumber) {
		t.Error("a NaN confidence does not sort after a real one")
	}
	if domain2.AltMatchLess(notANumber, number) {
		t.Error("a NaN confidence sorts before a real one")
	}
	if domain2.AltMatchLess(notANumber, notANumber) {
		t.Error("two NaN confidences do not compare equal, so the comparator is not reflexive")
	}

	numberEntry := domain2.LicenseFileEntry{Confidence: 0.5}
	nanEntry := domain2.LicenseFileEntry{Confidence: nan}
	if !domain2.LicenseFileEntryLess(numberEntry, nanEntry) {
		t.Error("a NaN file confidence does not sort after a real one")
	}
	if domain2.LicenseFileEntryLess(nanEntry, numberEntry) {
		t.Error("a NaN file confidence sorts before a real one")
	}
	if domain2.LicenseFileEntryLess(nanEntry, nanEntry) {
		t.Error("two NaN file confidences do not compare equal")
	}
	if !domain2.LicenseFileEntryLess(domain2.LicenseFileEntry{LowConfidenceCoverage: 0.5},
		domain2.LicenseFileEntry{LowConfidenceCoverage: nan}) {
		t.Error("a NaN low-confidence coverage does not sort after a real one")
	}
}
