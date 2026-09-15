package golden_test

// The hermetic fixture the two DOCUMENTS are recorded against: the CycloneDX
// SBOM and the THIRD-PARTY-LICENSES notice.
//
// It is a store of its own rather than a few more rows in fixture_test.go, and
// both halves of that were measured rather than assumed:
//
//   - `sbom` WRITES. It persists a record per (walk, format, pipeline version)
//     and appends an assurance event, so sharing a store with the read-only
//     cases would make `sbom-list` answer differently depending on which case
//     ran before it. audit already has a store per case for the same reason.
//   - A native-component record is read by `context`, `vuln-show` and
//     `vuln-scan-show` as well as by the SBOM. Seeding one into the shared
//     fixture moves three recorded surfaces that this change is not entitled to
//     move, so the non-Go component the ticket requires lives here.
//
// What this fixture has to be able to EXPRESS, and why each shape is present:
//
//  1. A walk in which EVERY component carries a licence identity, so `sbom`
//     exits 0 and `notice` publishes. Without it the only recording would be of
//     the failure shape.
//  2. A walk holding one module with no licence record at all, so `sbom` exits
//     1 with the document still written and `notice` refuses at the review gate
//     with exit 5. That is the shape a release pipeline branches on.
//  3. A walk of the target alone — nothing was brought in. It is the zero, and
//     it is a real state: a project with no dependencies.
//  4. One module whose artefact compiles a third-party C library in from source
//     its own zip ships. It is the non-Go component: a `pkg:generic` entry with
//     a CycloneDX evidence block and a dependsOn edge from the Go module that
//     hosts it, none of which the Go path can guard.
//  5. Module zips that actually CONTAIN their LICENSE and NOTICE files. The
//     notice document reproduces licence text verbatim out of the artefact, so
//     a fixture whose zips hold only a README would record a document with
//     every text block silently missing — the reproduction step untested.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	licsqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	nativesqlite "github.com/eitanity/kanonarion/internal/native/adapters/store/sqlite"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The three walks the documents are generated from. The identifiers are fixed,
// not minted, so a recorded document names the walk it was built from literally
// and a change to WHICH walk answers shows as a diff.
const (
	// docWalkID is the walk every component of which carries a licence
	// identity: the document publishes and the command exits 0.
	docWalkID = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	// docWalkGapID holds one module with no licence record. It is the exit-1
	// SBOM and the exit-5 notice.
	docWalkGapID = "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	// docWalkBareID is the target and nothing else: a build that brought
	// nothing in. The zero, paired with the populated walk above.
	docWalkBareID = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
)

// docExtractedAt is when every licence record in this fixture was extracted.
//
// ONE instant, deliberately, and it is the harder fixture rather than the
// convenient one. With no --generated-at the SBOM stamps metadata.timestamp
// with the newest licence extraction time among its inputs, so every document
// generated over this store carries this instant — and `sbom-list` therefore
// records a real TIE on its primary sort key, which is the state two documents
// built from one licence basis are in by construction.
//
// An earlier draft of this fixture gave the documents two instants and made the
// tie go away. That concealed the defect inside the suite built to catch it:
// the listing had no tiebreak below generated_at and returned whatever order
// the store produced. The tiebreak is now in the store (see sbomRecency), and
// this fixture is what proves it from the operator's side rather than only from
// the adapter's.
var docExtractedAt = time.Date(2026, 2, 3, 11, 30, 0, 0, time.UTC)

// The fixture's modules.
func docTarget(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/product", "v1.4.0")
}
func docPlain(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/plainlib", "v1.1.0")
}

// docCgo is the module whose artefact ships a third-party C library and
// compiles it in. It is the host of this fixture's non-Go component.
func docCgo(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/cgolib", "v0.4.2")
}

// docGap is held go.mod-only and carries NO licence record. It is the module
// that makes one walk's document incomplete.
func docGap(t testing.TB) coordinate.ModuleCoordinate {
	return fixtureCoord(t, "example.com/unlicensed", "v1.0.0")
}

// The verbatim text each module's LICENSE and NOTICE file holds. Short on
// purpose — the document reproduces it in full, and a golden is read by a
// person — but it is really in the zip and really hashed, so the path that
// reads bytes back out of the artefact is the path under test.
const (
	docMITText = `MIT License

Copyright (c) 2026 Example Product Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.`

	docApacheText = `Apache License, Version 2.0

Copyright 2026 Example Plainlib Authors

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License.`

	docApacheNoticeText = `Example Plainlib
Copyright 2026 Example Plainlib Authors

This product includes software developed at Example.`

	docBSDText = `BSD 3-Clause License

Copyright (c) 2026, Example Cgolib Authors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the above copyright notice is
retained.`
)

// docArtefact builds a module zip holding the files the document pipeline
// reads: a README so the archive is not a licence file alone, and one entry per
// supplied path.
//
// It is separate from fixtureArtefact rather than a flag on it: changing what
// the shared fixture's zips contain would change every artefact identity in the
// main store and move goldens this change is not entitled to move.
func docArtefact(
	t testing.TB,
	coord coordinate.ModuleCoordinate,
	files map[string]string,
) ([]byte, fetchdomain.ModuleHash, fetchports.BlobIdentity) {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	prefix := coord.Path() + "@" + coord.Version() + "/"
	// Written in a fixed order, so the archive's bytes — and therefore the
	// artefact identity every record in this fixture pins — are a function of
	// the content and not of map iteration.
	write := func(name, body string) {
		f, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatalf("fixture zip entry %s: %v", name, err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("fixture zip write %s: %v", name, err)
		}
	}
	write("README", "the "+coord.Path()+" module")
	for _, name := range sortedKeys(files) {
		write(name, files[name])
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("fixture zip close: %v", err)
	}
	content := buf.Bytes()

	tmp := filepath.Join(t.TempDir(), "fixture.zip")
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatalf("fixture zip file: %v", err)
	}
	raw, err := dirhash.HashZip(tmp, dirhash.Hash1)
	if err != nil {
		t.Fatalf("fixture zip hash: %v", err)
	}
	hash, err := fetchdomain.ParseModuleHash(raw)
	if err != nil {
		t.Fatalf("fixture zip hash parse: %v", err)
	}
	identity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, hash)
	if err != nil {
		t.Fatalf("fixture blob identity: %v", err)
	}
	return content, hash, identity
}

// sortedKeys returns m's keys in order. A fixture that iterated a map to build
// an archive would mint a different artefact identity per run.
func sortedKeys(m map[string]string) []string {
	out := slices.Collect(maps.Keys(m))
	slices.Sort(out)
	return out
}

// docModule is one seeded module and the two facts every later record and the
// document itself are built from: the artefact its records pin, and the digests
// the SBOM emits as that component's hashes.
type docModule struct {
	coord    coordinate.ModuleCoordinate
	identity fetchports.BlobIdentity
	digests  fetchdomain.ArtifactDigests
}

// seedDocFetch files one acquired measurement of coord and stores the
// artefact's bytes.
//
// git is the VCS origin the ledger recorded, zero where none was. It is a
// parameter because the document asserts an external reference only for a
// module whose zip was cross-verified against its repository, and a fixture in
// which every module carried one — or none did — would record one half of that
// rule and call it the whole.
func seedDocFetch(
	t testing.TB,
	facts *fetchsqlite.Store,
	blobs *localfs.Store,
	coord coordinate.ModuleCoordinate,
	files map[string]string,
	git fetchdomain.GitReference,
) docModule {
	t.Helper()
	content, hash, identity := docArtefact(t, coord, files)
	if err := blobs.Put(context.Background(), identity, bytes.NewReader(content)); err != nil {
		t.Fatalf("storing document fixture artefact for %s: %v", coord, err)
	}
	sealed, err := fetchdomain.Seal(fetchdomain.FetchedModule{
		Coordinate:         coord,
		ModuleHash:         hash,
		GoModHash:          fixtureGoModHash(t, coord, "doc"),
		VerificationStatus: fetchdomain.Verified,
		PipelineVersion:    fetchapp.PipelineVersion,
		ContentLocation:    identity.String(),
		GoModLocation:      "gomod:" + coord.Path() + "@" + coord.Version(),
		FetchedAt:          fixtureWalkAt,
		MeasurementKind:    fetchdomain.MeasurementAcquired,
		GitReference:       git,
	})
	if err != nil {
		t.Fatalf("sealing document fixture fetch record for %s: %v", coord, err)
	}
	if err := facts.PutFetchRecord(context.Background(), sealed); err != nil {
		t.Fatalf("filing document fixture fetch record for %s: %v", coord, err)
	}
	return docModule{
		coord:    coord,
		identity: identity,
		// Taken over the same bytes the identity is, so the hashes the document
		// publishes describe the artefact its records name.
		digests: fetchdomain.ComputeArtifactDigests(content),
	}
}

// docLicenceFile describes one licence file as the extraction recorded it. The
// hash and the size are computed from the text that is actually in the zip, so
// the document reproduces bytes it also correctly identifies.
type docLicenceFile struct {
	path string
	spdx string
	text string
}

// seedDocLicense files one licence record with copyright statements attached.
//
// The copyright is what separates this from seedFixtureLicense: `notice`
// refuses to publish a module whose CopyrightStatus is anything but Found, so a
// record without one can only ever record the review gate. Both are wanted, and
// the gate is reached here by a module with no record at all rather than by
// weakening these.
func seedDocLicense(
	t *testing.T,
	store *licsqlite.Store,
	coord coordinate.ModuleCoordinate,
	identity fetchports.BlobIdentity,
	spdx string,
	copyrightLine string,
	extractedAt time.Time,
	files []docLicenceFile,
) {
	t.Helper()
	entries := make([]licdomain.LicenseFileEntry, 0, len(files))
	for _, f := range files {
		sum := sha256.Sum256([]byte(f.text))
		entry := licdomain.LicenseFileEntry{
			Path:       f.path,
			SPDX:       f.spdx,
			Confidence: 1.0,
			FileHash:   "sha256:" + hex.EncodeToString(sum[:]),
			FileSize:   int64(len(f.text)),
		}
		// The copyright is recorded against the file it was read in, which is
		// the only place the notice generator looks for it.
		if f.spdx == spdx {
			entry.CopyrightStatements = []licdomain.CopyrightStatement{
				{Verbatim: copyrightLine, Source: f.path},
			}
		}
		entries = append(entries, entry)
	}
	rec := licdomain.LicenseRecord{
		SchemaVersion:     licdomain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		Expression:        spdx,
		PrimaryConfidence: 1.0,
		OverallStatus:     licdomain.LicenseStatusDetected,
		CopyrightStatus:   licdomain.CopyrightStatusFound,
		LicenseFiles:      entries,
		ExtractedAt:       extractedAt,
		PipelineVersion:   licapp.PipelineVersion,
		ArtefactIdentity:  identity.String(),
	}
	rec.SortFiles()
	sealed, err := licdomain.LicenseRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing document fixture licence for %s: %v", coord, err)
	}
	if err := store.PutLicenseRecord(context.Background(), sealed); err != nil {
		t.Fatalf("filing document fixture licence for %s: %v", coord, err)
	}
}

// seedFixtureNative files the measurement behind the document's non-Go
// component: a third-party C library compiled into the host module from source
// the module's own published zip ships.
//
// It is the one shape the Go path cannot stand in for. The component is emitted
// under pkg:generic, carries a CycloneDX evidence block naming the file and the
// verbatim declaration its version was read from, and gains a dependsOn edge
// from the host module's own component. None of those three is reachable from a
// walk of Go modules alone.
func seedFixtureNative(
	t *testing.T,
	store *nativesqlite.Store,
	coord coordinate.ModuleCoordinate,
	identity fetchports.BlobIdentity,
) {
	t.Helper()
	components := []nativedomain.Component{{
		Name:       "SQLite",
		Version:    "3.45.1",
		Confidence: nativedomain.ConfidenceDeclared,
		Evidence: []nativedomain.Evidence{{
			File:        "sqlite3-binding.c",
			Declaration: `#define SQLITE_VERSION        "3.45.1"`,
		}},
	}}
	sources := []nativedomain.Source{{
		File:   "sqlite3-binding.c",
		Bytes:  8_675_309,
		SHA256: "3a5c1f9e2b7d4086a1c3e5f70981b2d4c6e8fa0b1d3f5729406182a3b4c5d6e7",
	}}
	rec := nativedomain.Record{
		SchemaVersion:          nativedomain.NativeSchemaVersion,
		Ecosystem:              nativedomain.EcosystemGo,
		Coordinate:             coord,
		ArtefactIdentity:       identity.String(),
		PipelineVersion:        nativedomain.PipelineVersion,
		RecipeCatalogueVersion: nativedomain.RecipeCatalogueVersion,
		Presence:               nativedomain.PresenceIdentified,
		Components:             components,
		Sources:                sources,
		ExtractedAt:            docExtractedAt,
	}
	rec.ContentHash = nativedomain.Hash(
		coord.String(), identity.String(),
		nativedomain.PipelineVersion, nativedomain.RecipeCatalogueVersion,
		rec.Presence, components, sources, nil,
	)
	if err := store.PutNativeRecord(context.Background(), rec); err != nil {
		t.Fatalf("filing document fixture native record for %s: %v", coord, err)
	}
}

// seedDocWalk files one walk of the document fixture's target over the supplied
// direct dependencies.
//
// Each node carries the digests of the artefact its fetch record measured. That
// is what a real walk carries, and it is what the SBOM emits as a component's
// hashes — a fixture whose nodes had none would record a document with the
// integrity block missing from every component and never notice.
func seedDocWalk(
	t *testing.T,
	store *walksqlite.Store,
	id string,
	target docModule,
	deps ...docModule,
) {
	t.Helper()
	nodes := []walkdomain.GraphNode{{
		Coordinate: target.coord, ResolutionSource: walkdomain.ResolutionTarget, Digests: target.digests,
	}}
	edges := make([]walkdomain.GraphEdge, 0, len(deps))
	results := map[coordinate.ModuleCoordinate]walkdomain.NodeResult{
		target.coord: {Coordinate: target.coord, Status: walkdomain.NodeSucceeded, DurationMs: 10},
	}
	for _, m := range deps {
		d := m.coord
		nodes = append(nodes, walkdomain.GraphNode{
			Coordinate: d, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS, Digests: m.digests,
		})
		edges = append(edges, walkdomain.GraphEdge{From: target.coord, To: d, ConstraintVersion: d.Version()})
		results[d] = walkdomain.NodeResult{Coordinate: d, Status: walkdomain.NodeSucceeded, DurationMs: 5}
	}
	outcome := walkdomain.WalkOutcome{
		Target: target.coord,
		Graph: walkdomain.Graph{
			Target:          target.coord,
			Nodes:           nodes,
			Edges:           edges,
			ResolvedAt:      fixtureWalkAt,
			PipelineVersion: "1.0.0",
		},
		PerNodeResults: results,
		StartedAt:      fixtureWalkAt,
		CompletedAt:    fixtureWalkAt.Add(time.Second),
		OverallStatus:  walkdomain.WalkSucceeded,
	}
	rec := walkdomain.NewWalkRecord(id, "fixture", "1.0.0",
		walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), "")
	rec, err := walkdomain.WalkRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing document fixture walk %s: %v", id, err)
	}
	if err := store.PutWalk(context.Background(), rec); err != nil {
		t.Fatalf("filing document fixture walk %s: %v", id, err)
	}
}

// buildDocumentStore builds the store the sbom and notice cases run against and
// returns its root.
//
// Every case that WRITES gets its own, for the reason auditFixture.newStore
// states: `sbom` persists a record and appends an assurance event, so a shared
// root would make sbom-list's answer depend on which case ran first.
func buildDocumentStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// Only the modules this fixture WRITES through. The rest — the SBOM records
	// the recorded runs create among them — are applied by the container when
	// the command opens the store, which is the path an operator's store takes.
	migrations := fetchsqlite.Migrations()
	migrations = append(migrations, walksqlite.Migrations()...)
	migrations = append(migrations, licsqlite.Migrations()...)
	migrations = append(migrations, nativesqlite.Migrations()...)

	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), migrations, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening document fixture store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	facts := fetchsqlite.New(db)
	blobs := localfs.New(root)
	licenses := licsqlite.New(db)

	// The target's own zip was never cross-verified against a repository — a
	// walk root is not fetched from a proxy — so it asserts no origin. One
	// dependency carries a verified VCS reference and the other does not, which
	// is what makes the external-reference rule legible: the document names a
	// repository only where one was confirmed, and says nothing where it was not.
	target := seedDocFetch(t, facts, blobs, docTarget(t),
		map[string]string{"LICENSE": docMITText}, fetchdomain.GitReference{})
	plain := seedDocFetch(t, facts, blobs, docPlain(t), map[string]string{
		"LICENSE": docApacheText,
		// Apache-2.0 section 4(d) makes the NOTICE file travel with the work, so
		// the document reproduces it whether or not the detector classified it.
		// A fixture with licence files alone never reaches that branch.
		"NOTICE": docApacheNoticeText,
	}, fetchdomain.GitReference{
		URL:        "https://example.com/plainlib",
		Ref:        "refs/tags/v1.1.0",
		CommitHash: "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c",
	})
	cgo := seedDocFetch(t, facts, blobs, docCgo(t),
		map[string]string{"LICENSE": docBSDText}, fetchdomain.GitReference{})
	// The gap module is held go.mod-only and gets NO licence record. It is what
	// makes one walk's document incomplete, and its remedy is the one an
	// operator would actually be given.
	gap := docGap(t)
	seedGoModOnly(t, facts, gap)

	seedDocLicense(t, licenses, target.coord, target.identity, "MIT",
		"Copyright (c) 2026 Example Product Authors", docExtractedAt,
		[]docLicenceFile{{path: "LICENSE", spdx: "MIT", text: docMITText}})
	seedDocLicense(t, licenses, plain.coord, plain.identity, "Apache-2.0",
		"Copyright 2026 Example Plainlib Authors", docExtractedAt,
		[]docLicenceFile{
			{path: "LICENSE", spdx: "Apache-2.0", text: docApacheText},
			// Recorded with no SPDX: it is a notice, not a grant. The document
			// reproduces it under that heading rather than as a licence.
			{path: "NOTICE", text: docApacheNoticeText},
		})
	seedDocLicense(t, licenses, cgo.coord, cgo.identity, "BSD-3-Clause",
		"Copyright (c) 2026, Example Cgolib Authors", docExtractedAt,
		[]docLicenceFile{{path: "LICENSE", spdx: "BSD-3-Clause", text: docBSDText}})

	seedFixtureNative(t, nativesqlite.New(db), cgo.coord, cgo.identity)

	walks := walksqlite.New(db)
	seedDocWalk(t, walks, docWalkID, target, plain, cgo)
	// The go.mod-only module has no zip and therefore no digests, which is the
	// state a node the SBOM emits no hashes for is actually in.
	seedDocWalk(t, walks, docWalkGapID, target, plain, cgo, docModule{coord: gap})
	seedDocWalk(t, walks, docWalkBareID, target)

	return root
}
