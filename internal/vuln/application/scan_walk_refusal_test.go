package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	"code.eitanity.com/kanonarion/internal/vuln/application"
	"code.eitanity.com/kanonarion/internal/vuln/vulntest"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// refusingBlob refuses every read of the identities in refuse, as a verifying
// store refuses held bytes that no longer hash to their identity.
type refusingBlob struct {
	*fakeBlob
	refuse map[fetchports.BlobIdentity]bool
}

func (b *refusingBlob) Get(ctx context.Context, identity fetchports.BlobIdentity) (io.ReadCloser, error) {
	if b.refuse[identity] {
		return nil, &fetchports.BlobTamperedError{Identity: identity, Observed: "h1:other"}
	}
	return b.fakeBlob.Get(ctx, identity)
}

func (b *refusingBlob) GetPath(ctx context.Context, identity fetchports.BlobIdentity) (string, error) {
	if b.refuse[identity] {
		return "", &fetchports.BlobTamperedError{Identity: identity, Observed: "h1:other"}
	}
	return b.fakeBlob.GetPath(ctx, identity)
}

// A walk scan that meets a stored artefact refused as altered ends with the
// refusal and writes no record and no run, whichever route read the bytes: the
// scan cache populated from the store, the module's own isolated scan under
// --from-modcache, or a coordinate walk's target-rooted analysis.
func TestScanWalk_ARefusedArtefactEndsTheRunWithNothingWritten(t *testing.T) {
	for _, route := range []string{"scan cache", "isolated scan", "isolated scan, go.mod", "target-rooted"} {
		t.Run(route, func(t *testing.T) {
			ctx := t.Context()
			coord := coordinatetest.MustNew("github.com/example/mod", "v1.0.0")
			walk := walkdomain.WalkRecord{ID: "w1", Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}}}
			if route == "target-rooted" {
				walk.Target = coord
			} else {
				local, err := coordinate.NewLocalCoordinate("example.com/app")
				if err != nil {
					t.Fatal(err)
				}
				walk.Target = local
			}
			walkStore := newFakeWalkStore()
			if err := walkStore.PutWalk(ctx, walk); err != nil {
				t.Fatal(err)
			}
			facts := newFakeFacts()
			blobs := &refusingBlob{fakeBlob: newFakeBlob(), refuse: map[fetchports.BlobIdentity]bool{}}
			opts := []fetchtest.Option{fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"),
				fetchtest.GoMod("mod"), fetchtest.GoModHash(fetchtest.H1("mod"))}
			rec := fetchtest.Record(t, opts...)
			if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip")); err != nil {
				t.Fatal(err)
			}
			if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, opts...)); err != nil {
				t.Fatal(err)
			}
			refused := fetchtest.ZipIdentity(t, rec)
			if route == "isolated scan, go.mod" {
				refused = fetchtest.GoModIdentity(t, rec)
				if err := blobs.Put(ctx, refused, strings.NewReader("module "+coord.Path()+"\n")); err != nil {
					t.Fatal(err)
				}
			}
			blobs.refuse[refused] = true

			db := &fakeDatabase{snapshot: vulntest.MustNew("test", "v1"), vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-VULN-ID"}}}
			vulnStore := newFakeVulnStore()
			clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
			moduleUC := application.NewScanModuleUseCase(facts, blobs, vulnStore, walkStore, &fakeScanner{}, db, nil, clock, "v1", slog.Default())
			walkUC := application.NewScanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())
			if route != "scan cache" {
				walkUC = walkUC.WithRealModcache(t.TempDir())
			}

			_, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1"})
			if !errors.Is(err, fetchports.ErrBlobTampered) {
				t.Fatalf("Scan err = %v, want the refusal", err)
			}
			if n := vulnStore.walkScanRunCount(); n != 0 {
				t.Errorf("%d scan run(s) written", n)
			}
			recs, lerr := vulnStore.ListVulnerabilityRecordsForModuleAllGenerations(ctx, coord)
			if lerr != nil || len(recs) != 0 {
				t.Errorf("%d record(s) written for the refused module (%v)", len(recs), lerr)
			}
		})
	}
}
