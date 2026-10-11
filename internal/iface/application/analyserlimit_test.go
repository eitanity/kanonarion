package application_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/iface/application"
	domain3 "github.com/eitanity/kanonarion/internal/iface/domain"
)

// A record as a go1.26.6 build wrote it for the probe module, before the limit
// was classified: the generic method filed as the module's parse failure.
func probeHeld(t *testing.T, coord coordinate.ModuleCoordinate, toolchain gotoolchain.Version, limit *gotoolchain.UnreadSource) domain3.InterfaceRecord {
	t.Helper()
	r := domain3.InterfaceRecord{
		SchemaVersion: domain3.InterfaceSchemaVersion,
		Coordinate:    coord,
		Packages: []domain3.PackageInterface{{
			ImportPath:    coord.Path(),
			ParseFailures: []domain3.ParseFailure{{File: "genmeth.go", Error: "genmeth.go:8:17: method must have no type parameters"}},
		}},
		OverallStatus:   domain3.InterfaceStatusPartial,
		FailureDetail:   "parse failures in 1 package(s): example.com/genmeth: genmeth.go:8:17: method must have no type parameters",
		Toolchain:       toolchain,
		AnalyserLimit:   limit,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: application.PipelineVersion,
	}
	if limit != nil {
		r.Packages[0].ParseFailures = nil
	}
	sealed, err := domain3.InterfaceRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

const probeSource = "package genmeth\n\n// Box holds a value.\ntype Box struct{ V int }\n"

func runProbe(t *testing.T, held domain3.InterfaceRecord) application.ExtractResult {
	t.Helper()
	coord := held.Coordinate
	facts, blobs, store := &fakeFactStore{}, &fakeBlobStore{}, &fakeInterfaceStore{}
	putFactWithBlob(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"go.mod": "module example.com/genmeth\n\ngo 1.27.2\n", "genmeth.go": probeSource,
	}))
	if err := store.PutInterfaceRecord(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	res, err := buildUseCase(t, facts, blobs, store, nil).Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return res
}

// A record with parse failures written by an older Go is measured again by a
// newer one, not served back: that build may have filed its own limit as the
// module's fault.
func TestExecute_FailureFromAnOlderGoIsRemeasured(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.27.2")
	defer restore()
	coord := mustCoord(t, "example.com/genmeth", "v1.0.0")

	res := runProbe(t, probeHeld(t, coord, "go1.26.6", nil))
	if res.FromCache {
		t.Fatal("a go1.26.6 record with parse failures was served to a go1.27.2 binary")
	}
	if res.Record.OverallStatus != domain3.InterfaceStatusExtracted {
		t.Errorf("re-measured status = %s, want Extracted", res.Record.OverallStatus)
	}
}

// The control: the same failure recorded by this binary's own Go is served.
func TestExecute_FailureFromThisGoIsServed(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.27.2")
	defer restore()
	coord := mustCoord(t, "example.com/genmeth", "v1.0.0")

	if res := runProbe(t, probeHeld(t, coord, "go1.27.2", nil)); !res.FromCache {
		t.Error("a record this binary's Go wrote was re-measured instead of served")
	}
}

// A record carrying the limit is never served, whichever binary reads it.
func TestExecute_LimitRecordIsRemeasured(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.27.2")
	defer restore()
	coord := mustCoord(t, "example.com/genmeth", "v1.0.0")
	limit := gotoolchain.NewUnreadSource(gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}, []string{"genmeth.go"})

	res := runProbe(t, probeHeld(t, coord, "go1.26.6", limit))
	if res.FromCache {
		t.Fatal("a record carrying the analyser limit was served")
	}
	if res.Record.AnalyserLimit != nil || res.Record.OverallStatus != domain3.InterfaceStatusExtracted {
		t.Errorf("re-measured: limit %v, status %s", res.Record.AnalyserLimit, res.Record.OverallStatus)
	}
}
