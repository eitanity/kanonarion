package application_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/application"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// putFactWithGoMod stores the zip and the standalone go.mod the fetch record
// addresses, as a fetch does.
func putFactWithGoMod(t *testing.T, s *fakeFactStore, blobs *fakeBlobStore, coord coordinate.ModuleCoordinate, zipData []byte, goMod string) {
	t.Helper()
	r := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(application.PipelineVersion),
		fetchtest.Content("zip"),
		fetchtest.GoMod("gomod"),
		fetchtest.Status(domain.Verified),
	)
	ctx := context.Background()
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, r), bytes.NewReader(zipData)); err != nil {
		t.Fatalf("Put zip: %v", err)
	}
	if err := blobs.Put(ctx, fetchtest.GoModIdentity(t, r), bytes.NewReader([]byte(goMod))); err != nil {
		t.Fatalf("Put go.mod: %v", err)
	}
	sealed, err := domain.Rehydrate(r)
	if err != nil {
		t.Fatalf("sealing record: %v", err)
	}
	if err := s.PutFetchRecord(ctx, sealed); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func goModOf(directive string) string { return "module example.com/genmeth\n\ngo " + directive + "\n" }

// heldRecord is a stored generation as an earlier build wrote it.
func heldRecord(t *testing.T, coord coordinate.ModuleCoordinate, failures []domain2.ParseFailure, limit *gotoolchain.UnreadSource) domain2.ExampleRecord {
	t.Helper()
	r := domain2.ExampleRecord{
		SchemaVersion:   domain2.ExampleSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain2.ExampleStatusNone,
		ParseFailures:   failures,
		AnalyserLimit:   limit,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: application.PipelineVersion,
	}
	sealed, err := domain2.ExampleRecordHasher{}.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// What a go1.26-built kanonarion recorded for the probe's example_test.go
// before the limit was classified, as measured.
var oldWriterFailure = []domain2.ParseFailure{{
	File:  "example_test.go",
	Error: "parsing example_test.go: example_test.go:11:18: method must have no type parameters",
}}

const probeTest = "package genmeth_test\n\nimport \"fmt\"\n\nfunc ExampleNew() {\n\tfmt.Println(1)\n\t// Output: 1\n}\n"

// A record whose parse failure the oldest build writing this shape could have
// met as a limit is measured again, not served: the cache was handing a newer
// binary the older one's refusal as the module's fault.
func TestExecute_OldWriterFailureIsRemeasured(t *testing.T) {
	coord := mustCoord(t, "example.com/genmeth", "v1.0.0")
	facts, blobs, store := &fakeFactStore{}, &fakeBlobStore{}, &fakeExampleStore{}
	putFactWithGoMod(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"go.mod": goModOf("1.27.2"), "example_test.go": probeTest,
	}), goModOf("1.27.2"))
	if err := store.PutExampleRecord(context.Background(), heldRecord(t, coord, oldWriterFailure, nil)); err != nil {
		t.Fatal(err)
	}

	res, err := buildUseCase(t, facts, blobs, store).Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Fatal("the older build's parse failure was served from cache")
	}
	if len(res.Record.ParseFailures) != 0 || len(res.Record.Examples) != 1 {
		t.Errorf("re-measured record: %d failure(s), %d example(s); want 0 and 1", len(res.Record.ParseFailures), len(res.Record.Examples))
	}
}

// The control: a parse failure in a module whose directive no build writing
// this shape is too old for is the module's own, and is served.
func TestExecute_FailureNoWriterWasTooOldForIsServed(t *testing.T) {
	coord := mustCoord(t, "example.com/genmeth", "v1.0.0")
	facts, blobs, store := &fakeFactStore{}, &fakeBlobStore{}, &fakeExampleStore{}
	putFactWithGoMod(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"go.mod": goModOf("1.21"), "example_test.go": probeTest,
	}), goModOf("1.21"))
	if err := store.PutExampleRecord(context.Background(), heldRecord(t, coord, oldWriterFailure, nil)); err != nil {
		t.Fatal(err)
	}

	res, err := buildUseCase(t, facts, blobs, store).Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.FromCache {
		t.Error("a genuine module parse failure was re-measured instead of served")
	}
}

// A record carrying the limit is never served, even to the binary that wrote
// it; that one re-measures and finds the generation it already holds.
func TestExecute_LimitRecordIsNeverServed(t *testing.T) {
	restore := gotoolchain.SetAnalysingGo("go1.26.6")
	defer restore()
	coord := mustCoord(t, "example.com/genmeth", "v1.0.0")
	facts, blobs, store := &fakeFactStore{}, &fakeBlobStore{}, &fakeExampleStore{}
	putFactWithGoMod(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"go.mod":           goModOf("1.27.2"),
		"example_test.go":  "package genmeth_test\n\nfunc ExampleLost() {\n",
		"plain/ok_test.go": probeTest,
	}), goModOf("1.27.2"))
	uc := buildUseCase(t, facts, blobs, store)

	first, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	u := first.Record.AnalyserLimit
	if u == nil || len(u.Files) != 1 || u.Files[0] != "example_test.go" || u.Limit.Built != "go1.26.6" || u.Limit.Required != "go1.27.2" {
		t.Fatalf("limit = %+v", u)
	}
	if len(first.Record.ParseFailures) != 0 || len(first.Record.Examples) != 1 {
		t.Errorf("first record: failures %v, %d example(s)", first.Record.ParseFailures, len(first.Record.Examples))
	}

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if second.FromCache || !second.Reused || len(store.puts) != 1 {
		t.Errorf("second run: FromCache %v, Reused %v, %d put(s); want measured, reused, one put",
			second.FromCache, second.Reused, len(store.puts))
	}
}
