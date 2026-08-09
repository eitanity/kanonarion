package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

func historyCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

// TestExamplesHistory_ShowsEveryGenerationAndMarksTheServedOne is the read
// surface of the example ledger. An overwriting store could not answer this at
// all: the earlier extraction was destroyed by the later one.
func TestExamplesHistory_ShowsEveryGenerationAndMarksTheServedOne(t *testing.T) {
	coord := historyCoord(t)
	uc := testfakes.NewFakeQueryExamples()

	older := exdomain.ExampleRecord{
		Coordinate:       coord,
		OverallStatus:    exdomain.ExampleStatusFound,
		ParseFailures:    []exdomain.ParseFailure{{File: "a_test.go", Error: "boom"}},
		ExtractedAt:      time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		ContentHash:      "sha256:older",
		ArtefactIdentity: "zip:h1:abc=",
	}
	newer := exdomain.ExampleRecord{
		Coordinate:    coord,
		OverallStatus: exdomain.ExampleStatusFound,
		ExtractedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		ContentHash:   "sha256:newer",
		// Deliberately no artefact identity, to pin that the renderer says so
		// rather than printing an empty column.
	}
	uc.SetHistory(coord, exapp.PipelineVersion, []exdomain.ExampleRecord{older, newer})
	uc.AddRecord(coord, exapp.PipelineVersion, newer)

	var stdout bytes.Buffer
	if err := runExamplesHistory(context.Background(), coord, uc, &stdout); err != nil {
		t.Fatalf("runExamplesHistory: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "2 generation(s)") {
		t.Errorf("output does not report both generations:\n%s", out)
	}
	if !strings.Contains(out, "sha256:older") || !strings.Contains(out, "sha256:newer") {
		t.Errorf("output does not name both records:\n%s", out)
	}
	if !strings.Contains(out, "* 2026-07-01T00:00:00Z") {
		t.Errorf("the served generation is not marked:\n%s", out)
	}
	if !strings.Contains(out, "1 parse failure(s)") {
		t.Errorf("the earlier generation's parse failures are not shown:\n%s", out)
	}
	if !strings.Contains(out, "(no artefact recorded)") {
		t.Errorf("a record naming no artefact prints an empty artefact rather than saying so:\n%s", out)
	}
}

// TestExamplesList_ConflictRowDoesNotDeleteTheOtherModules pins the rule the
// licence conversion found the hard way: one disputed module reported as the
// list's error denies every correct answer beside it.
func TestExamplesList_ConflictRowDoesNotDeleteTheOtherModules(t *testing.T) {
	uc := testfakes.NewFakeQueryExamples()
	uc.SetList([]exports.ExampleSummary{
		{
			ModulePath: "example.com/disputed", ModuleVersion: "v1.0.0",
			PipelineVersion: exapp.PipelineVersion,
			Conflict:        exports.ErrExampleConflict,
		},
		{
			ModulePath: "example.com/fine", ModuleVersion: "v1.0.0",
			PipelineVersion: exapp.PipelineVersion,
			OverallStatus:   exdomain.ExampleStatusFound, ExampleCount: 3,
		},
	})

	var stdout bytes.Buffer
	err := runExamplesList(context.Background(), 0, 0, uc, &stdout, io.Discard)
	if !errors.Is(err, exports.ErrExampleConflict) {
		t.Errorf("examples-list returned %v; a module in dispute must not read as a clean run", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "example.com/fine") || !strings.Contains(out, "3 example(s)") {
		t.Errorf("the healthy module was not listed:\n%s", out)
	}
	if !strings.Contains(out, "CONFLICT") || !strings.Contains(out, "--history") {
		t.Errorf("the disputed module is not reported on its own row:\n%s", out)
	}
}

// TestInterfaceHistory_ShowsTheAPIDigestPerGeneration is the read surface of the
// interface ledger. The API digest is what makes "the two records agree" or "the
// two records disagree" readable: the content hash cannot say, because it covers
// the time of measurement as well as the claim.
func TestInterfaceHistory_ShowsTheAPIDigestPerGeneration(t *testing.T) {
	coord := historyCoord(t)
	uc := testfakes.NewFakeQueryInterface()

	base := ifacedomain.InterfaceRecord{
		SchemaVersion: ifacedomain.InterfaceSchemaVersion,
		Coordinate:    coord,
		Packages: []ifacedomain.PackageInterface{{
			ImportPath: "example.com/mod",
			Funcs:      []ifacedomain.FuncDecl{{Name: "New", Signature: "func New()"}},
		}},
		OverallStatus:    ifacedomain.InterfaceStatusExtracted,
		ArtefactIdentity: "zip:h1:abc=",
	}
	older := base
	older.ExtractedAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	older.ContentHash = "sha256:older"
	newer := base
	newer.ExtractedAt = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	newer.ContentHash = "sha256:newer"

	uc.SetInterfaceHistory(coord, ifaceapp.PipelineVersion, []ifacedomain.InterfaceRecord{older, newer})
	uc.AddRecord(coord, ifaceapp.PipelineVersion, newer)

	var stdout bytes.Buffer
	if err := runInterfaceHistory(context.Background(), coord, uc, &stdout); err != nil {
		t.Fatalf("runInterfaceHistory: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "2 generation(s)") {
		t.Errorf("output does not report both generations:\n%s", out)
	}
	if !strings.Contains(out, "* 2026-07-01T00:00:00Z") {
		t.Errorf("the served generation is not marked:\n%s", out)
	}
	// Two runs a second apart that produced the identical API carry different
	// content hashes; the digest must show them agreeing anyway.
	digest := ifacedomain.APIDigest(older)
	if digest != ifacedomain.APIDigest(newer) {
		t.Fatal("the two records disagree about the API; this test no longer covers what it claims")
	}
	if strings.Count(out, digest) != 2 {
		t.Errorf("the API digest is not printed for both generations, so agreement is unreadable:\n%s", out)
	}
}

// TestInterfaceList_ConflictRowDoesNotDeleteTheOtherModules is the same rule at
// interface-list: every module is listed, the disputed one says so, and the
// command still fails.
func TestInterfaceList_ConflictRowDoesNotDeleteTheOtherModules(t *testing.T) {
	sums := []ifaceports.InterfaceSummary{
		{
			ModulePath: "example.com/disputed", ModuleVersion: "v1.0.0",
			PipelineVersion: ifaceapp.PipelineVersion,
			Conflict:        ifaceports.ErrInterfaceConflict,
		},
		{
			ModulePath: "example.com/fine", ModuleVersion: "v1.0.0",
			PipelineVersion: ifaceapp.PipelineVersion,
			OverallStatus:   ifacedomain.InterfaceStatusExtracted, PackageCount: 2,
		},
	}

	var stdout bytes.Buffer
	// The scope is the zero-result statement, and this listing returns rows, so
	// it is never read.
	err := printInterfaceList(sums, false, 0, 0, listZeroScope{}, &stdout, io.Discard)
	if !errors.Is(err, ifaceports.ErrInterfaceConflict) {
		t.Errorf("interface-list returned %v; a module in dispute must not read as a clean run", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "example.com/fine") || !strings.Contains(out, "2 package(s)") {
		t.Errorf("the healthy module was not listed:\n%s", out)
	}
	if !strings.Contains(out, "CONFLICT") || !strings.Contains(out, "--history") {
		t.Errorf("the disputed module is not reported on its own row:\n%s", out)
	}
}
