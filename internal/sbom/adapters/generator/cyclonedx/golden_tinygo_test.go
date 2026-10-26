package cyclonedx_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	"code.eitanity.com/kanonarion/internal/sbom/domain"
	"code.eitanity.com/kanonarion/internal/sbom/ports"

	licensedomain "code.eitanity.com/kanonarion/internal/license/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// TestGoldenByteLock_TinyGoWalk locks a TinyGo walk's document: TinyGo's own
// component with its target, packages and mixed files, the Go-served packages on
// the stdlib component, root → tinygo in the dependency graph, and TinyGo named
// in the licence-completeness statement, since its licence is not determined.
func TestGoldenByteLock_TinyGoWalk(t *testing.T) {
	root, err := coordinate.NewModuleCoordinate("example.com/wexp", coordinate.LocalVersion)
	if err != nil {
		t.Fatal(err)
	}
	std, ok := walkdomain.StdlibNode("go1.27.2")
	if !ok {
		t.Fatal("StdlibNode refused go1.27.2")
	}
	std.Packages = []string{"io", "strconv"}
	tg, ok := walkdomain.TinyGoNode("0.42.0", walkdomain.TinyGoFacts{
		Target: "wasip1", Packages: []string{"os", "runtime", "sync"},
		Mixed: map[string][]string{"sync": {"once.go", "pool.go"}},
	})
	if !ok {
		t.Fatal("TinyGoNode refused 0.42.0")
	}
	walk := walkdomain.WalkRecord{
		ID: "walk-golden-tinygo",
		Graph: walkdomain.Graph{
			Target: root,
			Nodes:  []walkdomain.GraphNode{{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule}, tg, std},
			Edges:  []walkdomain.GraphEdge{{From: root, To: tg.Coordinate}, {From: root, To: std.Coordinate}},
			BuildEnv: walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm", GoVersion: "go1.27.2",
				TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0", TinyGoTags: []string{"tinygo.wasm", "tinygo"}},
			ResolvedAt: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC),
		},
	}
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		root: {PrimarySPDX: "MIT", ExtractedAt: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)},
	}
	rec, err := cyclonedx.New("0.3.0-test").Generate(t.Context(), walk, licenses, ports.GenerateRequest{
		Format: domain.CycloneDX16, PipelineVersion: "0.3.0-test", Operator: "golden",
		DocumentTimestamp: time.Date(2026, 10, 18, 9, 15, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const golden = "testdata/golden_sbom_tinygo.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if werr := os.WriteFile(golden, rec.Content, 0o600); werr != nil {
			t.Fatalf("writing golden: %v", werr)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(rec.Content, want) {
		t.Errorf("TinyGo document drifted from %s (len got=%d want=%d)", golden, len(rec.Content), len(want))
	}
	if !rec.LicensesIncomplete {
		t.Error("LicensesIncomplete = false; TinyGo's component carries no licence identity")
	}
}
