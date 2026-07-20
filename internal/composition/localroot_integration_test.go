package composition_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/driver"

	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const mitLicenceText = `MIT License

Copyright (c) 2026 Example Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

// writeProject writes a dependency-free Go module working tree.
func writeProject(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":  "module example.test/proj\n\ngo 1.22\n",
		"lib.go":  source,
		"LICENSE": mitLicenceText,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

// A local walk→extract with AnalyseLocalRoot produces real per-stage records
// for the project's OWN packages: the root arrives at extraction promoted to
// ResolutionLocalAnalysed, the licence record is marked as the project's
// outbound declaration, and re-running over an edited tree reflects the edit
// (no stale cached record is ever served for the root).
func TestLocalWalkExtract_AnalyseLocalRoot_EndToEnd(t *testing.T) {
	storeRoot := t.TempDir()
	projDir := writeProject(t, "// Package proj is the project root.\npackage proj\n\n// Answer returns 42.\nfunc Answer() int { return 42 }\n")

	drv, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	defer func() { _ = cleanup() }()

	ctx := context.Background()
	root := coordinate.ModuleCoordinate{Path: "example.test/proj", Version: coordinate.LocalVersion}
	// The dependency-free project keeps the test offline. Callgraph is excluded
	// here because the extract pipeline now spawns the kanonarion binary as a
	// subprocess for that stage; in-process test runs don't have a real binary
	// available. End-to-end callgraph coverage lives in the txtar suite.
	stages := []string{"license", "interface", "example"}

	res, err := drv.LocalWalkExtract.Run(ctx, driver.LocalWalkExtractRequest{
		Dir:              projDir,
		Stages:           stages,
		AnalyseLocalRoot: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Root node promoted to local_analysed in the walk record.
	var rootNode walkdomain.GraphNode
	found := false
	for _, n := range res.Walk.Graph.Nodes {
		if n.Coordinate == root {
			rootNode, found = n, true
		}
	}
	if !found {
		t.Fatalf("root node missing from walk graph")
	}
	if rootNode.ResolutionSource != walkdomain.ResolutionLocalAnalysed {
		t.Errorf("root resolution = %s, want local_analysed", rootNode.ResolutionSource)
	}

	// Every requested stage produced a real (succeeded, not skipped) record
	// for the project's own packages.
	modRes, ok := res.Extraction.PerModuleResults[root]
	if !ok {
		t.Fatalf("no extraction result for root %s", root)
	}
	for _, stage := range stages {
		sr, ok := modRes.Stages[stage]
		if !ok {
			t.Errorf("stage %s missing for root", stage)
			continue
		}
		if sr.Status.String() != "succeeded" {
			t.Errorf("stage %s = %s (%s), want succeeded", stage, sr.Status, sr.Error)
		}
	}

	queries, qcleanup, err := composition.NewQueries(storeRoot)
	if err != nil {
		t.Fatalf("NewQueries: %v", err)
	}
	defer func() { _ = qcleanup() }()

	// The root licence record is the project's own outbound declaration.
	licRec, found, err := queries.License.GetLicenseRecord(ctx, root, licapp.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("GetLicenseRecord: found=%v err=%v", found, err)
	}
	if licRec.Role != licdomain.LicenseRoleRootDeclaration {
		t.Errorf("licence Role = %q, want %q", licRec.Role, licdomain.LicenseRoleRootDeclaration)
	}
	if licRec.PrimarySPDX != "MIT" {
		t.Errorf("licence PrimarySPDX = %q, want MIT", licRec.PrimarySPDX)
	}

	// FRESHNESS: edit the tree, re-run, and the new symbol must appear — no
	// stale cached record for the root is ever served.
	edited := "// Package proj is the project root.\npackage proj\n\n// Answer returns 42.\nfunc Answer() int { return 42 }\n\n// Extra is new.\nfunc Extra() string { return \"new\" }\n"
	if err := os.WriteFile(filepath.Join(projDir, "lib.go"), []byte(edited), 0o600); err != nil {
		t.Fatalf("editing lib.go: %v", err)
	}
	if _, err := drv.LocalWalkExtract.Run(ctx, driver.LocalWalkExtractRequest{
		Dir:              projDir,
		Stages:           []string{"interface"},
		AnalyseLocalRoot: true,
	}); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	ifaceRec, found, err := queries.Interface.GetInterfaceRecord(ctx, root, ifaceapp.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("GetInterfaceRecord: found=%v err=%v", found, err)
	}
	gotExtra := false
	for _, p := range ifaceRec.Packages {
		for _, f := range p.Funcs {
			if f.Name == "Extra" {
				gotExtra = true
			}
		}
	}
	if !gotExtra {
		t.Error("interface record does not contain Extra after editing the tree; a stale root record was served")
	}
}

// Default off: without AnalyseLocalRoot the root stays skipped-with-reason
// and no record is fabricated for it.
func TestLocalWalkExtract_DefaultRootStaysSkipped(t *testing.T) {
	storeRoot := t.TempDir()
	projDir := writeProject(t, "package proj\n")

	drv, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	defer func() { _ = cleanup() }()

	root := coordinate.ModuleCoordinate{Path: "example.test/proj", Version: coordinate.LocalVersion}
	res, err := drv.LocalWalkExtract.Run(context.Background(), driver.LocalWalkExtractRequest{
		Dir:    projDir,
		Stages: []string{"license"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	modRes, ok := res.Extraction.PerModuleResults[root]
	if !ok {
		t.Fatalf("no extraction result for root %s", root)
	}
	if sr := modRes.Stages["license"]; sr.Status.String() != "skipped" {
		t.Errorf("license stage = %s, want skipped when root analysis is off", sr.Status)
	}
}
