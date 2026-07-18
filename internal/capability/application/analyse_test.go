package application

import (
	"context"
	"errors"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

type fakeSource struct {
	records map[string]cgdomain.CallGraphRecord
	err     error
}

func (f fakeSource) GetCallGraphRecord(_ context.Context, coord fetchdomain.ModuleCoordinate, _ string) (cgdomain.CallGraphRecord, bool, error) {
	if f.err != nil {
		return cgdomain.CallGraphRecord{}, false, f.err
	}
	rec, ok := f.records[coord.Path+"@"+coord.Version]
	return rec, ok, nil
}

func coord(t *testing.T, path, version string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func recordWithHTTP() cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			{ID: "m.Root", Package: "m", Symbol: "Root", IsExportedAPI: true},
			{ID: "net/http.Get", Package: "net/http", Symbol: "Get", IsExternal: true},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "m.Root", ToID: "net/http.Get", Confidence: cgdomain.ConfidenceDirect},
		},
	}
}

func TestAnalyseReturnsReport(t *testing.T) {
	src := fakeSource{records: map[string]cgdomain.CallGraphRecord{
		"m@v1.0.0": recordWithHTTP(),
	}}
	uc := NewAnalyseCapabilitiesUseCase(src)
	report, err := uc.Analyse(context.Background(), coord(t, "m", "v1.0.0"), "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	caps := report.Capabilities()
	if len(caps) != 1 || caps[0] != capdomain.CapabilityNetwork {
		t.Errorf("caps = %v, want [NETWORK]", caps)
	}
}

func TestAnalyseNotFound(t *testing.T) {
	uc := NewAnalyseCapabilitiesUseCase(fakeSource{records: map[string]cgdomain.CallGraphRecord{}})
	_, err := uc.Analyse(context.Background(), coord(t, "m", "v1.0.0"), "0.1.0")
	if !errors.Is(err, ErrNoCallGraph) {
		t.Errorf("err = %v, want ErrNoCallGraph", err)
	}
}

func TestAnalyseStoreError(t *testing.T) {
	sentinel := errors.New("boom")
	uc := NewAnalyseCapabilitiesUseCase(fakeSource{err: sentinel})
	_, err := uc.Analyse(context.Background(), coord(t, "m", "v1.0.0"), "0.1.0")
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

func TestDiffTwoVersions(t *testing.T) {
	withExec := recordWithHTTP()
	withExec.Nodes = append(withExec.Nodes, cgdomain.CallNode{ID: "os/exec.Command", Package: "os/exec", Symbol: "Command", IsExternal: true})
	withExec.Edges = append(withExec.Edges, cgdomain.CallEdge{FromID: "m.Root", ToID: "os/exec.Command", Confidence: cgdomain.ConfidenceDirect})

	src := fakeSource{records: map[string]cgdomain.CallGraphRecord{
		"m@v1.0.0": recordWithHTTP(),
		"m@v1.1.0": withExec,
	}}
	uc := NewAnalyseCapabilitiesUseCase(src)
	_, _, diff, err := uc.Diff(context.Background(), coord(t, "m", "v1.0.0"), coord(t, "m", "v1.1.0"), "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Added) != 1 || diff.Added[0] != capdomain.CapabilityExec {
		t.Errorf("Added = %v, want [EXEC]", diff.Added)
	}
	if !diff.ParityOK {
		t.Error("both Extracted → parity OK")
	}
}

func TestDiffFromError(t *testing.T) {
	uc := NewAnalyseCapabilitiesUseCase(fakeSource{records: map[string]cgdomain.CallGraphRecord{
		"m@v1.1.0": recordWithHTTP(),
	}})
	_, _, _, err := uc.Diff(context.Background(), coord(t, "m", "v1.0.0"), coord(t, "m", "v1.1.0"), "0.1.0")
	if !errors.Is(err, ErrNoCallGraph) {
		t.Errorf("err = %v, want ErrNoCallGraph for missing 'from'", err)
	}
}

func TestDiffToError(t *testing.T) {
	uc := NewAnalyseCapabilitiesUseCase(fakeSource{records: map[string]cgdomain.CallGraphRecord{
		"m@v1.0.0": recordWithHTTP(),
	}})
	_, _, _, err := uc.Diff(context.Background(), coord(t, "m", "v1.0.0"), coord(t, "m", "v1.1.0"), "0.1.0")
	if !errors.Is(err, ErrNoCallGraph) {
		t.Errorf("err = %v, want ErrNoCallGraph for missing 'to'", err)
	}
}
