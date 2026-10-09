package local

import (
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/failurecause"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
)

// A stage whose record met a limit binding this binary is failed on this
// host's account with the shared statement, so the run cannot read as clean
// and its exit can name the remedy; once this binary clears it, it is the
// stage it always was.
func TestAdapterExtractor_AnalyserLimitFailsTheStage(t *testing.T) {
	ctx := t.Context()
	coord, _ := coordinate.NewModuleCoordinate("example.com/genmeth", "v1.0.0")
	u := gotoolchain.NewUnreadSource(gotoolchain.AnalyserLimit{Required: "go1.27.2", Built: "go1.26.6"}, []string{"genmeth.go"})
	cgDetail := "/src/genmeth.go:1:1: package requires newer Go version go1.27.2 (application built with go1.26.6)"
	stages := map[string]*AdapterExtractor{
		"interface": NewAdapterExtractor(nil, &mockInterfaceUseCase{res: ifaceapp.ExtractResult{Record: ifacedomain.InterfaceRecord{
			ContentHash: "h", OverallStatus: ifacedomain.InterfaceStatusPartial, AnalyserLimit: u,
		}}}, nil, nil, "", nil, nil),
		"example": NewAdapterExtractor(nil, nil, nil, nil, "", nil, &mockExampleUseCase{res: exapp.ExtractResult{Record: exdomain.ExampleRecord{
			ContentHash: "h", OverallStatus: exdomain.ExampleStatusFound, AnalyserLimit: u,
		}}}),
		"callgraph": newCallgraphAdapter(&fakeSubprocessExecutor{}, &fakeCallGraphReader{found: true, out: cgports.CallGraphOutcome{
			ContentHash: "h", OverallStatus: cgdomain.CallGraphStatusPartial,
			FailureCause: cgdomain.FailureCauseEnvironment, FailureDetail: cgDetail,
		}}),
	}
	for stage, a := range stages {
		restore := gotoolchain.SetAnalysingGo("go1.26.6")
		res, err := a.Extract(ctx, coord, stage, false, "")
		restore()
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if res.Status != domain.StageFailed || res.Cause != failurecause.Environment {
			t.Errorf("%s bound: status %v cause %q, want failed on the environment", stage, res.Status, res.Cause)
		}
		if l, ok := gotoolchain.ReadAnalyserLimit(res.Error); !ok || l.Required != "go1.27.2" {
			t.Errorf("%s bound: error does not carry the limit: %q", stage, res.Error)
		}

		restore = gotoolchain.SetAnalysingGo("go1.27.2")
		res, err = a.Extract(ctx, coord, stage, false, "")
		restore()
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if res.Status != domain.StageSucceeded || strings.Contains(res.Error, "cannot read") {
			t.Errorf("%s cleared: status %v error %q, want the stage it always was", stage, res.Status, res.Error)
		}
	}
}
