package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	coordinatetest "code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	vulndomain "code.eitanity.com/kanonarion/internal/vuln/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

func tinyGoWalkRecord(t *testing.T) walkdomain.WalkRecord {
	t.Helper()
	std, ok := walkdomain.StdlibNode("go1.27.2")
	if !ok {
		t.Fatal("StdlibNode refused go1.27.2")
	}
	std.Packages = []string{"io", "strconv", "time"}
	tg, ok := walkdomain.TinyGoNode("0.42.0", walkdomain.TinyGoFacts{Target: "wasip1", Packages: []string{"os", "runtime"}})
	if !ok {
		t.Fatal("TinyGoNode refused 0.42.0")
	}
	return walkdomain.WalkRecord{Graph: walkdomain.Graph{
		Nodes:    []walkdomain.GraphNode{tg, std},
		BuildEnv: walkdomain.BuildEnv{GoVersion: "go1.27.2", TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0"},
	}}
}

const wantTinyGoToolchainLine = "tinygo 0.42.0: no advisory source kanonarion reads covers TinyGo; 2 of 5 standard packages in this build are TinyGo's"

func TestToolchainLine_TinyGoIsStatedBesideGoAndNeverJudged(t *testing.T) {
	j := vulndomain.JudgeToolchain("go1.27.2", testSnapshot(t), vulndomain.ToolchainAdvisorySet{KeyPresent: true})
	j.TinyGo = &vulndomain.TinyGoToolchain{Version: "0.42.0", TinyGoPackages: 2, StandardPackages: 5}

	got := toolchainOutput(t, j)
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "  go1.27.2:") || lines[2] != "  "+wantTinyGoToolchainLine {
		t.Errorf("toolchain block =\n%s", got)
	}

	section := toolchainSectionOf(j)
	if strings.Contains(section.Statement, "tinygo") {
		t.Errorf("the Go statement carries the TinyGo line: %q", section.Statement)
	}
	tg := section.TinyGo
	if tg == nil || tg.Judged || tg.Status != string(vulndomain.ToolchainUnjudged) || tg.Version != "0.42.0" ||
		tg.Reason != vulndomain.TinyGoToolchainReason || tg.Statement != wantTinyGoToolchainLine ||
		tg.Covering == nil || tg.WithdrawnCovering == nil || tg.Snapshot != section.Snapshot {
		t.Errorf("TinyGo section = %+v", tg)
	}
}

func TestToolchainLine_AHostWalkHasNoTinyGoLine(t *testing.T) {
	j := vulndomain.JudgeToolchain("go1.27.2", testSnapshot(t), vulndomain.ToolchainAdvisorySet{KeyPresent: true})
	if got := toolchainOutput(t, j); strings.Contains(got, "tinygo") {
		t.Errorf("a host walk printed a TinyGo line:\n%s", got)
	}
	data, err := json.Marshal(toolchainSectionOf(j))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "tinygo") {
		t.Errorf("a host walk's toolchain section carries a TinyGo key: %s", data)
	}
}

func TestJudgeWalkToolchain_ReadsTheTinyGoNode(t *testing.T) {
	j := judgeWalkToolchain(t.Context(), &Container{}, tinyGoWalkRecord(t), testSnapshot(t))
	if j.TinyGo == nil || *j.TinyGo != (vulndomain.TinyGoToolchain{Version: "0.42.0", TinyGoPackages: 2, StandardPackages: 5}) {
		t.Errorf("TinyGo judgment = %+v", j.TinyGo)
	}
	if j.Status != vulndomain.ToolchainUnjudged || j.Version != "go1.27.2" {
		t.Errorf("the Go half moved: %+v", j)
	}
}

func TestNativeCoverageSummary_TinyGoBlockFollowsTheNativeLines(t *testing.T) {
	roll := withTinyGoCode(&nativeWalkRollup{NotExamined: 2}, tinyGoWalkRecord(t))

	var out bytes.Buffer
	if err := writeNativeCoverageSummary(&out, roll); err != nil {
		t.Fatalf("writeNativeCoverageSummary: %v", err)
	}
	got := out.String()
	block := "tinygo code: 2 of 5 standard-library package(s) in this build are TinyGo's code, covered by no advisory source kanonarion reads; " +
		"3 are Go's and are judged against Go's advisories\n  os runtime\n"
	if !strings.HasSuffix(got, block) || !strings.HasPrefix(got, "native code:") {
		t.Errorf("coverage block =\n%s", got)
	}
	data, err := json.Marshal(roll)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"tinygo":{"version":"0.42.0","target":"wasip1","standard_packages":5,"tinygo_packages":["os","runtime"],"go_packages":["io","strconv","time"]}`) {
		t.Errorf("rollup JSON = %s", data)
	}
}

func TestNativeCoverageSummary_HostWalkUnchanged(t *testing.T) {
	host := walkdomain.WalkRecord{}
	roll := withTinyGoCode(&nativeWalkRollup{NotExamined: 1}, host)
	data, err := json.Marshal(roll)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "tinygo") {
		t.Errorf("a host walk's rollup carries a TinyGo key: %s", data)
	}
	if withTinyGoCode(nil, tinyGoWalkRecord(t)) != nil {
		t.Error("a rollup the producer does not derive gained one")
	}
}

func TestVulnScanResult_InconclusiveIsItsOwnSectionAndWord(t *testing.T) {
	std := coordinatetest.MustNew(vulndomain.StdlibModulePath, "v1.27.2")
	rec := vulndomain.VulnerabilityRecord{
		Coordinate: std, OverallStatus: vulndomain.StatusInconclusive,
		Findings: vulndomain.PartitionTinyGoFindings([]vulndomain.VulnerabilityFinding{
			{ID: "GO-OS", Summary: "os bug", AffectedPackages: []string{"os"}},
		}, vulndomain.TinyGoSupply{TinyGo: []string{"os"}}),
	}
	r := newVulnScanRollups()
	r.add(std, rec)
	if len(r.inconclusive) != 1 || len(r.affected) != 0 || len(r.withdrawn) != 0 {
		t.Fatalf("rollups = %+v", r)
	}
	var out bytes.Buffer
	run := vulndomain.WalkScanRun{ID: "run-1", CoverageStatus: vulndomain.CoverageComplete, FindingsStatus: vulndomain.FindingsInconclusive,
		Counts: vulndomain.WalkScanCounts{Inconclusive: 1}}
	if err := printVulnScanResult(run, r.affected, r.withdrawn, r.inconclusive, r.failed, r.unscannable,
		vulnScanReachability{}, vulnScanToolchainJSON{}, nil, false, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Not established under the TinyGo frame (1 module(s), counted neither as findings nor as clean):",
		"    GO-OS: TinyGo supplies os; Go's affected range describes Go's code — os bug",
		"Scan completed: Complete, Inconclusive (1 module(s) not established)  Run ID: run-1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Findings (") {
		t.Errorf("a not-established module was listed as a finding:\n%s", out.String())
	}
}

func TestScanCompletionSummary_NamesTheModulesNotEstablished(t *testing.T) {
	affected := vulndomain.WalkScanRun{CoverageStatus: vulndomain.CoverageComplete, FindingsStatus: vulndomain.FindingsAffected,
		Counts: vulndomain.WalkScanCounts{Affected: 1, Inconclusive: 1}}
	if got := scanCompletionSummary(affected); got != "Complete, Affected (1), 1 module(s) not established" {
		t.Errorf("affected = %q", got)
	}
	clean := vulndomain.WalkScanRun{CoverageStatus: vulndomain.CoverageComplete, FindingsStatus: vulndomain.FindingsClean}
	if got := scanCompletionSummary(clean); got != "Complete, Clean" {
		t.Errorf("a run with nothing not established changed its line: %q", got)
	}
}

func TestVulnScanStatusLabel_InconclusiveUnderACoverageGap(t *testing.T) {
	rec := vulndomain.VulnerabilityRecord{
		Coordinate:   coordinatetest.MustNew(vulndomain.StdlibModulePath, "v1.27.2"),
		UnscanReason: vulndomain.UnscanReasonProjectBuildDiverged, UnscannableReason: "diverged",
		Findings: []vulndomain.VulnerabilityFinding{{ID: "a", NotEstablished: true}},
	}
	if got := vulnScanStatusLabel(rec); !strings.HasPrefix(got, "Inconclusive — ") {
		t.Errorf("label = %q", got)
	}
}

func TestAuditDependencyNodes_TinyGoIsNoModuleRow(t *testing.T) {
	rec := tinyGoWalkRecord(t)
	for _, n := range auditDependencyNodes(rec, coordinatetest.MustNew("example.com/wexp", "local")) {
		if n.ResolutionSource == walkdomain.ResolutionTinyGo {
			t.Errorf("audit lists TinyGo's node as a module row: %s", n.Coordinate)
		}
	}
	if got := len(auditDependencyNodes(rec, coordinatetest.MustNew("example.com/wexp", "local"))); got != 1 {
		t.Errorf("rows = %d, want the stdlib node alone", got)
	}
}
