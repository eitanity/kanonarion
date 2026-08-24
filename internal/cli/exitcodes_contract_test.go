package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	extractdomain "github.com/eitanity/kanonarion/internal/extract/domain"
	sbomdomain "github.com/eitanity/kanonarion/internal/sbom/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The exit-code taxonomy is a compatibility surface: an automation caller
// branches on the number, not on the prose, so a code that drifts breaks a
// script silently. These tests pin one code per failure class per command.
//
// They are deliberately organised by CLASS rather than by command. The defect
// this guards against is not "command X returned the wrong code" but "two
// commands answered the same question with two different codes" — which is
// exactly how the not-found class came to be split between 4 and 20, with one
// site's comment explaining why the distinction mattered while its neighbour
// ignored it.

// exitCase is one command's response to one failure class.
type exitCase struct {
	name string
	want int
	run  func(t *testing.T) error
}

func runExitCases(t *testing.T, cases []exitCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil {
				t.Fatalf("want a failure carrying exit %d, got nil", tc.want)
			}
			var ee *exitError
			if !errors.As(err, &ee) {
				t.Fatalf("want *exitError carrying %d, got a plain error that falls through to ExitConfig(%d): %v",
					tc.want, ExitConfig, err)
			}
			if ee.code != tc.want {
				t.Errorf("want exit %d, got %d (%q)", tc.want, ee.code, ee.msg)
			}
			// The carrier must survive ExitCodeForError, which is what main
			// actually calls — a correct code on the chain is worthless if the
			// mapping drops it.
			if got := ExitCodeForError(err); got != tc.want {
				t.Errorf("ExitCodeForError: want %d, got %d", tc.want, got)
			}
		})
	}
}

// ---- class: the record you named does not exist -> ExitNotFound(4) ---------

func TestExitCodeContract_MissingRecordIsNotFound(t *testing.T) {
	const missingWalk = "01JWALKMISSING0000000001"
	coord := coordinatetest.MustNew("example.com/m", "v1.0.0")

	// A walk store that knows no walks: GetWalk returns ErrWalkNotFound and
	// ListWalks returns nothing, which is the shape every one of these
	// commands meets when the operator names an ID that was never written.
	emptyWalks := testfakes.NewFakeQueryWalks

	runExitCases(t, []exitCase{
		{"walk-show", ExitNotFound, func(t *testing.T) error {
			return runWalkShow(context.Background(), missingWalk, emptyWalks(), &bytes.Buffer{}, io.Discard)
		}},
		{"walk-diff", ExitNotFound, func(t *testing.T) error {
			return runWalkDiff(context.Background(), missingWalk, missingWalk,
				&testfakes.FakeDiffWalks{Err: walkports.ErrWalkNotFound}, emptyWalks(), &bytes.Buffer{}, io.Discard)
		}},
		{"walk-list --walk-id", ExitNotFound, func(t *testing.T) error {
			return runWalkList(context.Background(), "", "", "", "", missingWalk, 0, 0, false, false,
				emptyWalks(), &bytes.Buffer{}, &bytes.Buffer{})
		}},
		// --latest-success names one record too — the most recent succeeded
		// walk — and answered its absence with a bare error that landed on the
		// invocation-error catch-all. Nothing was malformed about the request:
		// the record it selects is not there, which is the same class as every
		// other selector above.
		{"walk-list --latest-success", ExitNotFound, func(t *testing.T) error {
			return runWalkList(context.Background(), "", "", "succeeded", "", "", 1, 0, false, true,
				emptyWalks(), &bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"directives show", ExitNotFound, func(t *testing.T) error {
			return directivesShowWith(context.Background(),
				&Container{QueryDirectives: &testfakes.FakeQueryDirectives{}}, "missing-scan",
				&bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"vuln-snapshot-show", ExitNotFound, func(t *testing.T) error {
			return runSnapshotShow(context.Background(), "govulndb", "v9999-01-01T00-00-00", false,
				testfakes.NewFakeQueryScanRuns(), &bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"vuln-show --walk-id (walk never scanned)", ExitNotFound, func(t *testing.T) error {
			return runVulnShow(context.Background(), coord.String(), missingWalk, "", false, false, false,
				testfakes.NewFakeQueryVuln(), testfakes.NewFakeQueryScanRuns(), emptyWalks(), nil, &bytes.Buffer{})
		}},
		{"vuln-show (no record at all)", ExitNotFound, func(t *testing.T) error {
			return runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
				testfakes.NewFakeQueryVuln(), testfakes.NewFakeQueryScanRuns(), emptyWalks(), nil, &bytes.Buffer{})
		}},
		{"vuln-show --history", ExitNotFound, func(t *testing.T) error {
			return runVulnShow(context.Background(), coord.String(), "", "", false, false, true,
				testfakes.NewFakeQueryVuln(), testfakes.NewFakeQueryScanRuns(), emptyWalks(), nil, &bytes.Buffer{})
		}},
		{"scan-show", ExitNotFound, func(t *testing.T) error {
			return runScanShow(context.Background(), "vscan-missing", false,
				testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryVuln(), nil, &bytes.Buffer{}, io.Discard)
		}},
		{"scan-show (a run this build cannot serve in full)", ExitNotFound, func(t *testing.T) error {
			// The run itself is found; what is not served is part of its body. A
			// header asserting a verdict over modules this build cannot read is not
			// a success, and the code has to say so on the same terms as a record
			// that is missing outright.
			run, _ := fixtureRunAndRec(t)
			run.PipelineVersion = "v1"
			runs := testfakes.NewFakeQueryScanRuns()
			runs.AddRun(run)
			vuln := testfakes.NewFakeQueryVuln()
			vuln.SetRecordGenerations(mustVulnCoord(t, "example.com/app", "v1.0.0"),
				[]vulnports.VulnerabilityRecordGeneration{{PipelineVersion: "v1", Records: 1, Findings: 0}})
			return runScanShow(context.Background(), fixtureScanID, false, runs, vuln, nil, &bytes.Buffer{}, io.Discard)
		}},
		{"license-compat (no walk record)", ExitNotFound, func(t *testing.T) error {
			return licenseCompatWith(context.Background(),
				&Container{QueryWalks: emptyWalks()}, coord, "Apache-2.0", "", &bytes.Buffer{}, io.Discard)
		}},
	})
}

// Every command that reads a walk by ID must answer a missing one identically.
// This is the specific drift that was measured: verification-coverage carried a
// comment explaining why the not-found code exists, and its neighbour dependents
// returned ExitConfig for the same condition three files away.
func TestExitCodeContract_WalkByIDAgreesAcrossCommands(t *testing.T) {
	const missingWalk = "01JWALKMISSING0000000001"

	for name, err := range map[string]error{
		"walk-show": runWalkShow(context.Background(), missingWalk, testfakes.NewFakeQueryWalks(), &bytes.Buffer{}, io.Discard),
		"walk-diff": runWalkDiff(context.Background(), missingWalk, missingWalk,
			&testfakes.FakeDiffWalks{Err: walkports.ErrWalkNotFound}, testfakes.NewFakeQueryWalks(), &bytes.Buffer{}, io.Discard),
		"walk-list --walk-id": runWalkList(context.Background(), "", "", "", "", missingWalk, 0, 0, false, false,
			testfakes.NewFakeQueryWalks(), &bytes.Buffer{}, &bytes.Buffer{}),
		"verification-coverage": runVerificationCoverage(context.Background(), missingWalk,
			testfakes.NewFakeQueryWalks(), fakeFetchRecords{}, false, &bytes.Buffer{}, io.Discard),
	} {
		if code := ExitCodeForError(err); code != ExitNotFound {
			t.Errorf("%s answers a missing walk with exit %d; every walk-by-ID read must answer %d",
				name, code, ExitNotFound)
		}
	}
}

// ---- class: a policy gate fired on real findings -> ExitPolicy(5) ----------

// Every governance gate reports the same class, so a CI step can branch once on
// 5 rather than knowing which of the five commands it happened to run. These
// exercise the pure blocking-error functions: the gate decision is what carries
// the code, and it is testable without a store.
func TestExitCodeContract_FiredGateIsPolicy(t *testing.T) {
	runExitCases(t, []exitCase{
		{"directives", ExitPolicy, func(t *testing.T) error {
			return directivesBlockingErr(directivesSection{
				Directives: []directiveResult{{Kind: "replace", OldPath: "example.com/m", Classification: "local-path", PolicyBlocking: true}},
			})
		}},
		{"godebug", ExitPolicy, func(t *testing.T) error {
			return godebugBlockingErr(godebugSection{
				Settings: []godebugResult{{Setting: "x509negativeserial", Value: "1", Classification: "red", PolicyBlocking: true}},
			})
		}},
		{"vendor", ExitPolicy, func(t *testing.T) error {
			return vendorBlockingErr(vendorSection{
				Findings: []vendorFinding{{Kind: "drift", Module: "example.com/m", PolicyBlocking: true}},
			})
		}},
		{"fips", ExitPolicy, func(t *testing.T) error {
			return fipsBlockingErr(fipsSection{
				Findings: []fipsFindingResult{{Kind: "algorithm", Package: "crypto/md5", Module: "example.com/m", PolicyBlocking: true}},
			})
		}},
		{"audit", ExitPolicy, func(t *testing.T) error {
			return auditBlockingErr([]auditModuleResult{{Coordinate: "example.com/m@v1.0.0", PolicyBlocking: true}})
		}},
	})
}

// A gate that did NOT fire returns nil, not a zero-valued exitError: the
// difference between "no findings" and "exit 0 carrier" is what keeps a clean
// run from being reported as a graded one.
func TestExitCodeContract_UnfiredGateIsNil(t *testing.T) {
	for name, err := range map[string]error{
		"directives": directivesBlockingErr(directivesSection{}),
		"godebug":    godebugBlockingErr(godebugSection{}),
		"vendor":     vendorBlockingErr(vendorSection{}),
		"fips":       fipsBlockingErr(fipsSection{}),
		"audit":      auditBlockingErr(nil),
	} {
		if err != nil {
			t.Errorf("%s: an unfired gate must return nil, got %v", name, err)
		}
	}
}

// ---- class: the artefact was produced but is known-incomplete -> ExitPartial(1)

// An SBOM whose components do not all carry a licence identity is written and
// then fails. The document exists — a consumer can read what is missing — and the
// exit code is what a release step branches on, so this code is the whole reason
// a licence-less artefact cannot be published by a pipeline that checks it.
func TestExitCodeContract_IncompleteArtefactIsPartial(t *testing.T) {
	runExitCases(t, []exitCase{
		{"sbom with a component carrying no licence identity", ExitPartial, func(t *testing.T) error {
			ctr := &Container{GenerateSBOM: &testfakes.FakeGenerateSBOM{
				Result: sbomdomain.SBOMRecord{
					ID:                 "S1",
					Content:            []byte(`{"components":[{"name":"example.com/mod","version":"v1.0.0"}]}`),
					LicensesIncomplete: true,
				},
			}}
			var stdout bytes.Buffer
			return sbomGenerateWith(context.Background(), ctr, "W1",
				sbomFlags{format: "cyclonedx-1.6", operator: "tester"}, time.Time{}, &stdout, io.Discard)
		}},
		// An extraction run recorded partial has left named modules' public API
		// permanently unmeasured, and the stages that did run are stored. Same
		// class as the SBOM above, and it answered 0 — so a CI step running the
		// documented pipeline step passed green over it.
		{"extract with a failed stage", ExitPartial, func(_ *testing.T) error {
			return extractionExit(extractdomain.ExtractionRun{
				ID:            "01EXTRACTRUN00000000000001",
				OverallStatus: extractdomain.ExtractionRunPartial,
				PerModuleResults: map[coordinate.ModuleCoordinate]extractdomain.ModuleExtractionResult{
					coordinatetest.MustNew("example.com/mod", "v1.0.0"): {
						Stages: map[string]extractdomain.StageResult{
							"interface": {Status: extractdomain.StageFailed, Error: "conflicting interface records"},
						},
					},
				},
			})
		}},
		// inspect over a dependency set some of which went unanalysed. The summary
		// IS still printed and names the gap; the table has always listed inspect
		// here, and the --gomod form answered 0.
		{"inspect --gomod over a partial closure", ExitPartial, func(_ *testing.T) error {
			return inspectExit(inspectSummaryStatus(0, 2, 0, vuldomain.WalkStatusAllClean))
		}},
		// A Partial call graph is the same artefact-with-a-hole: a graph exists,
		// and the failed packages line scopes what it does not cover.
		{"callgraph returning a Partial graph", ExitPartial, func(t *testing.T) error {
			rec := makeCGRecord(t)
			rec.OverallStatus = cgdomain.CallGraphStatusPartial
			rec.FailureDetail = "could not import example.com/plot"
			return callGraphExtractionExit(rec)
		}},
	})
}

// ---- class: the invocation was wrong -> ExitConfig(20) --------------------

// A usage error keeps ExitConfig. It shares the code with a store-schema
// refusal and a missing policy FILE, and that is the point: all three say the
// command never reached an answer. What must NOT share it is a fired gate or a
// missing record.
func TestExitCodeContract_UsageAndPreconditionsStayConfig(t *testing.T) {
	runExitCases(t, []exitCase{
		{"store schema newer than binary", ExitConfig, func(t *testing.T) error {
			return newerStoreError("/tmp/mirror.db", storeSchemaState{unknown: []string{"999_future"}})
		}},
	})
}

// A question that names no build, on a store holding the coordinate in more
// than one consumer's build, is a missing selector rather than a missing record:
// every record it could serve exists, and the invocation does not say which one
// was meant. It shares ExitConfig with the other "never got as far as an answer"
// cases, and it must never share exit 0 with an answer about another project.
func TestExitCodeContract_AmbiguousFrameIsConfig(t *testing.T) {
	coord := twoProjectCoord(t)

	runExitCases(t, []exitCase{
		{"vuln-show, two consumer frames, no anchor", ExitConfig, func(t *testing.T) error {
			uc, walks := twoProjectFakes(t)
			return runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
				uc, testfakes.NewFakeQueryScanRuns(), walks, nil, &bytes.Buffer{})
		}},
		{"reachability, two consumer frames, no anchor", ExitConfig, func(t *testing.T) error {
			uc, walks := twoProjectFakes(t)
			return runVulnReachability(context.Background(), coord.String(), twoProjectVulnID, "", "", false, false,
				uc, walks, nil, &bytes.Buffer{})
		}},
		{"vuln-show, --walk-id and --gomod together", ExitConfig, func(t *testing.T) error {
			uc, walks := twoProjectFakes(t)
			return runVulnShow(context.Background(), coord.String(), walkA, "./go.mod", true, false, false,
				uc, testfakes.NewFakeQueryScanRuns(), walks, nil, &bytes.Buffer{})
		}},
	})
}

// A pin the store cannot answer in the pinned build's own frame is the
// not-found class: the walk exists, the module was covered, and the record the
// question asks for is not there. Serving a neighbouring frame instead would be
// exit 0 with another build's verdict — which is the defect, not the code.
func TestExitCodeContract_PinnedFrameWithNoRecordIsNotFound(t *testing.T) {
	coord := twoProjectCoord(t)

	runExitCases(t, []exitCase{
		{"vuln-show --walk-id (walk holds no record in its own frame)", ExitNotFound, func(t *testing.T) error {
			uc, walks := twoProjectFakes(t)
			return runVulnShow(context.Background(), coord.String(), walkC, "", false, false, false,
				uc, testfakes.NewFakeQueryScanRuns(), walks, nil, &bytes.Buffer{})
		}},
		{"reachability --walk-id (walk holds no record in its own frame)", ExitNotFound, func(t *testing.T) error {
			uc, walks := twoProjectFakes(t)
			return runVulnReachability(context.Background(), coord.String(), twoProjectVulnID, walkC, "", false, false,
				uc, walks, nil, &bytes.Buffer{})
		}},
	})
}

// The taxonomy crosses a process boundary: `extract` spawns `kanonarion
// callgraph` per module and classifies what comes back. If the child's Partial
// code and the parent's idea of it ever drift, every incompletely-analysable
// module is recorded as a failed stage while its graph sits in the store.
func TestExitCodeContract_PartialSurvivesTheProcessBoundary(t *testing.T) {
	if childproc.PartialExitCode != ExitPartial {
		t.Errorf("childproc.PartialExitCode = %d, ExitPartial = %d; the parent reads the child's exit code and the two must be one number",
			childproc.PartialExitCode, ExitPartial)
	}
}

// The three classes must not collide. This is the whole contract in one
// assertion: a script that branches on these numbers can distinguish them.
func TestExitCodeContract_ClassesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"ok": ExitOK, "partial": ExitPartial, "failed": ExitFailed,
		"cancelled": ExitCancelled, "notfound": ExitNotFound, "policy": ExitPolicy,
		"integrity": ExitIntegrity, "config": ExitConfig,
	} {
		if other, dup := seen[code]; dup {
			t.Errorf("exit code %d is shared by %q and %q; the taxonomy only works if each class has its own number",
				code, other, name)
		}
		seen[code] = name
	}
}
