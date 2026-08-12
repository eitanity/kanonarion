package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	exapplication "github.com/eitanity/kanonarion/internal/example/application"
	exdomain "github.com/eitanity/kanonarion/internal/example/domain"
	exports "github.com/eitanity/kanonarion/internal/example/ports"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The defect this file pins: a caller who names one record — a walk id, a run
// id, a module — and does not get it was told only that it is not here. The
// same sentence was printed over a store holding nothing and over a store
// holding fourteen walks, and those have different remedies: produce a record,
// or correct a value the store could have shown them.
//
// The listings and two `show` commands were fixed first; these are the
// surfaces a caller reaches with an ID already in hand, and they answered with
// three different spellings of the same miss — `walk record "X" not found`,
// `walk X not found`, and `one or both walk IDs not found`, which named neither
// of the two ids it was given.
//
// Every assertion below is on the wording the adopters already ship. Nothing
// here is a second vocabulary for the same statement.

// ---- fixtures --------------------------------------------------------------

const missingWalkID = "01NOPE"

func missTargetCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	return mustCoord(t, "example.com/app", "v1.0.0")
}

// walksWithRecords is the two-walk corpus of populatedWalkList with the walk
// records themselves, so a surface can be driven down both the found and the
// missing path against one store.
func walksWithRecords(t *testing.T) *testfakes.FakeQueryWalks {
	t.Helper()
	uc := populatedWalkList(t)
	target := missTargetCoord(t)
	dep := mustCoord(t, "example.com/dep", "v2.0.0")
	uc.AddWalk(walkdomain.WalkRecord{
		ID:             "walk-0",
		Target:         target,
		StartedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		OverallStatus:  walkdomain.WalkSucceeded,
		Scope:          walkdomain.WalkScopeCode,
		Depth:          walkdomain.WalkDepthFull,
		PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{},
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS, DirectDependency: true},
			},
			Edges: []walkdomain.GraphEdge{{From: target, To: dep}},
		},
	})
	return uc
}

// scanRunsFixture holds one run, so a miss on a run id is measured against a
// corpus that is not empty — the case a flat negative could never distinguish.
func scanRunsFixture() *testfakes.FakeQueryScanRuns {
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddRun(vulndomain.WalkScanRun{
		ID:            "vscan-real",
		WalkID:        "walk-0",
		OverallStatus: vulndomain.WalkStatusAllClean,
		CompletedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	return uc
}

// examplesFixture holds a record for the target and a listing of two, so the
// module miss below is over a populated corpus.
func examplesFixture(t *testing.T) *testfakes.FakeQueryExamples {
	t.Helper()
	uc := populatedExamplesList()
	uc.AddRecord(missTargetCoord(t), exapplication.PipelineVersion, exdomain.ExampleRecord{
		Coordinate: missTargetCoord(t),
		Examples:   []exdomain.ExampleEntry{{Name: "ExampleMain", Package: "app", Body: "{}"}},
	})
	return uc
}

// missSurface is one command that answers a named record it does not hold.
type missSurface struct {
	name string
	// miss drives the surface with a name the store does not hold and returns
	// the error it failed with and whatever it wrote to stderr.
	miss func(t *testing.T) (string, error)
	// found drives the same surface with a name it does hold, returning stderr
	// and the number of listing reads the surface made. A found record must
	// carry no statement of scope and pay no survey read.
	found func(t *testing.T) (string, int, error)
	// foundListCalls is the number of listing reads the found path legitimately
	// makes: zero for a surface that selects by id, one for a surface whose
	// selection IS a filtered listing.
	foundListCalls int
	// wantFragments are the parts of the statement this surface must carry.
	wantFragments []string
	// goneSpelling is the flat negative it used to answer with.
	goneSpelling string
}

func missSurfaces() []missSurface {
	walkStatement := []string{
		`no walk record matched walk id "01NOPE"`,
		"compared for exact equality against the walk id of all 2 walk record(s) in the store",
		"(e.g. walk-0)",
		"to list every walk record: kanonarion walk-list --limit 0",
	}
	targetStatement := func(coord string) []string {
		return []string{
			`no walk record matched target module "` + coord + `"`,
			"against the target coordinate of all 2 walk record(s) in the store",
			"to list every walk record: kanonarion walk-list --limit 0",
			"to produce one: kanonarion walk " + coord,
		}
	}
	unwalked := "example.com/never-walked@v9.9.9"

	return []missSurface{
		{
			name: "walk-show",
			miss: func(t *testing.T) (string, error) {
				var stdout, stderr bytes.Buffer
				err := runWalkShow(context.Background(), missingWalkID, walksWithRecords(t), &stdout, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := walksWithRecords(t)
				var stdout, stderr bytes.Buffer
				err := runWalkShow(context.Background(), "walk-0", uc, &stdout, &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: walkStatement,
			goneSpelling:  `walk record "01NOPE" not found`,
		},
		{
			name: "verification-coverage",
			miss: func(t *testing.T) (string, error) {
				var stdout, stderr bytes.Buffer
				err := runVerificationCoverage(context.Background(), missingWalkID, walksWithRecords(t),
					fakeFetchRecords{}, false, &stdout, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := walksWithRecords(t)
				var stdout, stderr bytes.Buffer
				err := runVerificationCoverage(context.Background(), "walk-0", uc,
					fakeFetchRecords{}, false, &stdout, &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: walkStatement,
			goneSpelling:  `walk record "01NOPE" not found`,
		},
		{
			name: "dependents --walk-id",
			miss: func(t *testing.T) (string, error) {
				ctr := &Container{QueryWalks: walksWithRecords(t)}
				var stdout, stderr bytes.Buffer
				err := dependentsWith(context.Background(), ctr, missTargetCoord(t), missingWalkID,
					false, false, false, &stdout, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := walksWithRecords(t)
				var stdout, stderr bytes.Buffer
				err := dependentsWith(context.Background(), &Container{QueryWalks: uc},
					mustCoord(t, "example.com/dep", "v2.0.0"), "walk-0", false, false, false, &stdout, &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: walkStatement,
			goneSpelling:  `walk record "01NOPE" not found`,
		},
		{
			name: "context --walk-id",
			miss: func(t *testing.T) (string, error) {
				var stderr bytes.Buffer
				_, err := contextWalkRecord(context.Background(), walksWithRecords(t), missingWalkID, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := walksWithRecords(t)
				var stderr bytes.Buffer
				_, err := contextWalkRecord(context.Background(), uc, "walk-0", &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: walkStatement,
			goneSpelling:  "walk 01NOPE not found",
		},
		{
			name: "walk-diff",
			miss: func(t *testing.T) (string, error) {
				var stdout, stderr bytes.Buffer
				err := runWalkDiff(context.Background(), "walk-0", missingWalkID,
					&testfakes.FakeDiffWalks{Err: walkports.ErrWalkNotFound}, walksWithRecords(t),
					&stdout, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := walksWithRecords(t)
				var stdout, stderr bytes.Buffer
				err := runWalkDiff(context.Background(), "walk-0", "walk-1",
					&testfakes.FakeDiffWalks{}, uc, &stdout, &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: append([]string{"the <id-b> argument named a walk the store does not hold"},
				walkStatement...),
			goneSpelling: "one or both walk IDs not found",
		},
		{
			name: "vuln-scan-show",
			miss: func(t *testing.T) (string, error) {
				var stdout, stderr bytes.Buffer
				err := runScanShow(context.Background(), "vscan-NOPE", jsonOut, scanRunsFixture(),
					testfakes.NewFakeQueryVuln(), &stdout, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := scanRunsFixture()
				var stdout, stderr bytes.Buffer
				err := runScanShow(context.Background(), "vscan-real", jsonOut, uc,
					testfakes.NewFakeQueryVuln(), &stdout, &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: []string{
				`no scan run matched run id "vscan-NOPE"`,
				"compared for exact equality against the run id of all 1 scan run(s) in the store",
				"(e.g. vscan-real)",
				"to list every scan run: kanonarion vuln-scan-list --limit 0",
			},
			goneSpelling: "scan run not found: vscan-NOPE",
		},
		{
			name: "examples-show",
			miss: func(t *testing.T) (string, error) {
				var stdout, stderr bytes.Buffer
				err := runExamplesShow(context.Background(), unwalked, "Foo", jsonOut,
					examplesFixture(t), &stdout, &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := examplesFixture(t)
				var stdout, stderr bytes.Buffer
				err := runExamplesShow(context.Background(), missTargetCoord(t).String(), "ExampleMain", jsonOut,
					uc, &stdout, &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			wantFragments: []string{
				`no example record matched module coordinate "` + unwalked + `"`,
				"against the module coordinate of all 2 example record(s) in the store",
				"to list every example record: kanonarion examples-list",
				"to produce one: kanonarion examples " + unwalked,
			},
			goneSpelling: "no example record for " + unwalked + " — run 'kanonarion examples' first",
		},
		{
			name: "use",
			miss: func(t *testing.T) (string, error) {
				var stderr bytes.Buffer
				_, err := useTargetWalk(context.Background(), walksWithRecords(t),
					mustCoord(t, "example.com/never-walked", "v9.9.9"), "", &stderr)
				return stderr.String(), err
			},
			found: func(t *testing.T) (string, int, error) {
				uc := walksWithRecords(t)
				var stderr bytes.Buffer
				_, err := useTargetWalk(context.Background(), uc, missTargetCoord(t), "", &stderr)
				return stderr.String(), uc.ListCalls, err
			},
			foundListCalls: 1,
			wantFragments:  targetStatement(unwalked),
			goneSpelling:   "no walk record found for " + unwalked + " — run 'kanonarion walk' first",
		},
		{
			name: "license-compat",
			miss: func(t *testing.T) (string, error) {
				ctr := &Container{QueryWalks: walksWithRecords(t)}
				var stdout, stderr bytes.Buffer
				err := licenseCompatWith(context.Background(), ctr,
					mustCoord(t, "example.com/never-walked", "v9.9.9"), "Apache-2.0", "", &stdout, &stderr)
				return stderr.String(), err
			},
			foundListCalls: 1,
			wantFragments:  targetStatement(unwalked),
			goneSpelling:   "no walk record found for " + unwalked,
		},
		{
			name: "license --recursive",
			miss: func(t *testing.T) (string, error) {
				var stdout, stderr bytes.Buffer
				err := printLicenseRecursive(context.Background(),
					mustCoord(t, "example.com/never-walked", "v9.9.9"), walksWithRecords(t),
					&testfakes.FakeExtractLicense{}, testfakes.NewFakeQueryLicense(), licenseFlags{},
					&stdout, &stderr)
				return stderr.String(), err
			},
			foundListCalls: 1,
			wantFragments:  targetStatement(unwalked),
			goneSpelling:   "no walk record found for " + unwalked,
		},
	}
}

// Every one of these surfaces now says what it searched, how big that corpus
// was, and the invocation that lists it — the statement the listings ship, on
// the one line an error message gets.
func TestNamedRecordMisses_StateTheCorpusTheySearched(t *testing.T) {
	for _, s := range missSurfaces() {
		t.Run(s.name, func(t *testing.T) {
			withJSON(t, false)
			stderr, err := s.miss(t)
			if err == nil {
				t.Fatal("a named record the store does not hold returned a nil error")
			}
			if code := ExitCodeForError(err); code != ExitNotFound {
				t.Errorf("exit code = %d, want %d — a record that is not there is not a malformed request",
					code, ExitNotFound)
			}
			for _, want := range s.wantFragments {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the message is missing %q, got: %v", want, err)
				}
			}
			if strings.Contains(err.Error(), s.goneSpelling) {
				t.Errorf("the flat negative survived: %v", err)
			}
			if stderr != "" {
				t.Errorf("the text path wrote a structured notice:\n%s", stderr)
			}
		})
	}
}

// The same counts reach a machine reader, on stderr, while the exit code stays
// the answer it reads first.
func TestNamedRecordMisses_TheMachineReaderGetsTheSameCounts(t *testing.T) {
	for _, s := range missSurfaces() {
		t.Run(s.name, func(t *testing.T) {
			withJSON(t, true)
			stderr, err := s.miss(t)
			if err == nil {
				t.Fatal("a named record the store does not hold returned a nil error")
			}
			notice := decodeZeroNotice(t, stderr)
			if notice.RecordsConsidered == 0 || notice.StoreEmpty {
				t.Errorf("notice = %+v, want a corpus sized from the store", notice)
			}
			if notice.Filter == nil || notice.Filter.Value == "" {
				t.Errorf("the selector that missed is not named: %+v", notice)
			}
			if len(notice.Remedy) == 0 {
				t.Errorf("notice = %+v, want an invocation that changes the answer", notice)
			}
		})
	}
}

// The known trap. Every one of these lookups succeeds far more often than it
// fails, so a corpus count hoisted above the miss branch would be paid on every
// successful walk-show in the CLI — and would keep every other test in this
// file green. This is the listings' read-count assertion extended to the
// single-record surfaces rather than imitated beside them.
//
// A surface whose selection IS a filtered listing (`use`, `license-compat`,
// `license --recursive`) legitimately reads once; one that selects by id reads
// not at all.
func TestNamedRecordMisses_FoundRecordCarriesNoNoticeAndNoSurveyRead(t *testing.T) {
	for _, s := range missSurfaces() {
		if s.found == nil {
			continue
		}
		t.Run(s.name, func(t *testing.T) {
			for _, asJSON := range []bool{false, true} {
				withJSON(t, asJSON)
				stderr, listCalls, err := s.found(t)
				if err != nil {
					t.Fatalf("json=%v: a record that is there failed: %v", asJSON, err)
				}
				if listCalls != s.foundListCalls {
					t.Errorf("json=%v: the found path read the corpus %d times, want %d — the "+
						"not-found survey is being paid on every successful lookup",
						asJSON, listCalls, s.foundListCalls)
				}
				if strings.Contains(stderr, "records_considered") ||
					strings.Contains(stderr, "the store holds no") {
					t.Errorf("json=%v: a found record carried a statement of scope:\n%s", asJSON, stderr)
				}
			}
		})
	}
}

// license-compat's found path is the one whose selection is a filtered listing
// and whose success does not return a record to the caller, so its control is
// stated against the seam fixture that already exists.
func TestLicenseCompatWith_FoundWalkPaysNoSurveyRead(t *testing.T) {
	withJSON(t, false)
	coord := compatCoord()
	ctr := containerWithWalk(coord, licdomain.ClosureCompatibilityReport{TargetSPDX: "Apache-2.0", Clean: true}, nil)
	fqw, ok := ctr.QueryWalks.(*testfakes.FakeQueryWalks)
	if !ok {
		t.Fatalf("fixture walk store is %T, not the counting fake", ctr.QueryWalks)
	}
	var stdout, stderr bytes.Buffer
	if err := licenseCompatWith(context.Background(), ctr, coord, "Apache-2.0", "", &stdout, &stderr); err != nil {
		t.Fatalf("licenseCompatWith: %v", err)
	}
	if fqw.ListCalls != 1 {
		t.Errorf("the found path read the corpus %d times, want exactly 1", fqw.ListCalls)
	}
	if strings.Contains(stderr.String(), "records_considered") {
		t.Errorf("a found walk carried a statement of scope:\n%s", stderr.String())
	}
}

// Three spellings of one miss were in use, and each taught a reader nothing
// about the next. They collapse to one sentence: every command that reads a
// walk by ID answers a missing one with the identical message, so a fourth
// cannot be introduced by a surface quietly writing its own.
//
// walk-diff is the one exception and states why in its own prefix — it took two
// operands and has to name which — so it is asserted to CONTAIN the shared
// statement rather than to equal it.
func TestWalkIDMisses_ShareOneSpelling(t *testing.T) {
	withJSON(t, false)
	shared := ""
	for _, s := range missSurfaces() {
		if !strings.Contains(s.goneSpelling, "walk") || s.name == "use" ||
			strings.HasPrefix(s.name, "license") {
			continue
		}
		if s.name == "vuln-scan-show" || s.name == "examples-show" {
			continue
		}
		_, err := s.miss(t)
		if err == nil {
			t.Fatalf("%s: a missing walk returned a nil error", s.name)
		}
		msg := err.Error()
		if s.name == "walk-diff" {
			if shared != "" && !strings.Contains(msg, shared) {
				t.Errorf("walk-diff does not carry the shared statement:\n got: %s\nwant to contain: %s",
					msg, shared)
			}
			continue
		}
		if shared == "" {
			shared = msg
			continue
		}
		if msg != shared {
			t.Errorf("%s spells the walk miss its own way:\n got: %s\nwant: %s", s.name, msg, shared)
		}
	}
	if shared == "" {
		t.Fatal("no walk-by-ID surface was exercised")
	}
}

// walk-diff was worse than flat: given one good id and one typo it said "one or
// both" and named neither, so a caller had to run walk-show twice to learn
// which of their two arguments to correct. Each side is now looked up and the
// missing one named — and when both are missing, both are.
func TestRunWalkDiff_NamesTheMissingSide(t *testing.T) {
	diffMiss := func(t *testing.T, idA, idB string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		err := runWalkDiff(context.Background(), idA, idB,
			&testfakes.FakeDiffWalks{Err: walkports.ErrWalkNotFound}, walksWithRecords(t),
			&stdout, &stderr)
		if err == nil {
			t.Fatal("a diff over a missing walk returned a nil error")
		}
		if code := ExitCodeForError(err); code != ExitNotFound {
			t.Errorf("exit code = %d, want %d", code, ExitNotFound)
		}
		return err.Error()
	}

	t.Run("the first argument", func(t *testing.T) {
		withJSON(t, false)
		msg := diffMiss(t, "01NOPE", "walk-0")
		if !strings.Contains(msg, "the <id-a> argument named a walk the store does not hold") {
			t.Errorf("the missing side is not named: %s", msg)
		}
		if !strings.Contains(msg, `walk id "01NOPE"`) {
			t.Errorf("the missing id is not named: %s", msg)
		}
		// The good id appears only as the corpus example, never as a value the
		// statement says was not matched.
		if strings.Contains(msg, `walk id "walk-0"`) {
			t.Errorf("the id that IS in the store was reported missing: %s", msg)
		}
	})

	t.Run("the second argument", func(t *testing.T) {
		withJSON(t, false)
		msg := diffMiss(t, "walk-0", "01NOPE")
		if !strings.Contains(msg, "the <id-b> argument named a walk the store does not hold") {
			t.Errorf("the missing side is not named: %s", msg)
		}
	})

	t.Run("both arguments", func(t *testing.T) {
		withJSON(t, false)
		msg := diffMiss(t, "01NOPEA", "01NOPEB")
		if !strings.Contains(msg, "both arguments named a walk the store does not hold") {
			t.Errorf("both missing sides are not named: %s", msg)
		}
		for _, id := range []string{"01NOPEA", "01NOPEB"} {
			if !strings.Contains(msg, id) {
				t.Errorf("%s is missing from the message: %s", id, msg)
			}
		}
		if strings.Contains(msg, "one or both") {
			t.Errorf("the sentence that named neither survived: %s", msg)
		}
	})

	// The corpus is the store's, not the argument list's: sizing it from the two
	// ids in hand would report a corpus of two whatever the store holds.
	t.Run("the corpus is the store, not the two operands", func(t *testing.T) {
		withJSON(t, false)
		msg := diffMiss(t, "01NOPEA", "01NOPEB")
		if !strings.Contains(msg, "all 2 walk record(s) in the store") {
			t.Errorf("the corpus is not the store's: %s", msg)
		}
		// The fixture's corpus is two walks, which is also the number of
		// operands, so the count is re-measured against a corpus of one to show
		// it follows the store.
		uc := testfakes.NewFakeQueryWalks()
		uc.SetSummaries([]walkports.WalkSummary{{ID: "only-walk", Target: missTargetCoord(t)}})
		var stdout, stderr bytes.Buffer
		err := runWalkDiff(context.Background(), "01NOPEA", "01NOPEB",
			&testfakes.FakeDiffWalks{Err: walkports.ErrWalkNotFound}, uc, &stdout, &stderr)
		if err == nil {
			t.Fatal("a diff over a missing walk returned a nil error")
		}
		if !strings.Contains(err.Error(), "all 1 walk record(s) in the store") {
			t.Errorf("the count did not follow the store: %v", err)
		}
	})
}

// The empty-store half of the statement: with nothing to compare against, the
// remedy is to produce a record rather than to correct a value, and the two
// surfaces that already carried that remedy keep it.
func TestNamedRecordMisses_EmptyStoreSaysSo(t *testing.T) {
	withJSON(t, false)

	var stdout, stderr bytes.Buffer
	err := runWalkShow(context.Background(), missingWalkID, testfakes.NewFakeQueryWalks(), &stdout, &stderr)
	if err == nil {
		t.Fatal("a missing walk over an empty store returned a nil error")
	}
	for _, want := range []string{
		`the store holds no walk record at all, so walk id "01NOPE" is not what made this empty`,
		"to produce one: kanonarion walk <module>@<version>",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message is missing %q, got: %v", want, err)
		}
	}

	stdout.Reset()
	stderr.Reset()
	unwalked := mustCoord(t, "example.com/never-walked", "v9.9.9")
	_, err = useTargetWalk(context.Background(), testfakes.NewFakeQueryWalks(), unwalked, "", &stderr)
	if err == nil {
		t.Fatal("a missing target over an empty store returned a nil error")
	}
	if !strings.Contains(err.Error(), "to produce one: kanonarion walk "+unwalked.String()) {
		t.Errorf("the remedy the flat negative carried was dropped: %v", err)
	}
}

// A miss over a populated corpus keeps the produce remedy the flat negative
// carried AND gains the one that lists the corpus. Replacing one with the other
// would have traded half the answer for the other half.
func TestNamedRecordMisses_KeepTheRemedyTheyAlreadyCarried(t *testing.T) {
	withJSON(t, true)
	unwalked := mustCoord(t, "example.com/never-walked", "v9.9.9")
	var stderr bytes.Buffer
	if _, err := useTargetWalk(context.Background(), walksWithRecords(t), unwalked, "", &stderr); err == nil {
		t.Fatal("a missing target returned a nil error")
	}
	notice := decodeZeroNotice(t, stderr.String())
	if len(notice.Remedy) != 2 {
		t.Fatalf("remedy = %v, want both the listing and the produce invocation", notice.Remedy)
	}
	if notice.Remedy[0] != "kanonarion walk-list --limit 0" ||
		notice.Remedy[1] != "kanonarion walk "+unwalked.String() {
		t.Errorf("remedy = %v, want the corpus listing then the produce invocation", notice.Remedy)
	}
}

// A survey read that fails is surfaced, not absorbed: every sentence the
// statement can render carries a count, so a corpus that could not be sized has
// nothing honest to say, and a zero substituted for a failed count would assert
// the one reading that is certainly wrong — that the store holds none.
func TestNamedRecordMisses_ASurveyThatFailsIsSurfaced(t *testing.T) {
	withJSON(t, false)
	uc := walksWithRecords(t)
	uc.ListErr = errTestSurvey
	var stdout, stderr bytes.Buffer
	err := runWalkShow(context.Background(), missingWalkID, uc, &stdout, &stderr)
	if err == nil {
		t.Fatal("a failed survey returned a nil error")
	}
	if strings.Contains(err.Error(), "holds no walk record at all") {
		t.Errorf("a failed count was reported as an empty store: %v", err)
	}
	if !strings.Contains(err.Error(), errTestSurvey.Error()) {
		t.Errorf("the survey failure was absorbed: %v", err)
	}
}

var errTestSurvey = errSurveyFailure{}

type errSurveyFailure struct{}

func (errSurveyFailure) Error() string { return "survey read refused" }

// examples-list <module> sits beside examples-show and answered with the same
// flat negative, so it adopts the same statement rather than being left as the
// one spelling of this miss the class did not reach.
func TestRunExamplesListForModule_MissStatesItsCorpus(t *testing.T) {
	withJSON(t, false)
	var stdout, stderr bytes.Buffer
	err := runExamplesListForModule(context.Background(), "example.com/never-walked@v9.9.9",
		examplesFixture(t), &stdout, &stderr)
	if err == nil {
		t.Fatal("a module with no example record returned a nil error")
	}
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Errorf("exit code = %d, want %d", code, ExitNotFound)
	}
	for _, want := range []string{
		`no example record matched module coordinate "example.com/never-walked@v9.9.9"`,
		"of all 2 example record(s) in the store",
		"to produce one: kanonarion examples example.com/never-walked@v9.9.9",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message is missing %q, got: %v", want, err)
		}
	}
}

// The corpus a run-id miss is measured against is every run in the store, not
// the runs of any one walk: a run id is not keyed on a walk, so the caller's
// walk is not what excluded it.
func TestRunScanShow_MissIsMeasuredAgainstEveryRun(t *testing.T) {
	withJSON(t, false)
	uc := scanRunsFixture()
	uc.AddRun(vulndomain.WalkScanRun{ID: "vscan-other", WalkID: "walk-1"})
	var stdout, stderr bytes.Buffer
	err := runScanShow(context.Background(), "vscan-NOPE", false, uc,
		testfakes.NewFakeQueryVuln(), &stdout, &stderr)
	if err == nil {
		t.Fatal("a missing run returned a nil error")
	}
	if !strings.Contains(err.Error(), "all 2 scan run(s) in the store") {
		t.Errorf("the corpus is not every run in the store: %v", err)
	}
}

// A guard on the fixture rather than on the code: the example-record corpus the
// statement counts is the listing, so a fixture whose listing went empty would
// make the assertions above pass for the wrong reason.
func TestExamplesFixture_HasACorpusToCount(t *testing.T) {
	all, err := examplesFixture(t).ListExampleRecords(context.Background(), exports.ExampleFilter{})
	if err != nil {
		t.Fatalf("listing example records: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("fixture corpus = %d, want 2", len(all))
	}
}

// interface-show and `interface-list <module>` are the pair beside examples-show
// in the same class, with the same flat negative, so they adopt the same
// statement rather than being left as the one spelling of this miss that
// survived. Both build their own container, so the miss is asserted on the
// function they both call — which is the whole of the behaviour.
func TestInterfaceRecordMiss_StatesItsCorpus(t *testing.T) {
	unwalked := mustCoord(t, "example.com/never-analysed", "v9.9.9")

	t.Run("text", func(t *testing.T) {
		withJSON(t, false)
		var stderr bytes.Buffer
		err := interfaceRecordMiss(context.Background(), populatedInterfaceList(), unwalked, false, &stderr)
		if err == nil {
			t.Fatal("a module with no interface record returned a nil error")
		}
		if code := ExitCodeForError(err); code != ExitNotFound {
			t.Errorf("exit code = %d, want %d", code, ExitNotFound)
		}
		for _, want := range []string{
			`no interface record matched module coordinate "example.com/never-analysed@v9.9.9"`,
			"of all 2 interface record(s) in the store",
			"to list every interface record: kanonarion interface-list",
			"to produce one: kanonarion interface example.com/never-analysed@v9.9.9",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the message is missing %q, got: %v", want, err)
			}
		}
	})

	t.Run("machine reader", func(t *testing.T) {
		withJSON(t, true)
		var stderr bytes.Buffer
		if err := interfaceRecordMiss(context.Background(), populatedInterfaceList(), unwalked, true,
			&stderr); err == nil {
			t.Fatal("a module with no interface record returned a nil error")
		}
		notice := decodeZeroNotice(t, stderr.String())
		if notice.RecordsConsidered != 2 || notice.StoreEmpty {
			t.Errorf("notice = %+v, want the interface corpus sized at 2", notice)
		}
		if len(notice.Remedy) != 2 {
			t.Errorf("remedy = %v, want the listing and the produce invocation", notice.Remedy)
		}
	})
}

// The ninth surface. The original walked-past report named
// `vuln-scan --snapshot-source/--snapshot-version`, and those flags do not
// exist on `vuln-scan` — but they do exist on `vuln-scan-rescan`, where the pin
// answered `snapshot not found: source@version` with no corpus at all. It is
// the same lookup vuln-snapshot-show makes, so it now makes the same statement.
func TestSnapshotMiss_IsOneStatementForBothSurfaces(t *testing.T) {
	uc := testfakes.NewFakeQueryScanRuns()
	uc.AddSnapshot(fixtureSnap)

	withJSON(t, false)
	var showOut, showErr bytes.Buffer
	showMiss := runSnapshotShow(context.Background(), "govulndb", "v9999-01-01T00-00-00", false,
		uc, &showOut, &showErr)
	if showMiss == nil {
		t.Fatal("a missing snapshot returned a nil error from vuln-snapshot-show")
	}

	snapshots, err := uc.ListSnapshots(context.Background())
	if err != nil {
		t.Fatalf("listing snapshots: %v", err)
	}
	var pinErr bytes.Buffer
	pinMiss := snapshotMiss(snapshots, "govulndb", "v9999-01-01T00-00-00", false, &pinErr)
	if pinMiss == nil {
		t.Fatal("a missing snapshot pin returned a nil error")
	}
	if pinMiss.Error() != showMiss.Error() {
		t.Errorf("the pin spells the miss its own way:\n got: %s\nwant: %s", pinMiss, showMiss)
	}
	if strings.Contains(pinMiss.Error(), "snapshot not found:") {
		t.Errorf("the flat negative survived: %v", pinMiss)
	}
	if !strings.Contains(pinMiss.Error(), "of all 1 vulnerability database snapshot(s) in the store") {
		t.Errorf("the pin does not state its corpus: %v", pinMiss)
	}
	if code := ExitCodeForError(pinMiss); code != ExitNotFound {
		t.Errorf("exit code = %d, want %d", code, ExitNotFound)
	}
}
