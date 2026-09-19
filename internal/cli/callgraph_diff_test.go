package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	coordinatetest "github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func diffGeneration(t *testing.T, coord coordinate.ModuleCoordinate, buildList string, at time.Time, nodes []cgdomain.CallNode) cgdomain.CallGraphRecord {
	t.Helper()
	r := cgdomain.CallGraphRecord{
		SchemaVersion:    cgdomain.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Algorithm:        cgdomain.AlgorithmCHA,
		Completeness:     cgdomain.CompletenessBuiltWithBodies,
		AnalysisSource:   cgdomain.AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:a",
		BuildListSource:  buildList,
		Nodes:            nodes,
		NodeCount:        len(nodes),
		OverallStatus:    cgdomain.CallGraphStatusExtracted,
		ExtractedAt:      at,
		PipelineVersion:  cgapp.PipelineVersion,
	}
	var h cgdomain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// TestCallGraphShowDiff_NamesTheInputRatherThanTwoDigests.
//
// --history prints a digest per generation, which says THAT two measurements
// differ. This is the read that says what about: the worked case is two
// generations whose graphs are identical and whose build lists are not, and the
// answer has to be the build list.
func TestCallGraphShowDiff_NamesTheInputRatherThanTwoDigests(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	nodes := []cgdomain.CallNode{
		{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"},
	}
	older := diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nodes)
	newer := diffGeneration(t, coord, "walk-b", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nodes)
	uc.AddGeneration(coord, cgapp.PipelineVersion, older)
	uc.AddGeneration(coord, cgapp.PipelineVersion, newer)

	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), "example.com/mod@v1.0.0", flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"2 distinct measurement(s) and 1 distinct graph(s)",
		"the graphs agree; the generations differ in what they were asked",
		"build_list_source",
		"walk-a",
		"walk-b",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--diff output does not contain %q:\n%s", want, out)
		}
	}
}

// TestCallGraphShowDiff_ListsTheMembersThatDiffer: where the graphs genuinely
// differ, the reader is handed the symbols rather than a count.
func TestCallGraphShowDiff_ListsTheMembersThatDiffer(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	base := []cgdomain.CallNode{{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"}}
	grown := append(append([]cgdomain.CallNode(nil), base...),
		cgdomain.CallNode{ID: "vendor/x/idna.isASCII", Symbol: "isASCII", Package: "vendor/x/idna", IsExternal: true})
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), base))
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), grown))

	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), "example.com/mod@v1.0.0", flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "+ vendor/x/idna.isASCII") {
		t.Errorf("--diff does not name the node only one generation reached:\n%s", out)
	}
	if !strings.Contains(out, "0 only in left, 1 only in right") {
		t.Errorf("--diff does not count the membership difference:\n%s", out)
	}
}

// TestCallGraphShowDiff_NothingToCompare: one measurement, however many times it
// was recorded, is not a disagreement — and saying so is what stops a reader
// reading a re-analysis as a second answer.
func TestCallGraphShowDiff_NothingToCompare(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	nodes := []cgdomain.CallNode{{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"}}
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nodes))
	uc.AddGeneration(coord, cgapp.PipelineVersion,
		diffGeneration(t, coord, "walk-a", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), nodes))

	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), "example.com/mod@v1.0.0", flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	if !strings.Contains(buf.String(), "all stating the same measurement") {
		t.Errorf("--diff over one measurement does not say so:\n%s", buf.String())
	}
}

// -- which pair --diff compares ---------------------------------------------

// fourMeasurements stages the shape a working tree reaches: one coordinate
// ingested four times with the tree moving between each, and the newest
// generation served. It is the fixture the ticket was measured on, in the
// small.
func fourMeasurements(t *testing.T) (*testfakes.FakeQueryCallGraph, coordinate.ModuleCoordinate, []cgdomain.CallGraphRecord) {
	t.Helper()
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	var (
		nodes []cgdomain.CallNode
		gens  []cgdomain.CallGraphRecord
	)
	for i := 1; i <= 4; i++ {
		nodes = append(nodes, cgdomain.CallNode{
			ID:      fmt.Sprintf("example.com/mod.Fn%d", i),
			Symbol:  fmt.Sprintf("Fn%d", i),
			Package: "example.com/mod",
		})
		rec := diffGeneration(t, coord, "walk-a", time.Date(2026, 1, i, 0, 0, 0, 0, time.UTC),
			append([]cgdomain.CallNode(nil), nodes...))
		uc.AddGeneration(coord, cgapp.PipelineVersion, rec)
		gens = append(gens, rec)
	}
	// What the composed read serves, which is what --history marks with '*'.
	uc.AddRecord(coord, cgapp.PipelineVersion, gens[len(gens)-1])
	return uc, coord, gens
}

// servedRecordHash reads the '*' marker off --history rather than being told
// which generation is served. The acceptance is that the record a reader is
// standing in is IN the comparison, and --history is where a reader sees which
// one that is.
func servedRecordHash(t *testing.T, uc QueryCallGraphUseCase, coord coordinate.ModuleCoordinate) string {
	t.Helper()
	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), coord.String(),
		callGraphShowFlags{history: true}, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --history: %v", err)
	}
	lines := strings.Split(buf.String(), "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "* ") || !strings.Contains(l, "node(s)") {
			continue
		}
		for _, r := range lines[i+1:] {
			if strings.Contains(r, "record:") {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r), "record:"))
			}
		}
	}
	t.Fatalf("--history marked no served generation:\n%s", buf.String())
	return ""
}

func diffText(t *testing.T, uc QueryCallGraphUseCase, coord coordinate.ModuleCoordinate, from, to string) string {
	t.Helper()
	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, diffFrom: from, diffTo: to, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), coord.String(), flags, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff: %v", err)
	}
	return buf.String()
}

func diffJSON(t *testing.T, uc QueryCallGraphUseCase, coord coordinate.ModuleCoordinate, from, to string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	flags := callGraphShowFlags{diff: true, diffFrom: from, diffTo: to, limitNodes: 50, limitEdges: 100}
	if err := runCallGraphShow(context.Background(), coord.String(), flags, true, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --diff --json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding --diff --json: %v\n%s", err, buf.String())
	}
	return doc
}

// sideHash reads one side's record hash off the rendered comparison, so the
// assertion is about the line a reader sees rather than about an internal.
func sideHash(t *testing.T, out, side string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		fields := strings.Fields(l)
		if len(fields) >= 2 && fields[0] == side && strings.HasPrefix(fields[1], "sha256:") {
			return fields[1]
		}
	}
	t.Fatalf("no %q line in the comparison:\n%s", side, out)
	return ""
}

// TestCallGraphShowDiff_DefaultPairIsTheTwoMostRecent.
//
// Four measurements, and the pair a reader gets is the newest two — with the
// generation the composed read serves on the right. Taking the first two was an
// artefact of append order: it answered "what changed" about two states the
// reader had already left behind, and the record they are standing in was not
// in the comparison at all.
func TestCallGraphShowDiff_DefaultPairIsTheTwoMostRecent(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)
	served := servedRecordHash(t, uc, coord)

	out := diffText(t, uc, coord, "", "")
	if !strings.Contains(out, "comparing the first generation of the two most recent measurements:") {
		t.Errorf("--diff does not say which pair it took:\n%s", out)
	}
	if got := sideHash(t, out, "left"); got != gens[2].ContentHash {
		t.Errorf("left = %s, want the second most recent measurement %s", got, gens[2].ContentHash)
	}
	if got := sideHash(t, out, "right"); got != served {
		t.Errorf("right = %s, want the served generation %s (the one --history marks)", got, served)
	}
	for _, stale := range []string{gens[0].ContentHash, gens[1].ContentHash} {
		if strings.Contains(out, stale) {
			t.Errorf("--diff still reaches for an older measurement %s:\n%s", stale, out)
		}
	}
}

// TestCallGraphShowDiff_NamesBothSidesInEitherOrderOfAge: the flags decide which
// record is on which side, not the clock. A reader may ask what the newest
// generation adds to the oldest, or what the oldest lacks against the newest.
func TestCallGraphShowDiff_NamesBothSidesInEitherOrderOfAge(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)
	for _, tc := range []struct{ name, from, to string }{
		{"oldest on the left", gens[0].ContentHash, gens[3].ContentHash},
		{"newest on the left", gens[3].ContentHash, gens[0].ContentHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := diffText(t, uc, coord, tc.from, tc.to)
			if !strings.Contains(out, "comparing the two generations you named:") {
				t.Errorf("--diff does not say the caller chose the pair:\n%s", out)
			}
			if got := sideHash(t, out, "left"); got != tc.from {
				t.Errorf("left = %s, want %s", got, tc.from)
			}
			if got := sideHash(t, out, "right"); got != tc.to {
				t.Errorf("right = %s, want %s", got, tc.to)
			}
		})
	}
}

// TestCallGraphShowDiff_NamingOneSideStatesTheNeighbourItChose: a reader who
// names one end must be able to see what it was compared against without
// running --history.
func TestCallGraphShowDiff_NamingOneSideStatesTheNeighbourItChose(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)
	for _, tc := range []struct {
		name, from, to, want, wantLeft, wantRight string
	}{
		{
			name:     "named on the right takes the measurement before it",
			to:       gens[1].ContentHash,
			want:     "comparing the first generation of the measurement before it against the generation you named:",
			wantLeft: gens[0].ContentHash, wantRight: gens[1].ContentHash,
		},
		{
			name:     "named on the left takes the measurement after it",
			from:     gens[1].ContentHash,
			want:     "comparing the generation you named against the first generation of the measurement after it:",
			wantLeft: gens[1].ContentHash, wantRight: gens[2].ContentHash,
		},
		{
			// The newest measurement has nothing after it, so the neighbour is
			// the one before — and the line says so rather than leaving the
			// reader to compare two timestamps.
			name:     "the end of the ladder takes the neighbour on the other side",
			from:     gens[3].ContentHash,
			want:     "comparing the generation you named against the first generation of the measurement before it:",
			wantLeft: gens[3].ContentHash, wantRight: gens[2].ContentHash,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := diffText(t, uc, coord, tc.from, tc.to)
			if !strings.Contains(out, tc.want) {
				t.Errorf("--diff does not state the neighbour it chose (want %q):\n%s", tc.want, out)
			}
			if got := sideHash(t, out, "left"); got != tc.wantLeft {
				t.Errorf("left = %s, want %s", got, tc.wantLeft)
			}
			if got := sideHash(t, out, "right"); got != tc.wantRight {
				t.Errorf("right = %s, want %s", got, tc.wantRight)
			}
		})
	}
}

// TestCallGraphShowDiff_AcceptsAUniquePrefix: the printed hash is 71 characters
// and nobody types it.
func TestCallGraphShowDiff_AcceptsAUniquePrefix(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)
	out := diffText(t, uc, coord, "", gens[3].ContentHash[:16])
	if got := sideHash(t, out, "right"); got != gens[3].ContentHash {
		t.Errorf("right = %s, want the generation the prefix names, %s", got, gens[3].ContentHash)
	}
}

// TestCallGraphShowDiff_RefusesAHashItCannotResolve.
//
// Three ways a named hash fails, and one class: the argument names something
// this coordinate's ledger does not hold. The exit code is ExitConfig, not
// ExitNotFound — what the refusal prints is --history, which lists the hashes so
// the caller can correct the argument. Nothing can be run to make the store hold
// the hash that was typed, and conventions.md draws the 4/20 line there.
func TestCallGraphShowDiff_RefusesAHashItCannotResolve(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)

	// A generation of ANOTHER coordinate. The hash exists in the store and is
	// not a match here: there is no comparison to make across two coordinates.
	other := coordinatetest.MustNew("example.com/other", "v2.0.0")
	foreign := diffGeneration(t, other, "walk-b", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		[]cgdomain.CallNode{{ID: "example.com/other.Fn", Symbol: "Fn", Package: "example.com/other"}})
	uc.AddGeneration(other, cgapp.PipelineVersion, foreign)

	for _, tc := range []struct {
		name, from, to string
		wantIn         []string
	}{
		{
			name: "unknown hash", to: "sha256:ffffffffffffffff",
			wantIn: []string{"names no generation of example.com/mod@v1.0.0", "--history"},
		},
		{
			name: "a hash of another coordinate", to: foreign.ContentHash,
			wantIn: []string{"names no generation of example.com/mod@v1.0.0", "--history"},
		},
		{
			name: "ambiguous prefix", from: "sha256:",
			wantIn: []string{"matches 4 generations", "name more of the hash",
				gens[0].ContentHash, gens[1].ContentHash, gens[2].ContentHash, gens[3].ContentHash},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			flags := callGraphShowFlags{diff: true, diffFrom: tc.from, diffTo: tc.to, limitNodes: 50, limitEdges: 100}
			err := runCallGraphShow(context.Background(), coord.String(), flags, false, uc, &buf)
			if err == nil {
				t.Fatalf("--diff accepted a hash it cannot resolve:\n%s", buf.String())
			}
			if code := ExitCodeForError(err); code != ExitConfig {
				t.Errorf("exit code = %d, want ExitConfig(%d): the refusal prints a diagnostic, not a remedy that produces the record",
					code, ExitConfig)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not name %q: %v", want, err)
				}
			}
			if buf.Len() != 0 {
				t.Errorf("a refused comparison still wrote to stdout:\n%s", buf.String())
			}
		})
	}
}

// TestCallGraphShow_RefusesASideSelectorThatCannotApply: the flag is refused by
// name rather than accepted and ignored. A reader who asked for a specific pair
// and silently got the composed answer would be back at the defect these flags
// close.
func TestCallGraphShow_RefusesASideSelectorThatCannotApply(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)
	for _, tc := range []struct {
		name  string
		flags callGraphShowFlags
		want  string
	}{
		{"--diff-from without --diff", callGraphShowFlags{diffFrom: gens[0].ContentHash}, "--diff-from"},
		{"--diff-to without --diff", callGraphShowFlags{diffTo: gens[0].ContentHash}, "--diff-to"},
		{"--diff-to alongside --history", callGraphShowFlags{history: true, diffTo: gens[0].ContentHash}, "--diff-to"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := runCallGraphShow(context.Background(), coord.String(), tc.flags, false, uc, &buf)
			if err == nil {
				t.Fatalf("a side selector that cannot apply was accepted:\n%s", buf.String())
			}
			if code := ExitCodeForError(err); code != ExitConfig {
				t.Errorf("exit code = %d, want ExitConfig(%d)", code, ExitConfig)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "--diff") {
				t.Errorf("refusal does not name the flag and the mode it needs: %v", err)
			}
		})
	}
}

// TestCallGraphShowDiff_TwoMeasurementsAreUnchanged is the control that protects
// every existing reader: a coordinate holding exactly two distinct measurements
// is the common case, and neither surface moves.
//
// The three-generation arm is the one that decides the WITHIN-measurement
// choice. A forced re-analysis of an unchanged tree appends a generation
// restating the measurement already held; taking the last generation of each
// group rather than the first would move this output, and it must not.
func TestCallGraphShowDiff_TwoMeasurementsAreUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name     string
		restated bool
	}{
		{"two generations", false},
		{"the newer measurement restated by a third generation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc := testfakes.NewFakeQueryCallGraph()
			coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
			base := []cgdomain.CallNode{{ID: "example.com/mod.Foo", Symbol: "Foo", Package: "example.com/mod"}}
			grown := append(append([]cgdomain.CallNode(nil), base...),
				cgdomain.CallNode{ID: "example.com/mod.Bar", Symbol: "Bar", Package: "example.com/mod"})
			older := diffGeneration(t, coord, "walk-a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), base)
			newer := diffGeneration(t, coord, "walk-a", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), grown)
			uc.AddGeneration(coord, cgapp.PipelineVersion, older)
			uc.AddGeneration(coord, cgapp.PipelineVersion, newer)
			served := newer
			if tc.restated {
				served = diffGeneration(t, coord, "walk-a", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), grown)
				uc.AddGeneration(coord, cgapp.PipelineVersion, served)
			}
			uc.AddRecord(coord, cgapp.PipelineVersion, served)

			out := diffText(t, uc, coord, "", "")
			if !strings.Contains(out, "\ncomparing the first generation of the first two measurements:\n") {
				t.Errorf("the two-measurement statement moved:\n%s", out)
			}
			if got := sideHash(t, out, "left"); got != older.ContentHash {
				t.Errorf("left = %s, want %s", got, older.ContentHash)
			}
			if got := sideHash(t, out, "right"); got != newer.ContentHash {
				t.Errorf("right = %s, want the first generation of the newer measurement %s", got, newer.ContentHash)
			}
			doc := diffJSON(t, uc, coord, "", "")
			for _, side := range []string{"left", "right"} {
				if _, ok := doc[side].(map[string]any)["selected_by"]; ok {
					t.Errorf("%s carries a selection basis where the ladder offered one pair: %v", side, doc[side])
				}
			}
		})
	}
}

// TestCallGraphShowDiff_JSONStatesWhyThePairWasChosen: an agent cannot read
// prose, so what the text statement says has to be a field.
func TestCallGraphShowDiff_JSONStatesWhyThePairWasChosen(t *testing.T) {
	uc, coord, gens := fourMeasurements(t)
	for _, tc := range []struct {
		name, from, to      string
		wantLeft, wantRight string
	}{
		{"default", "", "", "most_recent", "most_recent"},
		{"named on the right", "", gens[1].ContentHash, "neighbour_older", "named"},
		{"named on the left", gens[1].ContentHash, "", "named", "neighbour_newer"},
		{"both named", gens[0].ContentHash, gens[3].ContentHash, "named", "named"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := diffJSON(t, uc, coord, tc.from, tc.to)
			for side, want := range map[string]string{"left": tc.wantLeft, "right": tc.wantRight} {
				got, _ := doc[side].(map[string]any)["selected_by"].(string)
				if got != want {
					t.Errorf("%s.selected_by = %q, want %q", side, got, want)
				}
			}
		})
	}
}
