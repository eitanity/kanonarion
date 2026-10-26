package cli

import (
	"context"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// A go.mod scope names a local-path replacement by the node a walk records for
// it, so notice attributes its analysed record instead of sending it to review.
func TestWithLocalIdentity_LocalReplacementIsScopedAtLocal(t *testing.T) {
	required := coordinatetest.MustNew("example.com/c", "v1.2.3")
	plain := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	mods, err := parseGoListModuleRecords([]byte("\texample.com/c@v1.2.3\t../c\nexample.com/dep@v1.0.0\t\t\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	mods = withLocalIdentity(mods)
	local := coordinatetest.MustNew("example.com/c", coordinate.LocalVersion)
	byAnswer := map[coordinate.ModuleCoordinate]scopeModule{}
	for _, m := range mods {
		byAnswer[m.answering()] = m
	}
	if m, ok := byAnswer[local]; !ok || m.original != required || m.localPath != "../c" {
		t.Fatalf("scope = %+v, want %s replacing %s at ../c", mods, local, required)
	}
	if _, ok := byAnswer[plain]; !ok {
		t.Errorf("an ordinary module left the scope: %+v", mods)
	}
	coords, replaced, reviews := partitionNoticeModules(mods)
	if len(reviews) != 0 || replaced[local] != required || len(coords) != 2 {
		t.Errorf("partition = %v %v %v; want both attributed, no review", coords, replaced, reviews)
	}
}

// walksRootedAt answers ListWalks with a walk only for the coordinate it is
// rooted at.
type walksRootedAt struct{ root coordinate.ModuleCoordinate }

func (w walksRootedAt) GetWalk(context.Context, string) (walkdomain.WalkRecord, error) {
	return walkdomain.WalkRecord{}, nil
}

func (w walksRootedAt) ListWalks(_ context.Context, f walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	if f.Target != nil && *f.Target == w.root {
		return []walkports.WalkSummary{{ID: "W"}}, nil
	}
	return nil, nil
}

// A dependency a walk read from disk is analysed by coordinate; the project
// root keeps the working-tree remedy.
func TestLocalDependencyRemedy_NamesTheCallgraphOfTheStoredRecord(t *testing.T) {
	root := coordinatetest.MustNew("example.com/a", coordinate.LocalVersion)
	dep := coordinatetest.MustNew("example.com/c", coordinate.LocalVersion)
	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		root: {}, dep: {},
	}}
	uc := callGraphShowUC{nil, noSuperseded{}, localDependencyCheck{fetch: records, walks: walksRootedAt{root: root}}}

	got, ok := localDependencyRemedy(context.Background(), uc, dep)
	if !ok || !strings.HasPrefix(got, "kanonarion callgraph example.com/c@local") || strings.Contains(got, "kanonarion local") {
		t.Errorf("dependency remedy = %q, %v; want the callgraph of the stored record", got, ok)
	}
	if _, ok := localDependencyRemedy(context.Background(), uc, root); ok {
		t.Error("the walk's root is not a dependency read from disk")
	}
}

// The SBOM and licence remedy for a dependency a walk read from disk names that
// dependency's own source and the extract that reads it, never --analyse-root.
func TestMissingLicenceRecordRemedies_LocalDependenciesNameTheirSource(t *testing.T) {
	build := licenceRemedyBuild{goModPath: "/p/go.mod", localSources: map[string]string{
		"example.com/c": "the local path ../c this build replaces it with",
		"example.com/b": "its directory in the go.work workspace",
	}}
	root := coordinatetest.MustNew("example.com/a", coordinate.LocalVersion)
	member := coordinatetest.MustNew("example.com/b", coordinate.LocalVersion)
	replaced := coordinatetest.MustNew("example.com/c", coordinate.LocalVersion)

	if got := missingLicenceRecordRemedy(member, build); strings.Contains(got, "--analyse-root") ||
		!strings.Contains(got, "example.com/b@local from its directory in the go.work workspace") {
		t.Errorf("member remedy = %q", got)
	}
	got := missingLicenceRecordRemedies([]coordinate.ModuleCoordinate{root, replaced}, build)
	if !strings.Contains(got, "example.com/c@local from the local path ../c") || strings.Count(got, "--analyse-root") != 1 {
		t.Errorf("remedies = %q; want the root's --analyse-root once and the replacement's own source", got)
	}
}

// A history view marks the generation derived from a superseded artefact.
func TestSupersededNote(t *testing.T) {
	ids := map[string]bool{"zip:h1:dir=": true}
	if got := supersededNote(ids, "zip:h1:pub="); got != "" {
		t.Errorf("a published generation was marked: %q", got)
	}
	if got := supersededNote(ids, "zip:h1:dir="); !strings.Contains(got, "superseded by identity") {
		t.Errorf("the superseded generation is not marked: %q", got)
	}
}

// fixedSuperseded names a fixed set of artefacts as superseded.
type fixedSuperseded map[string]bool

func (f fixedSuperseded) SupersededArtefacts(context.Context, coordinate.ModuleCoordinate) (map[string]bool, error) {
	return f, nil
}

// A published coordinate whose every generation is superseded is refused with
// that statement and the command that measures the published module; one
// generation that is not superseded leaves the ordinary miss to speak.
func TestSupersededOnlyRefusal(t *testing.T) {
	ctx := context.Background()
	coord := coordinatetest.MustNew("github.com/foo/uuid", "v1.6.0")
	reader := fixedSuperseded{"zip:h1:dir=": true}

	err := supersededOnlyRefusal(ctx, reader, coord, []string{"zip:h1:dir="}, "kanonarion interface "+coord.String())
	if err == nil || !strings.Contains(err.Error(), "the store holds 1 generation(s) of github.com/foo/uuid@v1.6.0") ||
		!strings.Contains(err.Error(), "measure the published module: kanonarion interface github.com/foo/uuid@v1.6.0") {
		t.Fatalf("refusal = %v", err)
	}
	if err := supersededOnlyRefusal(ctx, reader, coord, []string{"zip:h1:dir=", "zip:h1:pub="}, "x"); err != nil {
		t.Errorf("a published generation is held, so this is not superseded-only: %v", err)
	}
	if err := supersededOnlyRefusal(ctx, reader, coord, nil, "x"); err != nil {
		t.Errorf("nothing held is the ordinary miss: %v", err)
	}
}
