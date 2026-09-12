package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// "Who depends on jwt/v4" is a question about a PATH. A caller who must first
// learn which version the build resolved in order to ask it has the
// answer-ordering backwards, so a bare path is answered across every version the
// build holds — and the answer says which ones, because a list of dependents
// does not carry its own scope.
func TestParseDependentsTarget_TakesEitherForm(t *testing.T) {
	pinned, err := parseDependentsTarget("github.com/golang-jwt/jwt/v4@v4.5.1")
	if err != nil {
		t.Fatalf("a coordinate was refused: %v", err)
	}
	if !pinned.HasVersion() || dependentsTargetText(pinned) != "github.com/golang-jwt/jwt/v4@v4.5.1" {
		t.Errorf("coordinate read back as %q", dependentsTargetText(pinned))
	}

	bare, err := parseDependentsTarget("github.com/golang-jwt/jwt/v4")
	if err != nil {
		t.Fatalf("a bare path was refused: %v", err)
	}
	if bare.HasVersion() {
		t.Error("a bare path arrived with a version invented for it")
	}
	// A version-less coordinate renders with a trailing "@", which is not what
	// the caller typed and not what the answer should echo.
	if got := dependentsTargetText(bare); got != "github.com/golang-jwt/jwt/v4" {
		t.Errorf("bare path read back as %q", got)
	}
}

// A string that cannot be a module path has no versions in any build, and
// answering "no modules depend on it" would present an absence as a measurement.
func TestParseDependentsTarget_RefusesWhatCannotBeAModulePath(t *testing.T) {
	if _, err := parseDependentsTarget("nodot"); err == nil {
		t.Error("a path with no dot in its first element was accepted")
	}
}

// A walk id in the module slot is the mistake license-compat already names, and
// "missing dot in first path element" does not name it. The remedy has to run.
func TestParseDependentsTarget_NamesAWalkIDAsOne(t *testing.T) {
	const id = "01KQDBVW092ER1HNXZ60X27CMD"
	_, err := parseDependentsTarget(id)
	if err == nil {
		t.Fatal("a walk id was read as a module path")
	}
	msg := err.Error()
	for _, want := range []string{"is a walk id", "--walk-id " + id} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}

// The union is the answer: a module depending on two versions of the target is
// one row, and the row keeps every annotation it earned.
func TestWalkDependentsOver_UnionsTheVersions(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	old := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	newer := coordinatetest.MustNew("example.com/dep", "v1.1.0")
	viaOld := coordinatetest.MustNew("example.com/mid", "v1.0.0")

	rec := walkdomain.WalkRecord{
		ID:     "01WALK",
		Target: root,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root},
				{Coordinate: old},
				{Coordinate: newer},
				{Coordinate: viaOld, DirectDependency: true},
			},
			Edges: []walkdomain.GraphEdge{
				{From: root, To: newer},
				{From: viaOld, To: old},
			},
		},
	}

	bare, err := coordinate.NewPathOnlyCoordinate("example.com/dep")
	if err != nil {
		t.Fatalf("path-only coordinate: %v", err)
	}
	targets, versions := dependentsTargets(rec.Graph, bare)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want both versions: %v", len(targets), versions)
	}
	// Newest first: a text sort would put v1.10.0 below v1.9.0, and this list is
	// read by a caller.
	if versions[0] != "v1.1.0" || versions[1] != "v1.0.0" {
		t.Errorf("versions are not newest-first: %v", versions)
	}

	deps, scope := walkDependentsOver(rec, targets, true)
	if len(deps) != 2 {
		t.Fatalf("got %d dependents, want the root and the middle module: %v", len(deps), deps)
	}
	if !deps[0].Root {
		t.Errorf("the root does not sort first: %v", deps)
	}
	if !scope.DependsOnTarget {
		t.Error("the root depends on one version of the target and the scope does not say so")
	}
	if !deps[1].Direct || deps[1].Coord != viaOld {
		t.Errorf("the direct dependent lost its annotation: %+v", deps[1])
	}

	// The pinned form is unchanged: one target, one version, no scope notice.
	one, none := dependentsTargets(rec.Graph, newer)
	if len(one) != 1 || one[0] != newer || none != nil {
		t.Errorf("a pinned question was widened: %v %v", one, none)
	}
}

// The scope of a bare-path answer is a field, not only prose: "which versions
// did you answer for" is exactly what a machine consumer cannot infer from a
// rendered list. A pinned answer names one version in "target", so the field is
// absent there and the document a consumer already parses does not move.
func TestDependentsJSON_NamesTheVersionsABarePathCovered(t *testing.T) {
	root := coordinatetest.MustNew("example.com/app", "v1.0.0")
	scope := dependentsRootScope{Root: root, Excluded: true}

	var bare, pinned map[string]any
	decodeDependentsJSON(t, &bare, "example.com/dep", []string{"v1.1.0", "v1.0.0"}, scope)
	decodeDependentsJSON(t, &pinned, "example.com/dep@v1.1.0", nil, scope)

	got, ok := bare["target_versions"].([]any)
	if !ok || len(got) != 2 || got[0] != "v1.1.0" {
		t.Errorf("a bare-path answer does not carry its own scope: %v", bare["target_versions"])
	}
	if _, present := pinned["target_versions"]; present {
		t.Errorf("a pinned answer grew a field: %v", pinned["target_versions"])
	}
}

func decodeDependentsJSON(t *testing.T, into any, target string, versions []string, scope dependentsRootScope) {
	t.Helper()
	var buf strings.Builder
	if err := writeDependentsJSON(&buf, "01WALK", linuxAmd64Frame, walkSelectionJSON{},
		target, versions, nil, scope, nil); err != nil {
		t.Fatalf("writeDependentsJSON: %v", err)
	}
	if err := json.Unmarshal([]byte(buf.String()), into); err != nil {
		t.Fatalf("decoding: %v", err)
	}
}

// The notice states the scope above the rows, where a reader meets it before
// deciding what they are about.
func TestDependentsVersionNotice_SaysWhatItCovered(t *testing.T) {
	if got := dependentsVersionNotice("example.com/dep", "01WALK", nil); got != "" {
		t.Errorf("a pinned answer printed a notice: %q", got)
	}
	one := dependentsVersionNotice("example.com/dep", "01WALK", []string{"v1.1.0"})
	if !strings.Contains(one, "at v1.1.0") || !strings.Contains(one, "01WALK") {
		t.Errorf("single-version notice does not name the version and walk: %q", one)
	}
	two := dependentsVersionNotice("example.com/dep", "01WALK", []string{"v1.1.0", "v1.0.0"})
	if !strings.Contains(two, "2 versions (v1.1.0, v1.0.0)") {
		t.Errorf("multi-version notice does not name them: %q", two)
	}
}
