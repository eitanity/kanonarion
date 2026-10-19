package cyclonedx_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// propertyValues returns a component's properties by name.
func propertyValues(t *testing.T, comp map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	props, ok := comp["properties"].([]any)
	if !ok {
		return out
	}
	for _, p := range props {
		pm := optAs[map[string]any](t, p)
		out[optAs[string](t, pm["name"])] = optAs[string](t, pm["value"])
	}
	return out
}

// A dependency read from disk is listed at <path>@local and says what it stands
// for: the published require it replaces, or that it is a go.work member.
func TestLocalSourceDependenciesStateWhatTheyStandFor(t *testing.T) {
	root := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	replaced := mustCoord(t, "example.com/dep", coordinate.LocalVersion)
	member := mustCoord(t, "example.com/member", coordinate.LocalVersion)
	walk := makeWalk(t, []coordinate.ModuleCoordinate{root, replaced, member})
	walk.Graph.Nodes[0].ResolutionSource = walkdomain.ResolutionLocalMainModule
	walk.Graph.Nodes[1].ResolutionSource = walkdomain.ResolutionLocalReplace
	walk.Graph.Nodes[1].OriginalCoordinate = mustCoord(t, "example.com/dep", "v1.2.3")
	walk.Graph.Nodes[1].LocalPath = "../dep"
	walk.Graph.Nodes[2].ResolutionSource = walkdomain.ResolutionLocalWorkspaceMember

	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, byPURL := bomComponents(t, rec.Content)

	dep, ok := byPURL["pkg:golang/example.com/dep@local"]
	if !ok {
		t.Fatalf("no component pkg:golang/example.com/dep@local; components %v", byPURL)
	}
	if got := propertyValues(t, dep); got["kanonarion:replaces"] != "example.com/dep@v1.2.3" || got["kanonarion:workspace_member"] != "" {
		t.Errorf("replacement properties = %v, want kanonarion:replaces=example.com/dep@v1.2.3 only", got)
	}
	mem, ok := byPURL["pkg:golang/example.com/member@local"]
	if !ok {
		t.Fatalf("no component pkg:golang/example.com/member@local")
	}
	if got := propertyValues(t, mem); got["kanonarion:workspace_member"] != "true" || got["kanonarion:replaces"] != "" {
		t.Errorf("member properties = %v, want kanonarion:workspace_member=true only", got)
	}
	if got := propertyValues(t, byPURL["pkg:golang/example.com/project@local"]); got["kanonarion:replaces"] != "" || got["kanonarion:workspace_member"] != "" {
		t.Errorf("the subject carries local-source properties: %v", got)
	}
}
