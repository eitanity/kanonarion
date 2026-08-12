package cyclonedx_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	"github.com/eitanity/kanonarion/internal/sbom/ports"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// bomComponents unmarshals the document and returns metadata.component plus the
// component list, keyed by purl.
func bomComponents(t *testing.T, content []byte) (map[string]any, map[string]map[string]any) {
	t.Helper()
	var bom map[string]any
	if err := json.Unmarshal(content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	meta, _ := bom["metadata"].(map[string]any)
	primary, _ := meta["component"].(map[string]any)
	byPURL := map[string]map[string]any{}
	comps, _ := bom["components"].([]any)
	for _, c := range comps {
		cm, _ := c.(map[string]any)
		purl, _ := cm["purl"].(string)
		byPURL[purl] = cm
	}
	return primary, byPURL
}

// externalRefs returns a component's external references as (type, url, comment)
// triples in document order.
func externalRefs(comp map[string]any) [][3]string {
	raw, _ := comp["externalReferences"].([]any)
	out := make([][3]string, 0, len(raw))
	for _, r := range raw {
		rm, _ := r.(map[string]any)
		typ, _ := rm["type"].(string)
		url, _ := rm["url"].(string)
		comment, _ := rm["comment"].(string)
		out = append(out, [3]string{typ, url, comment})
	}
	return out
}

// TestComponentReferencesOnlyRecordedOrigin verifies a module component's
// external references come from the recorded fetch origin and from nothing else:
// a module with a recorded origin carries that repository, a module with none
// carries no references at all, and no component carries a proxy download URL.
//
// The module paths are chosen to be exactly the shapes a path-derived URL gets
// wrong: a /v2 major-version suffix (which no forge serves as a repository
// path) and a vanity import domain that is not a forge.
func TestComponentReferencesOnlyRecordedOrigin(t *testing.T) {
	main := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	recorded := mustCoord(t, "github.com/example/ulid/v2", "v2.1.0")
	unrecorded := mustCoord(t, "golang.org/x/mod", "v0.14.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{main, recorded, unrecorded})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq()
	req.ModuleOrigins = map[coordinate.ModuleCoordinate]ports.ModuleOrigin{
		recorded: {
			VCSURL:    "https://github.com/example/ulid",
			VCSRef:    "refs/tags/v2.1.0",
			VCSCommit: "0123456789abcdef0123456789abcdef01234567",
		},
	}

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	primary, byPURL := bomComponents(t, rec.Content)

	got := externalRefs(byPURL["pkg:golang/github.com/example/ulid/v2@v2.1.0"])
	want := [][3]string{{
		"vcs",
		"https://github.com/example/ulid",
		"the module zip was cross-verified against refs/tags/v2.1.0 at commit 0123456789abcdef0123456789abcdef01234567",
	}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("recorded-origin component references = %v, want %v", got, want)
	}

	if refs := externalRefs(byPURL["pkg:golang/golang.org/x/mod@v0.14.0"]); len(refs) != 0 {
		t.Errorf("component with no recorded origin has references %v, want none", refs)
	}
	if refs := externalRefs(primary); len(refs) != 0 {
		t.Errorf("local main subject has references %v, want none", refs)
	}

	// No component anywhere may assert a download location: nothing recorded
	// supports one.
	for purl, comp := range byPURL {
		for _, r := range externalRefs(comp) {
			if r[0] == "distribution" {
				t.Errorf("%s asserts a distribution reference %q; the fetch ledger records no download address", purl, r[1])
			}
		}
	}
}

// TestReplacedComponentReferencesTheReplacementOrigin verifies a replace-to-fork
// node's reference names the repository the bytes in the build came from — the
// replacement's — and never the module it replaced. A document that points a
// consumer at the upstream repository for a forked artefact describes bytes
// that are not in the build.
func TestReplacedComponentReferencesTheReplacementOrigin(t *testing.T) {
	main := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	fork := mustCoord(t, "github.com/fork/goqu/v9", "v9.18.4")
	original := mustCoord(t, "github.com/upstream/goqu/v9", "v9.18.0")
	walk := walkdomain.WalkRecord{
		ID: "walk-replace-001",
		Graph: walkdomain.Graph{
			Target: main,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: main, DirectDependency: true, ResolutionSource: walkdomain.ResolutionTarget},
				{
					Coordinate:         fork,
					DirectDependency:   true,
					ResolutionSource:   walkdomain.ResolutionReplace,
					OriginalCoordinate: original,
				},
			},
			ResolvedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	gen := cyclonedx.New(testPipelineVersion)
	req := makeGenReq()
	req.ModuleOrigins = map[coordinate.ModuleCoordinate]ports.ModuleOrigin{
		fork: {
			VCSURL:    "https://github.com/fork/goqu",
			VCSRef:    "refs/tags/v9.18.4",
			VCSCommit: "9b0afa43ecc8a708313d4d49f223696b69a5da0b",
		},
		original: {
			VCSURL:    "https://github.com/upstream/goqu",
			VCSRef:    "refs/tags/v9.18.0",
			VCSCommit: "1111111111111111111111111111111111111111",
		},
	}

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, byPURL := bomComponents(t, rec.Content)
	refs := externalRefs(byPURL["pkg:golang/github.com/fork/goqu/v9@v9.18.4"])
	if len(refs) != 1 {
		t.Fatalf("replaced component references = %v, want exactly one", refs)
	}
	if refs[0][1] != "https://github.com/fork/goqu" {
		t.Errorf("replaced component vcs url = %q, want the replacement repository", refs[0][1])
	}
}

// TestPseudoVersionOriginCommentNamesTheCommit verifies a recorded origin with
// no ref (a pseudo-version, where only the commit is known) still states what
// the reference rests on.
func TestPseudoVersionOriginCommentNamesTheCommit(t *testing.T) {
	dep := mustCoord(t, "github.com/example/dep", "v0.0.0-20190221195224-5a805980a5f3")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{dep})
	gen := cyclonedx.New(testPipelineVersion)
	req := makeGenReq()
	req.ModuleOrigins = map[coordinate.ModuleCoordinate]ports.ModuleOrigin{
		dep: {VCSURL: "https://github.com/example/dep", VCSCommit: "5a805980a5f3"},
	}

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, byPURL := bomComponents(t, rec.Content)
	refs := externalRefs(byPURL["pkg:golang/github.com/example/dep@v0.0.0-20190221195224-5a805980a5f3"])
	if len(refs) != 1 {
		t.Fatalf("references = %v, want exactly one", refs)
	}
	if refs[0][2] != "the module zip was cross-verified against commit 5a805980a5f3" {
		t.Errorf("comment = %q, want the commit-only form", refs[0][2])
	}
}
