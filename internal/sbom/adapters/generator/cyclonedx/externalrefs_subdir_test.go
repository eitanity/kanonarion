package cyclonedx_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
)

// A nested module's VCS reference names the directory its zip was compared
// with; a root module says root; a record that names none says neither.
func TestComponentReferenceNamesTheComparedDirectory(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		path, subdir, want string
	}{
		{"cloud.google.com/go/compute/metadata", "compute/metadata",
			"the module zip was cross-verified against the compute/metadata directory of refs/tags/x at commit " + commit},
		{"github.com/google/uuid", ".",
			"the module zip was cross-verified against the repository root of refs/tags/x at commit " + commit},
		{"github.com/example/old", "",
			"the module zip was cross-verified against refs/tags/x at commit " + commit},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			main := mustCoord(t, "example.com/project", coordinate.LocalVersion)
			dep := mustCoord(t, tc.path, "v1.0.0")
			req := makeGenReq()
			req.ModuleOrigins = map[coordinate.ModuleCoordinate]ports.ModuleOrigin{
				dep: {VCSURL: "https://example.com/repo", VCSRef: "refs/tags/x", VCSCommit: commit, VCSSubdir: tc.subdir},
			}
			rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), makeWalk(t, []coordinate.ModuleCoordinate{main, dep}), nil, req)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			_, byPURL := bomComponents(t, rec.Content)
			refs := externalRefs(t, byPURL["pkg:golang/"+tc.path+"@v1.0.0"])
			if len(refs) != 1 || refs[0][2] != tc.want {
				t.Errorf("references = %v, want comment %q", refs, tc.want)
			}
		})
	}
}
