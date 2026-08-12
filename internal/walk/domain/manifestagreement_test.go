package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// agreementWalk is a walk of a local project carrying a stdlib node, the local
// main module, a replaced dependency and two ordinary ones — every node class
// the comparison has a rule for.
func agreementWalk() domain.WalkRecord {
	root := coordinatetest.MustNew("github.com/example/proj", coordinate.LocalVersion)
	return domain.WalkRecord{
		ID:     "walk-1",
		Target: root,
		Graph: domain.Graph{
			Target: root,
			Nodes: []domain.GraphNode{
				{Coordinate: root, ResolutionSource: domain.ResolutionLocalMainModule},
				{Coordinate: coordinatetest.MustNew("gopkg.in/yaml.v3", "v3.0.1"), ResolutionSource: domain.ResolutionMVS},
				{Coordinate: coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"), ResolutionSource: domain.ResolutionMVS},
				{
					// A replace: the manifest names the ORIGINAL coordinate.
					Coordinate:         coordinatetest.MustNew("github.com/fork/goqu/v9", "v9.18.4"),
					OriginalCoordinate: coordinatetest.MustNew("github.com/doug-martin/goqu/v9", "v9.18.0"),
					ResolutionSource:   domain.ResolutionReplace,
				},
				{Coordinate: coordinate.NewStdlibCoordinate(), ResolutionSource: domain.ResolutionStdlib},
			},
		},
	}
}

func TestNamedVersions_KeysOnTheNameTheManifestUses(t *testing.T) {
	named := domain.NamedVersions(agreementWalk())
	if got, want := len(named), 3; got != want {
		t.Fatalf("named versions = %d (%v), want %d: stdlib and local nodes are not require entries", got, named, want)
	}
	if got := named["github.com/doug-martin/goqu/v9"]; got != "v9.18.0" {
		t.Errorf("replaced node keyed as %q@%q, want the original require coordinate at v9.18.0", "github.com/doug-martin/goqu/v9", got)
	}
}

func TestRequireDisagreement(t *testing.T) {
	rec := agreementWalk()
	for _, tc := range []struct {
		name     string
		required map[string]string
		want     []string
		wantErr  bool
	}{
		{
			name:     "agreement over every module both name",
			required: map[string]string{"gopkg.in/yaml.v3": "v3.0.1", "github.com/spf13/cobra": "v1.8.1"},
		},
		{
			name:     "an upgraded module is a disagreement naming both versions",
			required: map[string]string{"gopkg.in/yaml.v3": "v3.0.2", "github.com/spf13/cobra": "v1.8.1"},
			want:     []string{"gopkg.in/yaml.v3 v3.0.1 -> v3.0.2"},
		},
		{
			name:     "a module the walk does not carry is not a disagreement",
			required: map[string]string{"gopkg.in/yaml.v3": "v3.0.1", "github.com/newly/adopted": "v1.0.0"},
		},
		{
			name:     "a replace is compared on the name the manifest uses",
			required: map[string]string{"github.com/doug-martin/goqu/v9": "v9.18.0"},
		},
		{
			name:     "nothing in common cannot be compared",
			required: map[string]string{"github.com/newly/adopted": "v1.0.0"},
			wantErr:  true,
		},
		{
			name:     "an empty manifest cannot be compared",
			required: nil,
			wantErr:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domain.RequireDisagreement(tc.required, rec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("RequireDisagreement = %v, want an error: an empty result and a clean one are not the same fact", got)
				}
				if !strings.Contains(err.Error(), rec.ID) {
					t.Errorf("error %q does not name the walk it could not compare", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RequireDisagreement: %v", err)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("disagreements = %v, want %v", got, tc.want)
			}
		})
	}
}
