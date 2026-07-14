package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestDigestHashes(t *testing.T) {
	t.Run("empty yields nil", func(t *testing.T) {
		if got := digestHashes(fetchdomain.ArtifactDigests{}); got != nil {
			t.Errorf("digestHashes(zero) = %v, want nil", got)
		}
	})

	t.Run("full set in fixed order", func(t *testing.T) {
		got := digestHashes(fetchdomain.ArtifactDigests{SHA256: "a", SHA384: "b", SHA512: "c"})
		if got == nil {
			t.Fatal("digestHashes returned nil for populated digests")
		}
		want := []cdx.Hash{
			{Algorithm: cdx.HashAlgoSHA256, Value: "a"},
			{Algorithm: cdx.HashAlgoSHA384, Value: "b"},
			{Algorithm: cdx.HashAlgoSHA512, Value: "c"},
		}
		if len(*got) != len(want) {
			t.Fatalf("got %d hashes, want %d", len(*got), len(want))
		}
		for i := range want {
			if (*got)[i] != want[i] {
				t.Errorf("hash[%d] = %+v, want %+v", i, (*got)[i], want[i])
			}
		}
	})

	t.Run("partial set emits only present algorithms", func(t *testing.T) {
		got := digestHashes(fetchdomain.ArtifactDigests{SHA384: "only384"})
		if got == nil || len(*got) != 1 {
			t.Fatalf("partial digests = %v, want exactly one hash", got)
		}
		if (*got)[0].Algorithm != cdx.HashAlgoSHA384 || (*got)[0].Value != "only384" {
			t.Errorf("partial hash = %+v", (*got)[0])
		}
	})
}

func TestBuildDependencies(t *testing.T) {
	mc := func(p, v string) fetchdomain.ModuleCoordinate {
		c, _ := fetchdomain.NewModuleCoordinate(p, v)
		return c
	}
	target := mc("example.com/app", "v1.0.0")
	dep := mc("example.com/dep", "v1.2.0")
	graph := walkdomain.Graph{
		Target: target,
		Edges:  []walkdomain.GraphEdge{{From: target, To: dep}},
	}
	components := []cdx.Component{
		{BOMRef: modulePURL(moduleRef(target))},
		{BOMRef: modulePURL(moduleRef(dep))},
	}
	root := &cdx.Component{BOMRef: modulePURL(moduleRef(target))}

	deps := buildDependencies(components, root, graph)

	if len(deps) != 2 {
		t.Fatalf("got %d dependency entries, want 2 (deduped root+target)", len(deps))
	}
	// Sorted by ref: app before dep.
	if deps[0].Ref != modulePURL(moduleRef(target)) {
		t.Errorf("first dep ref = %q", deps[0].Ref)
	}
	if deps[0].Dependencies == nil || len(*deps[0].Dependencies) != 1 || (*deps[0].Dependencies)[0] != modulePURL(moduleRef(dep)) {
		t.Errorf("root dependsOn = %v, want [%s]", deps[0].Dependencies, modulePURL(moduleRef(dep)))
	}

	// A nil root is tolerated (defensive): entries come from the components only.
	if got := buildDependencies(components, nil, graph); len(got) != 2 {
		t.Errorf("buildDependencies(nil root) = %d entries, want 2", len(got))
	}
}
