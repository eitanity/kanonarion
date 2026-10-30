package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// tinygoComponentProperties generates the SBOM of a pico walk whose TinyGo
// node carries custody, and returns the TinyGo component's properties.
func tinygoComponentProperties(t *testing.T, custody *walkdomain.TinyGoCustody) map[string][]string {
	t.Helper()
	walk := walkWithStdlibAndEnv(t)
	tg := mustCoord(t, walkdomain.TinyGoModulePath, "v0.42.0")
	walk.Graph.Nodes = append(walk.Graph.Nodes, walkdomain.GraphNode{
		Coordinate: tg, ResolutionSource: walkdomain.ResolutionTinyGo,
		TinyGo: &walkdomain.TinyGoFacts{Target: "pico", Packages: []string{"machine"}, Custody: custody},
	})
	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var b struct {
		Components []struct {
			Name       string `json:"name"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	for _, c := range b.Components {
		if c.Name != walkdomain.TinyGoModulePath {
			continue
		}
		out := map[string][]string{}
		for _, p := range c.Properties {
			out[p.Name] = append(out[p.Name], p.Value)
		}
		return out
	}
	t.Fatal("no TinyGo component")
	return nil
}

// The TinyGo source check is kanonarion's own measurement and vocabulary, so
// none of it reaches the TinyGo component, whatever the check reached.
func TestGenerate_TinyGoComponentStatesNoCustody(t *testing.T) {
	for name, custody := range map[string]*walkdomain.TinyGoCustody{
		"full": {
			Module: "github.com/tinygo-org/tinygo@v0.42.0", ModuleVerification: "Verified",
			ReleaseAsset: "tinygo0.42.0.linux-amd64.tar.gz", ReleaseOutcome: walkdomain.TinyGoReleaseDigestMatched,
			ReleasePublishedDigest: "b876", ReleaseObservedDigest: "b876",
			ReleaseMeasuredAt: time.Date(2026, 10, 23, 2, 23, 15, 0, time.UTC),
			VerifiedByModule:  184, VerifiedByRelease: 2,
			Differs:        []walkdomain.TinyGoFileDiffers{{Path: "machine/machine.go", Anchor: walkdomain.TinyGoAnchorModule}},
			NotEstablished: []walkdomain.TinyGoFileNotEstablished{{Path: "x.c", Reason: "absent from both"}},
		},
		"module only": {Module: "github.com/tinygo-org/tinygo@v0.42.0", VerifiedByModule: 3},
		"none":        nil,
	} {
		props := tinygoComponentProperties(t, custody)
		for prop := range props {
			if strings.Contains(prop, "custody") {
				t.Errorf("%s: the TinyGo component states %s", name, prop)
			}
		}
		if got := props["kanonarion:component:tinygo"]; len(got) != 1 || got[0] != "true" {
			t.Errorf("%s: kanonarion:component:tinygo = %v, want true", name, got)
		}
	}
}
