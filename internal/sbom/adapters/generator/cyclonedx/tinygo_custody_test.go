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

func TestGenerate_TinyGoCustodyProperties(t *testing.T) {
	props := tinygoComponentProperties(t, &walkdomain.TinyGoCustody{
		Module: "github.com/tinygo-org/tinygo@v0.42.0", ModuleVerification: "Verified",
		ReleaseAsset: "tinygo0.42.0.linux-amd64.tar.gz", ReleaseOutcome: walkdomain.TinyGoReleaseDigestMatched,
		ReleasePublishedDigest: "b876", ReleaseObservedDigest: "b876",
		ReleaseMeasuredAt: time.Date(2026, 10, 23, 2, 23, 15, 0, time.UTC),
		VerifiedByModule:  184, VerifiedByRelease: 2,
		Differs: []walkdomain.TinyGoFileDiffers{
			{Path: "machine/machine.go", Anchor: walkdomain.TinyGoAnchorModule},
			{Path: "device/rp/rp2040.go", Anchor: walkdomain.TinyGoAnchorRelease},
		},
		NotEstablished: []walkdomain.TinyGoFileNotEstablished{{Path: "x.c", Reason: "absent from both"}},
	})
	const p = "kanonarion:tinygo:custody:"
	for name, want := range map[string]string{
		p + "module":                   "github.com/tinygo-org/tinygo@v0.42.0",
		p + "module_verification":      "Verified",
		p + "verified_by_module":       "184",
		p + "verified_by_release":      "2",
		p + "release_asset":            "tinygo0.42.0.linux-amd64.tar.gz",
		p + "release_outcome":          "digest_matched",
		p + "release_published_sha256": "b876",
		p + "release_observed_sha256":  "b876",
		p + "release_measured_at":      "2026-10-23T02:23:15Z",
		p + "differs_from_module":      "machine/machine.go",
		p + "differs_from_release":     "device/rp/rp2040.go",
		p + "not_established":          "absent from both: x.c",
	} {
		if got := props[name]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want %q", name, got, want)
		}
	}
	if got := props[p+"anchor_limitation"]; len(got) != 1 || !strings.Contains(got[0], "184 of 189 compiled TinyGo file(s) match the module zip") {
		t.Errorf("anchor limitation = %v", got)
	}
}

func TestGenerate_TinyGoCustodyStatesOnlyWhatWasReached(t *testing.T) {
	props := tinygoComponentProperties(t, &walkdomain.TinyGoCustody{Module: "github.com/tinygo-org/tinygo@v0.42.0", VerifiedByModule: 3})
	for name := range props {
		if strings.Contains(name, ":release_") || strings.Contains(name, ":differs_") || strings.HasSuffix(name, ":not_established") {
			t.Errorf("%s stated with no release consulted and nothing differing", name)
		}
	}
	if got := props["kanonarion:tinygo:custody:anchor_limitation"]; len(got) != 1 || !strings.Contains(got[0], "no release archive was consulted") {
		t.Errorf("anchor limitation = %v", got)
	}
	unmeasured := tinygoComponentProperties(t, &walkdomain.TinyGoCustody{Module: "m", ReleaseAsset: "a", ReleaseOutcome: walkdomain.TinyGoReleaseUnavailable})
	if _, ok := unmeasured["kanonarion:tinygo:custody:release_published_sha256"]; ok {
		t.Error("a release with no published digest states one")
	}
	if _, ok := unmeasured["kanonarion:tinygo:custody:release_measured_at"]; ok {
		t.Error("an unmeasured release states a measurement time")
	}
	for name := range tinygoComponentProperties(t, nil) {
		if strings.HasPrefix(name, "kanonarion:tinygo:custody:") {
			t.Errorf("%s stated on a TinyGo walk without custody", name)
		}
	}
}
