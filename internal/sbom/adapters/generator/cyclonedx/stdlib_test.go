package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate"

	"code.eitanity.com/kanonarion/internal/sbom/adapters/generator/cyclonedx"

	licensedomain "code.eitanity.com/kanonarion/internal/license/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// walkWithStdlibAndEnv builds a project walk carrying a stdlib node and a
// captured build environment, mirroring what the resolver produces.
func walkWithStdlibAndEnv(t *testing.T) walkdomain.WalkRecord {
	t.Helper()
	target := mustCoord(t, "example.com/project", "v1.0.0")
	std := mustCoord(t, walkdomain.StdlibModulePath, "v1.26.4")
	return walkdomain.WalkRecord{
		ID: "walk-stdlib-001",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: std, DirectDependency: true, ResolutionSource: walkdomain.ResolutionStdlib},
			},
			ResolvedAt: time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC),
			BuildEnv:   walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.4"},
		},
	}
}

// bom is the minimal CycloneDX shape the assertions read.
type bom struct {
	Metadata struct {
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	} `json:"metadata"`
	Components []struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		PackageURL string `json:"purl"`
		Licenses   []struct {
			License struct {
				ID string `json:"id"`
			} `json:"license"`
		} `json:"licenses"`
		ExternalReferences []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"externalReferences"`
	} `json:"components"`
}

// TestGenerate_StdlibComponent verifies the standard-library node becomes a
// component with the Go BSD-3-Clause licence and no proxy-zip distribution
// reference, and that it does not flag the SBOM licences-incomplete.
func TestGenerate_StdlibComponent(t *testing.T) {
	walk := walkWithStdlibAndEnv(t)
	// Licence the project root so the only node without a fetched licence record
	// is the stdlib — isolating whether stdlib itself flags incompleteness.
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		walk.Graph.Target: {PrimarySPDX: "MIT"},
	}
	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if rec.LicensesIncomplete {
		t.Errorf("stdlib carries a known licence; SBOM must not be licences-incomplete")
	}

	var b bom
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	var found bool
	for _, c := range b.Components {
		if c.Name != walkdomain.StdlibModulePath {
			continue
		}
		found = true
		if c.Version != "v1.26.4" {
			t.Errorf("stdlib component version = %q, want v1.26.4", c.Version)
		}
		if len(c.Licenses) == 0 || c.Licenses[0].License.ID != "BSD-3-Clause" {
			t.Errorf("stdlib licence = %+v, want BSD-3-Clause", c.Licenses)
		}
		for _, ref := range c.ExternalReferences {
			if strings.Contains(ref.URL, "proxy.golang.org") {
				t.Errorf("stdlib component must not carry a proxy-zip reference: %s", ref.URL)
			}
		}
	}
	if !found {
		t.Fatalf("stdlib component absent from SBOM")
	}
}

// TestGenerate_BuildEnvProperties verifies GOOS/GOARCH/GOVERSION are emitted
// under the names the CycloneDX taxonomy registers, so the SBOM states the
// platform its component set is valid for.
func TestGenerate_BuildEnvProperties(t *testing.T) {
	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walkWithStdlibAndEnv(t), nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var b bom
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	want := map[string]string{
		"cdx:gomod:build:env:GOOS":      "linux",
		"cdx:gomod:build:env:GOARCH":    "amd64",
		"cdx:gomod:build:env:GOVERSION": "go1.26.4",
	}
	got := make(map[string]string)
	for _, p := range b.Metadata.Properties {
		got[p.Name] = p.Value
	}
	if len(got) != len(want) {
		t.Errorf("metadata properties = %v, want exactly %v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("property %s = %q, want %q", name, got[name], value)
		}
	}
}

// TestGenerate_NoBuildEnv_NoProperties verifies a walk without a build
// environment (a non-project walk, or a pre-BuildEnv record) emits no build
// properties, preserving backward-compatible output.
func TestGenerate_NoBuildEnv_NoProperties(t *testing.T) {
	walk := makeWalk(t, []coordinate.ModuleCoordinate{mustCoord(t, "example.com/a", "v1.0.0")})
	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var b bom
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	for _, p := range b.Metadata.Properties {
		t.Errorf("unexpected metadata property on a walk with no build env: %s", p.Name)
	}
}

// buildProperties is the build metadata properties in document order, each
// name's namespace trimmed.
func buildProperties(t *testing.T, walk walkdomain.WalkRecord) []string {
	t.Helper()
	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var b bom
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	var out []string
	for _, p := range b.Metadata.Properties {
		name := strings.TrimPrefix(strings.TrimPrefix(p.Name, "kanonarion:build:"), "cdx:gomod:build:env:")
		out = append(out, name+"="+p.Value)
	}
	return out
}

// A TinyGo walk states its frame as build properties; a standard walk gains
// none of them, so its document is unchanged.
func TestGenerate_TinyGoBuildPropertiesOnlyOnATinyGoWalk(t *testing.T) {
	if got, want := strings.Join(buildProperties(t, walkWithStdlibAndEnv(t)), " "),
		"GOOS=linux GOARCH=amd64 GOVERSION=go1.26.4"; got != want {
		t.Errorf("standard build properties = %q, want %q", got, want)
	}
	pico := walkWithStdlibAndEnv(t)
	pico.Graph.BuildEnv = walkdomain.BuildEnv{GOOS: "linux", GOARCH: "arm", GoVersion: "go1.27.2",
		GOARM: "6", TinyGoTarget: "pico", TinyGoVersion: "0.42.0", TinyGoTags: []string{"tinygo", "pico"}}
	if got, want := strings.Join(buildProperties(t, pico), " "),
		"GOOS=linux GOARCH=arm goarm=6 GOVERSION=go1.27.2 tinygo_target=pico tinygo_version=0.42.0 tinygo_tags=tinygo,pico"; got != want {
		t.Errorf("TinyGo build properties = %q, want %q", got, want)
	}
	// tinygo reports a GOARM for every target; off arm it has no meaning.
	wasm := walkWithStdlibAndEnv(t)
	wasm.Graph.BuildEnv = walkdomain.BuildEnv{GOOS: "wasip1", GOARCH: "wasm", GoVersion: "go1.27.2",
		GOARM: "6", TinyGoTarget: "wasip1", TinyGoVersion: "0.42.0", TinyGoTags: []string{"tinygo.wasm"}}
	if got, want := strings.Join(buildProperties(t, wasm), " "),
		"GOOS=wasip1 GOARCH=wasm GOVERSION=go1.27.2 tinygo_target=wasip1 tinygo_version=0.42.0 tinygo_tags=tinygo.wasm"; got != want {
		t.Errorf("wasm TinyGo build properties = %q, want %q", got, want)
	}
}
