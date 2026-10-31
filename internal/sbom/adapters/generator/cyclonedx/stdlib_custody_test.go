package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/sbom/adapters/generator/cyclonedx"

	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// custodyBOM is the CycloneDX shape needed to assert the stdlib chain of custody
// (hashes + properties), beyond what the shared bom struct reads.
type custodyBOM struct {
	Components []custodyComponent `json:"components"`
}

// custodyComponent is one component of a custodyBOM.
type custodyComponent struct {
	Name   string `json:"name"`
	Hashes []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	ExternalReferences []struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Hashes []struct {
			Alg     string `json:"alg"`
			Content string `json:"content"`
		} `json:"hashes"`
	} `json:"externalReferences"`
}

// walkWithStdlibCustody builds a project walk whose stdlib node carries a full
// chain of custody, mirroring what the resolver produces after acquisition.
func walkWithStdlibCustody(t *testing.T) walkdomain.WalkRecord {
	t.Helper()
	target := mustCoord(t, "example.com/project", "v1.0.0")
	std := mustCoord(t, walkdomain.StdlibModulePath, "v1.26.4")
	return walkdomain.WalkRecord{
		ID: "walk-stdlib-custody",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{
					Coordinate:       std,
					DirectDependency: true,
					ResolutionSource: walkdomain.ResolutionStdlib,
					Digests:          fetchdomain.ArtifactDigests{SHA256: "aa256", SHA384: "bb384", SHA512: "cc512"},
					Stdlib: &walkdomain.StdlibFacts{
						LicenseSPDX:        "BSD-3-Clause",
						VerificationStatus: "VerifiedGoDevChecksum",
						VerificationDetail: "SHA-256 matched go.dev/dl published checksum",
						PublishedSHA256:    "aa256",
						SourceURL:          "https://go.dev/dl/go1.26.4.src.tar.gz",
						VCSURL:             "https://go.googlesource.com/go",
						VCSRef:             "go1.26.4",
						VCSCommit:          "deadbeefcafe",
					},
				},
			},
			ResolvedAt: time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC),
			BuildEnv:   walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.4"},
		},
	}
}

func TestGenerate_StdlibCustodyChain(t *testing.T) {
	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walkWithStdlibCustody(t), nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var b custodyBOM
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	var found bool
	for _, c := range b.Components {
		if c.Name != walkdomain.StdlibModulePath {
			continue
		}
		found = true

		assertStdlibCustodyComponent(t, c)
	}
	if !found {
		t.Fatal("stdlib component absent from SBOM")
	}
}

// assertStdlibCustodyComponent checks the stdlib component carries the
// tarball's hashes, its source references with the published checksum on the
// distribution reference, and no verification status of kanonarion's own.
func assertStdlibCustodyComponent(t *testing.T, c custodyComponent) {
	t.Helper()
	// Hashes: SHA-256/384/512 from the tarball, no MD5/SHA-1.
	gotHashes := map[string]string{}
	for _, h := range c.Hashes {
		gotHashes[h.Alg] = h.Content
	}
	for alg, want := range map[string]string{"SHA-256": "aa256", "SHA-384": "bb384", "SHA-512": "cc512"} {
		if gotHashes[alg] != want {
			t.Errorf("hash %s = %q, want %q", alg, gotHashes[alg], want)
		}
	}

	assertStdlibPropertiesAreOnlyMarkers(t, c)

	// External references: the source tarball distribution URL carrying the
	// published checksum, and the commit.
	var hasDist, hasCommit bool
	for _, ref := range c.ExternalReferences {
		if ref.Type == "distribution" && strings.Contains(ref.URL, "go.dev/dl/go1.26.4.src.tar.gz") {
			hasDist = true
			if len(ref.Hashes) != 1 || ref.Hashes[0].Alg != "SHA-256" || ref.Hashes[0].Content != "aa256" {
				t.Errorf("distribution reference hashes = %+v, want the published SHA-256 aa256", ref.Hashes)
			}
		}
		if ref.URL == "https://go.googlesource.com/go" {
			hasCommit = true
		}
	}
	if !hasDist {
		t.Error("stdlib component missing source-tarball distribution reference")
	}
	if !hasCommit {
		t.Error("stdlib component missing googlesource VCS reference")
	}
}

// walkWithStdlibFacts builds a project walk whose stdlib node carries the given
// chain-of-custody evidence, so one generator can be driven over the connected
// and the offline measurement of the same toolchain.
func walkWithStdlibFacts(t *testing.T, facts *walkdomain.StdlibFacts) walkdomain.WalkRecord {
	t.Helper()
	target := mustCoord(t, "example.com/project", "v1.0.0")
	std := mustCoord(t, walkdomain.StdlibModulePath, "v1.26.4")
	return walkdomain.WalkRecord{
		ID: "walk-stdlib-anchor",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{
					Coordinate:       std,
					DirectDependency: true,
					ResolutionSource: walkdomain.ResolutionStdlib,
					Digests:          fetchdomain.ArtifactDigests{SHA256: "aa256", SHA384: "bb384", SHA512: "cc512"},
					Stdlib:           facts,
				},
			},
			ResolvedAt: time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC),
			BuildEnv:   walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.4"},
		},
	}
}

// assertStdlibPropertiesAreOnlyMarkers checks the stdlib component's properties
// are its ecosystem and its stdlib marker, and nothing of kanonarion's own
// verification vocabulary.
func assertStdlibPropertiesAreOnlyMarkers(t *testing.T, c custodyComponent) {
	t.Helper()
	props := map[string]string{}
	for _, p := range c.Properties {
		props[p.Name] = p.Value
	}
	want := map[string]string{"kanonarion:ecosystem": "go", "kanonarion:component:stdlib": "true"}
	if len(props) != len(want) || props["kanonarion:ecosystem"] != "go" || props["kanonarion:component:stdlib"] != "true" {
		t.Errorf("stdlib properties = %v, want exactly %v", props, want)
	}
}

// TestGenerate_OfflineStdlibNamesNoLocalPath: an offline measurement read the
// local $GOROOT/src, which is a path on the machine that ran it and not a
// distribution, and consulted no published checksum. Its references are the Go
// repository and website only, and neither they nor the component carry hashes.
func TestGenerate_OfflineStdlibNamesNoLocalPath(t *testing.T) {
	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walkWithStdlibFacts(t, &walkdomain.StdlibFacts{
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: "VerifiedLocalToolchain",
		VerificationDetail: "digests computed over local toolchain source; go.dev/dl published checksum not consulted (offline)",
		SourceURL:          "/opt/go/src",
		VCSURL:             "https://go.googlesource.com/go",
		VCSRef:             "go1.26.4",
	}), nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var b custodyBOM
	if err := json.Unmarshal(rec.Content, &b); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	for _, c := range b.Components {
		if c.Name != walkdomain.StdlibModulePath {
			continue
		}
		assertStdlibPropertiesAreOnlyMarkers(t, c)
		var got []string
		for _, ref := range c.ExternalReferences {
			got = append(got, ref.Type+" "+ref.URL)
			if len(ref.Hashes) != 0 {
				t.Errorf("%s reference %s carries hashes %+v, but no published checksum was consulted", ref.Type, ref.URL, ref.Hashes)
			}
		}
		if want := "vcs https://go.googlesource.com/go,website https://go.dev/"; strings.Join(got, ",") != want {
			t.Errorf("offline stdlib references = %v, want %s", got, want)
		}
		if len(c.Hashes) != 0 {
			t.Errorf("offline stdlib hashes = %+v; they are over a local source manifest, not a published artefact", c.Hashes)
		}
		return
	}
	t.Fatal("stdlib component absent from SBOM")
}
