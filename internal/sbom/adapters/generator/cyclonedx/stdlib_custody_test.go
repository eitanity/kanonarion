package cyclonedx_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// custodyBOM is the CycloneDX shape needed to assert the stdlib chain of custody
// (hashes + properties), beyond what the shared bom struct reads.
type custodyBOM struct {
	Components []struct {
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
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"externalReferences"`
	} `json:"components"`
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

		// Properties: verification status + honest-limitation note.
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		if props["kanonarion:stdlib:verification"] != "VerifiedGoDevChecksum" {
			t.Errorf("verification property = %q", props["kanonarion:stdlib:verification"])
		}
		if props["kanonarion:stdlib:published_sha256"] != "aa256" {
			t.Errorf("published_sha256 property = %q", props["kanonarion:stdlib:published_sha256"])
		}
		if !strings.Contains(props["kanonarion:stdlib:anchor_limitation"], "weaker than a module sumdb") {
			t.Errorf("missing honest-limitation note: %q", props["kanonarion:stdlib:anchor_limitation"])
		}

		// External references: the source tarball distribution URL and the commit.
		var hasDist, hasCommit bool
		for _, ref := range c.ExternalReferences {
			if strings.Contains(ref.URL, "go.dev/dl/go1.26.4.src.tar.gz") {
				hasDist = true
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
	if !found {
		t.Fatal("stdlib component absent from SBOM")
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

// stdlibProps returns the stdlib component's properties from a generated
// document, failing when the component is absent.
func stdlibProps(t *testing.T, walk walkdomain.WalkRecord) map[string]string {
	t.Helper()
	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
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
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		return props
	}
	t.Fatal("stdlib component absent from SBOM")
	return nil
}

// TestGenerate_StdlibAnchorLimitationFollowsTheEvidence is the regression for a
// document that stated one fixed anchor sentence for every measurement. An
// offline run records VerifiedLocalToolchain — the published checksum not
// consulted, the commit anchor skipped — and the document asserted both anchors
// three lines below the detail that said neither happened. The stronger claim
// won, in an artefact written to be read where the store is not.
func TestGenerate_StdlibAnchorLimitationFollowsTheEvidence(t *testing.T) {
	const prop = "kanonarion:stdlib:anchor_limitation"

	anchored := stdlibProps(t, walkWithStdlibFacts(t, &walkdomain.StdlibFacts{
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: "VerifiedGoDevChecksum",
		VerificationDetail: "SHA-256 matched go.dev/dl published checksum",
		PublishedSHA256:    "aa256",
		SourceURL:          "https://go.dev/dl/go1.26.4.src.tar.gz",
		VCSURL:             "https://go.googlesource.com/go",
		VCSRef:             "go1.26.4",
		VCSCommit:          "deadbeefcafe",
	}))
	offline := stdlibProps(t, walkWithStdlibFacts(t, &walkdomain.StdlibFacts{
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: "VerifiedLocalToolchain",
		VerificationDetail: "digests computed over local toolchain source; go.dev/dl published checksum not consulted (offline); googlesource commit anchor skipped (offline)",
		SourceURL:          "/opt/go/src",
	}))

	if anchored[prop] == offline[prop] {
		t.Fatalf("anchor limitation does not vary with the evidence; both documents say:\n%s", anchored[prop])
	}
	if !strings.Contains(anchored[prop], "go.dev/dl publishes") {
		t.Errorf("connected document does not name the published-checksum anchor it reached:\n%s", anchored[prop])
	}
	if !strings.Contains(anchored[prop], "cross-checked against a go.googlesource.com/go release tag") {
		t.Errorf("connected document does not name the commit anchor it resolved:\n%s", anchored[prop])
	}
	// The offline document must not claim either anchor its own detail denies.
	for _, forbidden := range []string{"integrity anchored to", "cross-checked"} {
		if strings.Contains(offline[prop], forbidden) {
			t.Errorf("offline document claims %q, which its verification detail denies:\n%s", forbidden, offline[prop])
		}
	}
	if !strings.Contains(offline[prop], "locally-held toolchain source") {
		t.Errorf("offline document does not say what its integrity rests on:\n%s", offline[prop])
	}
	// The ceiling is the reason the property exists and holds on both routes.
	for name, got := range map[string]string{"connected": anchored[prop], "offline": offline[prop]} {
		if !strings.Contains(got, "weaker than a module sumdb transparency-log entry") ||
			!strings.Contains(got, "never present in go.sum") {
			t.Errorf("%s document dropped the sumdb/go.sum ceiling:\n%s", name, got)
		}
	}
}
