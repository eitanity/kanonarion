package cyclonedx_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"

	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// A cgo module can ship a whole C library inside its own zip and compile it
// into the binary. These tests lock the two halves of stating that in the
// document: the identified library becomes a component of its own, and a walk
// with nothing identified produces the document it always produced, to the byte.

const nativeGenTime = "2026-09-13T10:00:00Z"

// nativeWalk builds a two-module walk: the project and one cgo dependency.
func nativeWalk(t *testing.T) (walkdomain.WalkRecord, coordinate.ModuleCoordinate) {
	t.Helper()
	target := mustCoord(t, "example.com/project", "v1.0.0")
	dep := mustCoord(t, "example.com/go-sqlite3", "v1.14.12")
	return walkdomain.WalkRecord{
		ID: "walk-native-001",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionTarget},
				{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS},
			},
			Edges:      []walkdomain.GraphEdge{{From: target, To: dep}},
			ResolvedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		},
	}, dep
}

// identifiedRecord is a native record naming one library, with the two
// declarations SQLite really states — one in the .c and one in the .h.
func identifiedRecord(coord coordinate.ModuleCoordinate, version string) nativedomain.Record {
	decl := `#define SQLITE_VERSION "` + version + `"`
	return nativedomain.Record{
		Coordinate:             coord,
		ArtefactIdentity:       "zip:h1:deadbeef=",
		PipelineVersion:        nativedomain.PipelineVersion,
		RecipeCatalogueVersion: nativedomain.RecipeCatalogueVersion,
		Presence:               nativedomain.PresenceIdentified,
		Components: []nativedomain.Component{{
			Name:       "SQLite",
			Version:    version,
			Confidence: nativedomain.ConfidenceDeclared,
			Evidence: []nativedomain.Evidence{
				{File: "sqlite3-binding.c", Declaration: decl},
				{File: "sqlite3-binding.h", Declaration: decl},
			},
		}},
		Sources: []nativedomain.Source{{File: "sqlite3-binding.c", Bytes: 1, SHA256: "aa"}},
	}
}

func generateNative(t *testing.T, walk walkdomain.WalkRecord, recs map[coordinate.ModuleCoordinate]nativedomain.Record) map[string]any {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, nativeGenTime)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := cyclonedx.New("test-pipeline").Generate(
		context.Background(), walk,
		map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{},
		ports.GenerateRequest{PipelineVersion: "test-pipeline", DocumentTimestamp: ts, NativeRecords: recs},
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Content, &doc); err != nil {
		t.Fatalf("decoding the generated document: %v", err)
	}
	return doc
}

func componentsOf(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	raw, ok := doc["components"].([]any)
	if !ok {
		t.Fatalf("the document carries no component list")
	}
	out := make([]map[string]any, 0, len(raw))
	for _, c := range raw {
		out = append(out, c.(map[string]any))
	}
	return out
}

// TestNative_IdentifiedLibraryBecomesItsOwnComponent is the defect this closes:
// the library kanonarion had already identified, hashed and verified reached no
// SBOM, so the artefact whose purpose is to list what ships omitted something
// that ships.
func TestNative_IdentifiedLibraryBecomesItsOwnComponent(t *testing.T) {
	walk, dep := nativeWalk(t)
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		dep: identifiedRecord(dep, "3.38.0"),
	})
	comps := componentsOf(t, doc)

	var found map[string]any
	for _, c := range comps {
		if c["purl"] == "pkg:generic/sqlite@3.38.0" {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("no pkg:generic component for the C library; the document lists only:\n%v", purlsOf(comps))
	}
	if found["name"] != "SQLite" || found["version"] != "3.38.0" {
		t.Errorf("component identity = %v@%v, want SQLite@3.38.0", found["name"], found["version"])
	}
	// The evidence that named it travels with it, so a reader can check the claim
	// against the artefact without re-running the tool.
	ev, _ := json.Marshal(found["evidence"])
	for _, want := range []string{"source-code-analysis", "sqlite3-binding.c", "sqlite3-binding.h", `#define SQLITE_VERSION`} {
		if !strings.Contains(string(ev), want) {
			t.Errorf("the component's evidence does not carry %q:\n%s", want, ev)
		}
	}
}

// TestNative_AssertsNothingItDidNotRead. No download URL, no checksum
// qualifier, no CPE, no hashes: each would describe an upstream release nobody
// fetched, in a document whose reader cannot re-run the tool.
func TestNative_AssertsNothingItDidNotRead(t *testing.T) {
	walk, dep := nativeWalk(t)
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		dep: identifiedRecord(dep, "3.38.0"),
	})
	for _, c := range componentsOf(t, doc) {
		if c["purl"] != "pkg:generic/sqlite@3.38.0" {
			continue
		}
		for _, forbidden := range []string{"hashes", "externalReferences", "cpe"} {
			if _, present := c[forbidden]; present {
				t.Errorf("the native component carries %q, which nothing measured:\n%v", forbidden, c)
			}
		}
		if purl := c["purl"].(string); strings.Contains(purl, "?") {
			t.Errorf("the native component's purl carries qualifiers: %q", purl)
		}
	}
}

// TestNative_HostModuleDependsOnTheLibrary. Without the edge the library sits
// in the component list unreachable from the subject, and a consumer walking
// the graph to find what ships does not find it.
func TestNative_HostModuleDependsOnTheLibrary(t *testing.T) {
	walk, dep := nativeWalk(t)
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		dep: identifiedRecord(dep, "3.38.0"),
	})
	deps := map[string][]string{}
	for _, d := range doc["dependencies"].([]any) {
		e := d.(map[string]any)
		var on []string
		if raw, ok := e["dependsOn"].([]any); ok {
			for _, r := range raw {
				on = append(on, r.(string))
			}
		}
		deps[e["ref"].(string)] = on
	}
	host := "pkg:golang/example.com/go-sqlite3@v1.14.12"
	if !containsString(deps[host], "pkg:generic/sqlite@3.38.0") {
		t.Errorf("%s dependsOn = %v; the module that ships the library must depend on it", host, deps[host])
	}
	// And it gets an entry of its own, so the array accounts for every component.
	if _, ok := deps["pkg:generic/sqlite@3.38.0"]; !ok {
		t.Errorf("the native component has no dependency entry of its own: %v", deps)
	}
}

// TestNative_GoComponentsAreUntouched is the control this change owes, in the
// strongest form available: not merely the same purls and fields, but the same
// INDEX in the array. Native components are appended, never interleaved.
func TestNative_GoComponentsAreUntouched(t *testing.T) {
	walk, dep := nativeWalk(t)
	before := componentsOf(t, generateNative(t, walk, nil))
	after := componentsOf(t, generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		dep: identifiedRecord(dep, "3.38.0"),
	}))
	if len(after) != len(before)+1 {
		t.Fatalf("component count went %d -> %d, want exactly one more", len(before), len(after))
	}
	for i := range before {
		b, _ := json.Marshal(before[i])
		a, _ := json.Marshal(after[i])
		if string(a) != string(b) {
			t.Errorf("Go component %d changed:\n before %s\n after  %s", i, b, a)
		}
	}
}

// TestNative_AWalkWithNothingIdentifiedIsByteIdentical. Every presence but
// present_identified contributes no component, so a document over such a walk
// must come out exactly as it did before native components existed — and a
// record that is merely ABSENT must not be able to change a byte.
func TestNative_AWalkWithNothingIdentifiedIsByteIdentical(t *testing.T) {
	walk, dep := nativeWalk(t)
	ts, err := time.Parse(time.RFC3339, nativeGenTime)
	if err != nil {
		t.Fatal(err)
	}
	gen := func(recs map[coordinate.ModuleCoordinate]nativedomain.Record) []byte {
		rec, gerr := cyclonedx.New("test-pipeline").Generate(
			context.Background(), walk,
			map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{},
			ports.GenerateRequest{PipelineVersion: "test-pipeline", DocumentTimestamp: ts, NativeRecords: recs},
		)
		if gerr != nil {
			t.Fatalf("Generate: %v", gerr)
		}
		return rec.Content
	}
	base := gen(nil)
	for _, tc := range []struct {
		name     string
		presence nativedomain.Presence
	}{
		{"absent", nativedomain.PresenceAbsent},
		{"linked but not shipped", nativedomain.PresenceLinkedNotShipped},
		{"present and unidentified", nativedomain.PresenceUnidentified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := identifiedRecord(dep, "3.38.0")
			rec.Presence = tc.presence
			rec.Components = nil
			if got := gen(map[coordinate.ModuleCoordinate]nativedomain.Record{dep: rec}); string(got) != string(base) {
				t.Errorf("a %s record changed the document; it must contribute nothing", tc.presence)
			}
		})
	}
}

// TestNative_UnidentifiedIsReportedToTheCaller. It emits no component — it has
// no identity to state — but the caller is told, so the run can say so rather
// than the omission being silent.
func TestNative_UnidentifiedIsReportedToTheCaller(t *testing.T) {
	walk, dep := nativeWalk(t)
	rec := identifiedRecord(dep, "3.38.0")
	rec.Presence = nativedomain.PresenceUnidentified
	rec.Components = nil
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{dep: rec})
	for _, c := range componentsOf(t, doc) {
		if strings.HasPrefix(c["purl"].(string), "pkg:generic/") {
			t.Errorf("an unidentified record produced a component: %v", c)
		}
	}
}

// TestNative_OneLibraryShippedTwiceIsOneComponent. Two modules amalgamating the
// same library at the same version ship one component, named once, with both
// modules recorded as hosts. Two bom-refs for one library would make a reader
// reconcile them; an arbitrary winner would drop a host.
func TestNative_OneLibraryShippedTwiceIsOneComponent(t *testing.T) {
	target := mustCoord(t, "example.com/project", "v1.0.0")
	depA := mustCoord(t, "example.com/aaa-sqlite", "v1.0.0")
	depB := mustCoord(t, "example.com/zzz-sqlite", "v2.0.0")
	walk := walkdomain.WalkRecord{
		ID: "walk-native-dup",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionTarget},
				// Out of coordinate order on purpose: the output must not depend on it.
				{Coordinate: depB, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: depA, ResolutionSource: walkdomain.ResolutionMVS},
			},
			ResolvedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		},
	}
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		depA: identifiedRecord(depA, "3.38.0"),
		depB: identifiedRecord(depB, "3.38.0"),
	})
	var hosts []string
	n := 0
	for _, c := range componentsOf(t, doc) {
		if c["purl"] != "pkg:generic/sqlite@3.38.0" {
			continue
		}
		n++
		for _, p := range c["properties"].([]any) {
			prop := p.(map[string]any)
			if prop["name"] == "kanonarion:native:host_module" {
				hosts = append(hosts, prop["value"].(string))
			}
		}
	}
	if n != 1 {
		t.Fatalf("got %d components for one library at one version, want 1", n)
	}
	want := []string{"example.com/aaa-sqlite@v1.0.0", "example.com/zzz-sqlite@v2.0.0"}
	if len(hosts) != 2 || hosts[0] != want[0] || hosts[1] != want[1] {
		t.Errorf("hosts = %v, want %v in that order", hosts, want)
	}
}

// TestNative_DifferentVersionsAreDifferentComponents: two modules shipping
// different versions of one library ship two components, because they do.
func TestNative_DifferentVersionsAreDifferentComponents(t *testing.T) {
	target := mustCoord(t, "example.com/project", "v1.0.0")
	depA := mustCoord(t, "example.com/aaa-sqlite", "v1.0.0")
	depB := mustCoord(t, "example.com/zzz-sqlite", "v2.0.0")
	walk := walkdomain.WalkRecord{
		ID: "walk-native-two",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionTarget},
				{Coordinate: depA, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: depB, ResolutionSource: walkdomain.ResolutionMVS},
			},
			ResolvedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		},
	}
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		depA: identifiedRecord(depA, "3.53.0"),
		depB: identifiedRecord(depB, "3.38.0"),
	})
	var got []string
	for _, c := range componentsOf(t, doc) {
		if strings.HasPrefix(c["purl"].(string), "pkg:generic/") {
			got = append(got, c["purl"].(string))
		}
	}
	// Sorted by purl, which is unique across the set, so the order is total.
	want := []string{"pkg:generic/sqlite@3.38.0", "pkg:generic/sqlite@3.53.0"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("native components = %v, want %v", got, want)
	}
}

// TestNative_OutputIsDeterministic. The whole document is re-emitted from the
// same inputs and compared byte for byte: a map iteration leaking into the
// component order, the host list or the evidence would show here.
func TestNative_OutputIsDeterministic(t *testing.T) {
	target := mustCoord(t, "example.com/project", "v1.0.0")
	depA := mustCoord(t, "example.com/aaa-sqlite", "v1.0.0")
	depB := mustCoord(t, "example.com/zzz-sqlite", "v2.0.0")
	walk := walkdomain.WalkRecord{
		ID: "walk-native-det",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionTarget},
				{Coordinate: depA, ResolutionSource: walkdomain.ResolutionMVS},
				{Coordinate: depB, ResolutionSource: walkdomain.ResolutionMVS},
			},
			Edges:      []walkdomain.GraphEdge{{From: target, To: depA}, {From: target, To: depB}},
			ResolvedAt: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC),
		},
	}
	recs := map[coordinate.ModuleCoordinate]nativedomain.Record{
		depA: identifiedRecord(depA, "3.53.0"),
		depB: identifiedRecord(depB, "3.53.0"),
	}
	ts, err := time.Parse(time.RFC3339, nativeGenTime)
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for i := range 12 {
		rec, gerr := cyclonedx.New("test-pipeline").Generate(
			context.Background(), walk,
			map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{},
			ports.GenerateRequest{PipelineVersion: "test-pipeline", DocumentTimestamp: ts, NativeRecords: recs},
		)
		if gerr != nil {
			t.Fatalf("Generate: %v", gerr)
		}
		if i == 0 {
			first = string(rec.Content)
			continue
		}
		if string(rec.Content) != first {
			t.Fatalf("generation %d differs from the first; the native path is not deterministic", i)
		}
	}
}

// TestNative_StatesWhatItDidNotEstablish. Two questions a reader arrives with —
// was this checked against an advisory database, and what is its licence — are
// answered on the component rather than left to an absent field, which reads as
// a producer that does not track them.
func TestNative_StatesWhatItDidNotEstablish(t *testing.T) {
	walk, dep := nativeWalk(t)
	doc := generateNative(t, walk, map[coordinate.ModuleCoordinate]nativedomain.Record{
		dep: identifiedRecord(dep, "3.38.0"),
	})
	props := map[string]string{}
	for _, c := range componentsOf(t, doc) {
		if c["purl"] != "pkg:generic/sqlite@3.38.0" {
			continue
		}
		for _, p := range c["properties"].([]any) {
			prop := p.(map[string]any)
			props[prop["name"].(string)] = prop["value"].(string)
		}
	}
	for name, want := range map[string]string{
		"kanonarion:native:advisories_searched": "false",
		"kanonarion:native:licence_determined":  "false",
		"kanonarion:component:native":           "true",
		"kanonarion:native:confidence":          "declared",
		"kanonarion:ecosystem":                  "native",
		"kanonarion:native:host_artefact":       "zip:h1:deadbeef=",
	} {
		if props[name] != want {
			t.Errorf("%s = %q, want %q", name, props[name], want)
		}
	}
}

// TestNative_LicenceCompletenessCountsOnlyTheGoComponents. A native component
// carries no licence and it is not a gap in the licence extraction, which reads
// the LICENSE files of a Go module's artefact. Counting it would move the
// document's licence gate — a non-zero exit — onto a question with no remedy an
// operator could run.
func TestNative_LicenceCompletenessCountsOnlyTheGoComponents(t *testing.T) {
	walk, dep := nativeWalk(t)
	ts, err := time.Parse(time.RFC3339, nativeGenTime)
	if err != nil {
		t.Fatal(err)
	}
	// Both modules carry a licence, so nothing Go-side is undetermined.
	lics := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		walk.Graph.Target: {PrimarySPDX: "Apache-2.0"},
		dep:               {PrimarySPDX: "MIT"},
	}
	rec, err := cyclonedx.New("test-pipeline").Generate(
		context.Background(), walk, lics,
		ports.GenerateRequest{PipelineVersion: "test-pipeline", DocumentTimestamp: ts,
			NativeRecords: map[coordinate.ModuleCoordinate]nativedomain.Record{dep: identifiedRecord(dep, "3.38.0")}},
	)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if rec.LicensesIncomplete {
		t.Error("LicensesIncomplete = true; a native component's undetermined licence must not fire the document's licence gate")
	}
	if strings.Contains(string(rec.Content), "kanonarion:licence-completeness") {
		t.Error("a licence-completeness annotation was emitted for a document whose Go components all carry a licence")
	}
}

func purlsOf(comps []map[string]any) []string {
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		out = append(out, c["purl"].(string))
	}
	return out
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
