package cli

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// Each section context reports not run names the invocation that produces its
// record, leading with the acquisition the producer refuses to run without.
func TestContextProducers_NameTheProducerFetchedAndUnfetched(t *testing.T) {
	published := mustCoord(t, "example.com/mod", "v1.0.0")
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	stdlib := mustCoord(t, "stdlib", "v1.27.2")
	const fetch = "kanonarion fetch example.com/mod@v1.0.0 && "
	const ingest = "kanonarion walk --gomod /work/app/go.mod --analyse-root && "
	for _, tc := range []struct {
		name    string
		coord   coordinate.ModuleCoordinate
		fetched bool
		dir     string
		want    contextCommands
	}{
		{"published, fetched", published, true, "", contextCommands{
			Interface: "kanonarion interface example.com/mod@v1.0.0",
			Examples:  "kanonarion examples example.com/mod@v1.0.0",
			License:   "kanonarion license example.com/mod@v1.0.0",
			CallGraph: fetch + "kanonarion callgraph example.com/mod@v1.0.0",
		}},
		{"published, unfetched", published, false, "", contextCommands{
			Interface: fetch + "kanonarion interface example.com/mod@v1.0.0",
			Examples:  fetch + "kanonarion examples example.com/mod@v1.0.0",
			License:   fetch + "kanonarion license example.com/mod@v1.0.0",
			CallGraph: fetch + "kanonarion callgraph example.com/mod@v1.0.0",
		}},
		{"working tree, ingested", local, true, "/work/app", contextCommands{
			Interface: "kanonarion interface example.com/app@local",
			Examples:  "kanonarion examples example.com/app@local",
			License:   "kanonarion license example.com/app@local",
			CallGraph: "kanonarion local /work/app",
		}},
		{"working tree, not ingested", local, false, "/work/app", contextCommands{
			Interface: ingest + "kanonarion interface example.com/app@local",
			Examples:  ingest + "kanonarion examples example.com/app@local",
			License:   ingest + "kanonarion license example.com/app@local",
			CallGraph: "kanonarion local /work/app",
		}},
		// Nothing names the tree, so no line can be printed that would run.
		{"working tree nothing names", local, false, "", contextCommands{
			License: "kanonarion license example.com/app@local",
		}},
		{"standard library", stdlib, false, "", contextCommands{
			License:   "kanonarion license stdlib@v1.27.2",
			CallGraph: "kanonarion callgraph stdlib@v1.27.2",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := contextProducers(tc.coord, tc.fetched, tc.dir); got != tc.want {
				t.Errorf("contextProducers = %+v\nwant              %+v", got, tc.want)
			}
		})
	}
}

// The working tree behind a local coordinate is read off the document's walk
// only when that walk was rooted at it.
func TestBasisDir_IsTheWalkRootsTreeOnly(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	rec := walkdomain.WalkRecord{Target: local, ProjectDir: "/work/app"}
	if got := basisDir(local, walkAsBasis(rec)); got != "/work/app" {
		t.Errorf("basisDir(root) = %q, want the walk's tree", got)
	}
	if got := basisDir(mustCoord(t, "example.com/mod", "v1.0.0"), walkAsBasis(rec)); got != "" {
		t.Errorf("basisDir(published) = %q, want none", got)
	}
	if got := basisDir(local, basisWalk{}); got != "" {
		t.Errorf("basisDir(no walk) = %q, want none", got)
	}
}

// The document's commands carry the producers, judged by the fetch section.
func TestBuildCommandsWithWalk_ReadsFetchedFromVerification(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	got := buildCommandsWithWalk(coord, "", contextVerification{Status: sectionStatusNotFetched}, basisWalk{})
	if want := "kanonarion fetch example.com/mod@v1.0.0 && kanonarion interface example.com/mod@v1.0.0"; got.Interface != want {
		t.Errorf("Interface = %q, want %q", got.Interface, want)
	}
	got = buildCommandsWithWalk(coord, "", contextVerification{Status: "Verified"}, basisWalk{})
	if want := "kanonarion interface example.com/mod@v1.0.0"; got.Interface != want {
		t.Errorf("Interface = %q, want %q", got.Interface, want)
	}
}

// The vulnerability section names the scan that produces its record: the walk
// it reads, else inspect for a published coordinate no walk holds.
func TestVulnProducer_NamesTheScanThatProducesTheRecord(t *testing.T) {
	published := mustCoord(t, "example.com/mod", "v1.0.0")
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	basis := walkAsBasis(walkdomain.WalkRecord{ID: "01BASISWALK000000000000000"})
	for _, tc := range []struct {
		name   string
		coord  coordinate.ModuleCoordinate
		walkID string
		basis  basisWalk
		want   string
	}{
		{"a walk rooted at the coordinate", published, "01ROOTEDWALK00000000000000", basisWalk{}, "kanonarion vuln-scan 01ROOTEDWALK00000000000000"},
		{"the document's walk", published, "", basis, "kanonarion vuln-scan 01BASISWALK000000000000000"},
		{"no walk at all", published, "", basisWalk{}, "kanonarion inspect example.com/mod@v1.0.0"},
		{"a working tree no walk holds", local, "", basisWalk{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := vulnProducer(tc.coord, tc.walkID, tc.basis); got != tc.want {
				t.Errorf("vulnProducer = %q, want %q", got, tc.want)
			}
		})
	}
}
