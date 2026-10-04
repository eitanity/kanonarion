package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TestIsReFetchable_ExcludesTheStandardLibrary: every remedy that offers a
// fetch asks this question first, so the one place the standard library has to
// be excluded is here rather than at each site.
func TestIsReFetchable_ExcludesTheStandardLibrary(t *testing.T) {
	t.Parallel()

	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	if domain.IsReFetchable(stdlib) {
		t.Error("the standard library is reported as fetchable, so every remedy built on this offers a fetch that refuses it")
	}
	published, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	if !domain.IsReFetchable(published) {
		t.Error("a published module is no longer fetchable, so its remedies lose the step that obtains it")
	}
}

// TestReanalysisInstruction_StandardLibrary: the command that analyses the
// standard library IS `callgraph stdlib@<version>`, so the remedy names it.
func TestReanalysisInstruction_StandardLibrary(t *testing.T) {
	t.Parallel()

	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	if got := domain.ReanalysisInstruction(stdlib, ""); got != "kanonarion callgraph stdlib@v1.26.5" {
		t.Errorf("ReanalysisInstruction = %q", got)
	}
}

// TestWeakerCompleteness is the rule a joined traversal rests on: a conclusion
// that crossed two graphs may claim only the lower of their fidelities.
func TestWeakerCompleteness(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		a, b, want domain.CompletenessLevel
	}{
		{domain.CompletenessBuiltWithBodies, domain.CompletenessBuiltWithBodies, domain.CompletenessBuiltWithBodies},
		{domain.CompletenessBuiltWithBodies, domain.CompletenessTypeOnly, domain.CompletenessTypeOnly},
		{domain.CompletenessTypeOnly, domain.CompletenessBuiltWithBodies, domain.CompletenessTypeOnly},
		{domain.CompletenessMetadataOnly, domain.CompletenessFailed, domain.CompletenessFailed},
		{domain.CompletenessBuiltWithBodies, domain.CompletenessUnknown, domain.CompletenessUnknown},
		{domain.CompletenessBuiltWithBodies, "INVENTED", "INVENTED"},
	} {
		if got := domain.WeakerCompleteness(tc.a, tc.b); got != tc.want {
			t.Errorf("WeakerCompleteness(%s, %s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestAnalysisSourceToolchainSource_IsDiscriminatedByTheTreeItRead: the
// artefact identity of a standard-library graph names the PUBLISHED tarball
// the custody chain holds, which is not what the analysis read, so the
// discriminator has to be the source-tree digest.
func TestAnalysisSourceToolchainSource_IsDiscriminatedByTheTreeItRead(t *testing.T) {
	t.Parallel()

	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	rec := domain.CallGraphRecord{
		Coordinate:       stdlib,
		AnalysisSource:   domain.AnalysisSourceToolchainSource,
		ArtefactIdentity: "sha256:published",
		WorktreeDigest:   "analysed-sha256:read",
	}
	source, discriminator := domain.RecordAnalysisSource(rec)
	if source != domain.AnalysisSourceToolchainSource {
		t.Errorf("source = %q", source)
	}
	if discriminator != "analysed-sha256:read" {
		t.Errorf("discriminator = %q, want the digest of the tree that was read", discriminator)
	}
	if !domain.NamesAnalysedContent(rec) {
		t.Error("the record says what it read and is reported as saying nothing")
	}
}

// TestCallGraphConflict_StandardLibraryRemedyNamesAReadableSource: a build that
// cannot read a record's source kind points the reader at one it can, and for
// the standard library that is its own source rather than a working tree.
func TestCallGraphConflict_StandardLibraryRemedyNamesAReadableSource(t *testing.T) {
	t.Parallel()

	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	remedy := domain.CallGraphConflict{Coordinate: stdlib, Field: domain.ConflictFieldAnalysisSource}.Remedy()
	joined := strings.Join(remedy.Lines, "\n")
	if !strings.Contains(joined, "--source "+string(domain.AnalysisSourceToolchainSource)) {
		t.Errorf("the remedy does not name the source a standard-library record carries:\n%s", joined)
	}
}

// TestIsStdlibPackage is the go command's own rule, and the one statement of it
// the analysis and both reads share: a module path's first element carries a
// dot, a standard-library path's does not.
//
// It takes a PACKAGE path, never a node id. "fmt.Println" is an id whose first
// element carries a dot and would read as a module, which is why every caller
// reads the package off the node instead of parsing the id.
func TestIsStdlibPackage(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]bool{
		"net/http":                     true,
		"fmt":                          true,
		"internal/godebug":             true,
		"vendor/golang.org/x/net/idna": true,
		"":                             false,
		"example.com/mod":              false,
		"gopkg.in/yaml.v2":             false,
	} {
		if got := domain.IsStdlibPackage(path); got != want {
			t.Errorf("IsStdlibPackage(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestReanalysisCommand_FillsASlotOrDeclines: a remedy slot takes a command or
// takes nothing. The sentence form exists for prose, and splicing it into
// "extract it with: …" composed text that read as an invocation and was not
// one — measured on a live store against a project-rooted frame.
func TestReanalysisCommand_FillsASlotOrDeclines(t *testing.T) {
	t.Parallel()

	published, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}

	for _, tc := range []struct {
		name  string
		coord coordinate.ModuleCoordinate
		dir   string
		force bool
		want  string
		ok    bool
	}{
		{name: "published", coord: published, want: "kanonarion callgraph example.com/mod@v1.0.0", ok: true},
		{name: "published forced", coord: published, force: true,
			want: "kanonarion callgraph example.com/mod@v1.0.0 --force", ok: true},
		{name: "standard library", coord: stdlib, want: "kanonarion callgraph stdlib@v1.26.5", ok: true},
		{name: "local with a named tree", coord: local, dir: "/srv/app",
			want: "kanonarion local /srv/app", ok: true},
		{name: "local with a named tree, forced", coord: local, dir: "/srv/app", force: true,
			want: "kanonarion local /srv/app --force", ok: true},
		{name: "local with no named tree", coord: local, ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := domain.ReanalysisCommand(tc.coord, tc.dir, tc.force)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (line %q)", ok, tc.ok, got)
			}
			if got != tc.want {
				t.Errorf("line = %q, want %q", got, tc.want)
			}
			if !ok && got != "" {
				t.Errorf("a declined slot was filled with %q", got)
			}
		})
	}
}

// TestComposeStdlibGeneration_AnswersAlongsideSilentRecords: the standard
// library's coordinate is reachable by no other route, so its records answer
// beside the ones that name no source at all.
func TestComposeStdlibGeneration_AnswersAlongsideSilentRecords(t *testing.T) {
	t.Parallel()

	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	rec := domain.CallGraphRecord{
		SchemaVersion:    domain.CallGraphSchemaVersion,
		Ecosystem:        "go",
		Coordinate:       stdlib,
		Algorithm:        domain.AlgorithmCHA,
		Completeness:     domain.CompletenessBuiltWithBodies,
		AnalysisSource:   domain.AnalysisSourceToolchainSource,
		AnalysisRoot:     "/usr/local/go/src",
		WorktreeDigest:   "analysed-sha256:abc",
		ArtefactIdentity: "sha256:495be4bc",
		OverallStatus:    domain.CallGraphStatusExtracted,
		PipelineVersion:  "0.7.0",
		Nodes:            []domain.CallNode{{ID: "net/http.Get", Module: "stdlib", Package: "net/http", Symbol: "Get"}},
	}
	sealed, err := domain.CallGraphRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	got, cerr := domain.Compose([]domain.CallGraphRecord{sealed}, domain.ComposeRequest{})
	if cerr != nil {
		t.Fatalf("Compose refused a standard-library generation: %v", cerr)
	}
	if got.ContentHash != sealed.ContentHash {
		t.Errorf("composed %s, want the one generation held", got.ContentHash)
	}
}

// TestCallGraphConflict_UnpublishedCoordinateIsReAnalysedNotReFetched: two
// identities under one name mean two source trees were analysed as one, and
// where nothing published the bytes there is no fetch to settle it — only
// re-analysing the tree in hand. The standard library is in that class
// alongside a working tree: it arrives with the toolchain.
func TestCallGraphConflict_UnpublishedCoordinateIsReAnalysedNotReFetched(t *testing.T) {
	t.Parallel()

	stdlib, err := coordinate.NewStdlibCoordinateAt("v1.26.5")
	if err != nil {
		t.Fatalf("stdlib coordinate: %v", err)
	}
	remedy := domain.CallGraphConflict{
		Coordinate:   stdlib,
		Field:        domain.ConflictFieldArtefactIdentity,
		AnalysisRoot: "/usr/local/go/src",
	}.Remedy()
	joined := strings.Join(remedy.Lines, "\n")
	if strings.Contains(joined, "kanonarion fetch") {
		t.Errorf("the remedy offers a fetch for a coordinate fetch refuses:\n%s", joined)
	}
	if !strings.Contains(joined, "kanonarion callgraph stdlib@v1.26.5") {
		t.Errorf("the remedy does not name the command that re-analyses it:\n%s", joined)
	}
	if strings.Contains(remedy.Lead, "project coordinate") {
		t.Errorf("the lead calls the standard library a project coordinate: %s", remedy.Lead)
	}
}
