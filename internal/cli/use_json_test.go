package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// useDocumentFor renders a selection the way the command does — copy first,
// document second — against one module cache directory, so a second call over
// the same directory meets the entries the first one wrote. That is how a real
// run meets an already-present module, and it is the only way to produce one
// without asserting the state into existence.
func useDocumentFor(t *testing.T, cache string, facts *pvFakeFacts, blobs *useBlobs,
	selection []useCandidate,
) (useDocument, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tally := copySelection(context.Background(), selection, facts, blobs, cache, logger, &stdout, &stderr)
	writeUseSummary(tally, &stderr)
	walk := walkdomain.WalkRecord{ID: "01USEDOC00000000000000000"}
	return useDocumentOf(coordinatetest.MustNew("example.com/app", "v1.0.0"), walk, true, cache, tally),
		stderr.String()
}

// outcomeOf finds one module's entry by coordinate, so an assertion names the
// module it is about rather than an index into an array whose order a later
// change could alter.
func outcomeOf(t *testing.T, doc useDocument, coord string) useModuleJSON {
	t.Helper()
	for _, m := range doc.Modules {
		if m.Coordinate == coord {
			return m
		}
	}
	t.Fatalf("the document names no entry for %s; it holds %d: %+v", coord, len(doc.Modules), doc.Modules)
	return useModuleJSON{}
}

// Copied, already present and failed are three outcomes, and two of them were
// indistinguishable from stdout alone: a module the run wrote and one it found
// already in the cache both printed "Copied ... to local cache", and a module
// that did not reach the cache was named on the other stream entirely. A
// consumer reading stdout therefore saw only what worked and concluded the copy
// was complete.
func TestUseDocument_CopiedAlreadyPresentAndFailedAreThreeOutcomes(t *testing.T) {
	facts := newPVFakeFacts()
	blobs := newUseBlobs()
	present := coordinatetest.MustNew("example.com/present", "v1.0.0")
	fresh := coordinatetest.MustNew("example.com/fresh", "v2.0.0")
	lost := coordinatetest.MustNew("example.com/lost", "v3.0.0")
	seedCopyableModule(t, facts, blobs, present)
	seedCopyableModule(t, facts, blobs, fresh)

	cache := t.TempDir()
	// The first run is what puts one module in the cache; the second meets it.
	useDocumentFor(t, cache, facts, blobs, []useCandidate{{coord: present, source: walkdomain.ResolutionMVS}})

	doc, stderr := useDocumentFor(t, cache, facts, blobs, []useCandidate{
		{coord: present, source: walkdomain.ResolutionMVS},
		{coord: fresh, source: walkdomain.ResolutionMVS},
		{coord: lost, source: walkdomain.ResolutionMVS},
		{coord: coordinatetest.MustNew("example.com/project", coordinate.LocalVersion),
			source: walkdomain.ResolutionLocalMainModule},
	})

	for _, want := range []struct {
		coord   string
		outcome string
		present bool
	}{
		{present.String(), useAlreadyPresent, true},
		{fresh.String(), useCopied, false},
		{lost.String(), useFailed, false},
		{"example.com/project@" + coordinate.LocalVersion, useNoArtefact, false},
	} {
		got := outcomeOf(t, doc, want.coord)
		if got.Outcome != want.outcome {
			t.Errorf("%s: outcome %q, want %q — the three states must be distinguishable in the document",
				want.coord, got.Outcome, want.outcome)
		}
		if got.AlreadyPresent != want.present {
			t.Errorf("%s: already_present %v, want %v", want.coord, got.AlreadyPresent, want.present)
		}
	}

	// The two that are in the cache say where; the two that are not say why.
	if got := outcomeOf(t, doc, fresh.String()); got.CachePath == "" {
		t.Error("a module that reached the cache must say where in it: cache_path is empty")
	}
	if got := outcomeOf(t, doc, present.String()); got.CachePath == "" {
		t.Error("an already-present module is in the cache and must say where: cache_path is empty")
	}
	failed := outcomeOf(t, doc, lost.String())
	if failed.Error == "" {
		t.Error("a module that failed must say why in the document, not only on stderr")
	}
	if failed.CachePath != "" {
		t.Errorf("a module that did not reach the cache occupies no directory in it, got %q", failed.CachePath)
	}
	absent := outcomeOf(t, doc, "example.com/project@"+coordinate.LocalVersion)
	if absent.NoArtefactReason == "" {
		t.Error("a module with nothing to copy must name what it is; an unexplained absence reads as a loss")
	}

	// The counts are the same run as numbers, and the summary line is measured
	// against them: a document whose counts disagreed with the sentence a person
	// reads would be a second answer, not the same one.
	want := useCountsJSON{Selected: 4, WithArtefact: 3, Copied: 1, AlreadyPresent: 1, InCache: 2, Failed: 1, NoArtefact: 1}
	if doc.Counts != want {
		t.Errorf("counts %+v, want %+v", doc.Counts, want)
	}
	if line := "copied 2 of 3 modules with a stored artefact"; !strings.Contains(stderr, line) {
		t.Errorf("the summary must state in_cache of with_artefact %q, got:\n%s", line, stderr)
	}
}

// Zero is a value. A run that copied nothing states that, rather than answering
// with an empty document a reader cannot tell from one that measured nothing.
func TestUseDocument_ARunThatCopiedNothingStatesZero(t *testing.T) {
	facts := newPVFakeFacts()
	blobs := newUseBlobs()
	doc, _ := useDocumentFor(t, t.TempDir(), facts, blobs, []useCandidate{
		{coord: coordinatetest.MustNew("example.com/project", coordinate.LocalVersion),
			source: walkdomain.ResolutionLocalMainModule},
	})

	if doc.Counts.Copied != 0 || doc.Counts.InCache != 0 || doc.Counts.WithArtefact != 0 {
		t.Errorf("a run that copied nothing must say so with counts, got %+v", doc.Counts)
	}
	if doc.Counts.Selected != 1 || doc.Counts.NoArtefact != 1 {
		t.Errorf("the run was asked about one module and must still say so, got %+v", doc.Counts)
	}

	// The zeros have to be in the bytes, not only in the struct: a count erased
	// by omitempty is absent, and absent is how a consumer spells "unmeasured".
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling the document: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshalling the document: %v", err)
	}
	counts, ok := decoded["counts"].(map[string]any)
	if !ok {
		t.Fatalf("the document carries no counts object: %s", body)
	}
	for _, key := range []string{"selected", "with_artefact", "copied", "already_present", "in_cache", "failed", "no_artefact"} {
		if _, present := counts[key]; !present {
			t.Errorf("counts.%s is absent from the document; a zero that is not printed cannot be read as a zero: %s", key, body)
		}
	}
	// An empty modules array is still an array. A null there is a second shape
	// for the same answer, and the parsers that meet it first are the ones that
	// break.
	if !strings.Contains(string(body), `"modules":[`) {
		t.Errorf("the modules member must be an array whatever its length, got: %s", body)
	}
}

// The per-module lines and the document are two renderings of one run, and only
// one of them can be on stdout: a "Copied ..." line in front of a JSON object is
// prose a parser has to read past. The routing is a seam because the run that
// exercises it needs a store, a blob for every module and a module cache — and
// the property being pinned is the choice, not the copy.
func TestUseLineWriter_TheDocumentIsAloneOnStdout(t *testing.T) {
	var stdout bytes.Buffer
	if got := useLineWriter(&stdout, false); got != io.Writer(&stdout) {
		t.Errorf("a text run writes its per-module lines to stdout, got %T", got)
	}
	if got := useLineWriter(&stdout, true); got != io.Discard {
		t.Errorf("under --json the per-module lines must go nowhere, got %T", got)
	}
}

// The end-to-end contract: one document on stdout and nothing else, with every
// selected module in it. This is the invocation the enumerated JSON-stdout guard
// runs, so it is exercised here in the same terms — a store the fixture seeded,
// a module cache the test owns, and no network.
func TestUseJSON_StdoutIsOneDocumentNamingEveryModule(t *testing.T) {
	fx := newJSONStdoutFixture(t)
	cache := t.TempDir()

	var stdout, stderr bytes.Buffer
	// The error is deliberately ignored: the fixture holds fetch records and no
	// blobs, so the copy fails and the run exits non-zero. What it wrote to
	// stdout is the assertion, and a failing run is the case that matters —
	// it is the one whose answer used to be invisible there.
	_ = Run([]string{"use", jsonDocRootCoord, "--recursive", "--walk-id", jsonDocWalkID,
		"--mod-cache", cache, "--json", "--store-root", fx.storeRoot}, &stdout, &stderr)

	doc := assertSingleJSONDocument(t, "use --json", stdout.Bytes())
	if got := doc["mod_cache"]; got != cache {
		t.Errorf("the document must name the destination cache once, got %v want %s", got, cache)
	}
	if got := doc["target"]; got != jsonDocRootCoord {
		t.Errorf("the document must name what was asked for, got %v want %s", got, jsonDocRootCoord)
	}
	if got := doc["recursive"]; got != true {
		t.Errorf("recursive is %v: the difference between the walk's closure and one module is the answer's scope", got)
	}
	if got := doc["walk_id"]; got != jsonDocWalkID {
		t.Errorf("the document must name the walk that supplied the bytes, got %v want %s", got, jsonDocWalkID)
	}
	// The frame is checked against the sentence a person is shown rather than
	// against a literal, so the two renderings cannot come to name different
	// builds for one copy.
	frame, ok := doc["walk_frame"].(string)
	if !ok || frame == "" {
		t.Errorf("walk_frame is %v: a cache entry carries nothing saying which build put it there", doc["walk_frame"])
	} else if !strings.Contains(stderr.String(), "(frame "+frame+")") {
		t.Errorf("the document names frame %q and stderr names another:\n%s", frame, stderr.String())
	}
	modules, ok := doc["modules"].([]any)
	if !ok || len(modules) != 2 {
		t.Fatalf("the walk holds two modules and both must appear whatever became of them, got %v", doc["modules"])
	}
	for _, m := range modules {
		entry, ok := m.(map[string]any)
		if !ok {
			t.Fatalf("a module entry is %T, want an object", m)
		}
		if entry["outcome"] != useFailed {
			t.Errorf("the fixture holds no blobs, so every module fails to copy; got outcome %v for %v",
				entry["outcome"], entry["coordinate"])
		}
		if entry["error"] == "" || entry["error"] == nil {
			t.Errorf("a failure must say why on the stream the consumer reads: %v", entry)
		}
	}
	// The same failures are still named for a person, on the stream that carries
	// the run's statements in both modes.
	if !strings.Contains(stderr.String(), "did not reach the cache") {
		t.Errorf("--json must not silence the stderr statements, got:\n%s", stderr.String())
	}
}
