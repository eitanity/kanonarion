package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestCallGraphShowJSON_CarriesTheArtefactKind: the dimension that decides how a
// reachability traversal over this graph is rooted — and therefore whether a
// negative answer over it could ever be confirmed — reached no read surface at
// all. Measured before this: callgraph-show --json published 24 keys and
// artifact_kind was not among them, so a reader could not tell a graph rooted at
// a library's public API from one rooted at every function an application ships.
func TestCallGraphShowJSON_CarriesTheArtefactKind(t *testing.T) {
	for kind, want := range map[cgdomain.ArtifactKind]string{
		cgdomain.ArtifactApplication:    "Application",
		cgdomain.ArtifactLibrary:        "Library",
		cgdomain.ArtifactNotEstablished: "NotEstablished",
	} {
		rec := referenceAxisRecord()
		rec.ArtifactKind = kind

		b, err := json.Marshal(toCallGraphJSON(rec))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got, present := doc["artifact_kind"]
		if !present {
			t.Fatalf("kind %q: artifact_kind absent from the record", kind)
		}
		if got != want {
			t.Errorf("kind %q rendered as %v, want %q", kind, got, want)
		}
	}
}

// TestCallGraphShowJSON_LibraryIsNamedNotBlank is the trap this axis sets and
// every other axis here avoids. A library's STORED kind is the empty string, so
// publishing the raw field renders a measured library as a blank — and the "not
// recorded" token the other axes use would be a second wrong answer, because the
// library kind is a positive finding: every package loaded and none builds a
// command.
func TestCallGraphShowJSON_LibraryIsNamedNotBlank(t *testing.T) {
	rec := referenceAxisRecord()
	rec.ArtifactKind = cgdomain.ArtifactLibrary

	b, err := json.Marshal(toCallGraphJSON(rec))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	switch doc["artifact_kind"] {
	case "":
		t.Error("a measured library publishes as a blank, which reads as an absent measurement")
	case jsonNotRecorded:
		t.Error("a measured library publishes as 'not recorded'; it is a finding, not an absence")
	}
}

// TestCallGraphShow_PrintsTheArtefactKind: the text surface states it too, so the
// two surfaces cannot disagree about which rooting produced an answer.
func TestCallGraphShow_PrintsTheArtefactKind(t *testing.T) {
	var buf bytes.Buffer
	rec := referenceAxisRecord()
	rec.ArtifactKind = cgdomain.ArtifactApplication

	if err := printCallGraphRecord(rec, 0, 0, &buf); err != nil {
		t.Fatalf("printing record: %v", err)
	}
	if !strings.Contains(buf.String(), "kind: Application") {
		t.Errorf("the text surface does not state the artefact kind:\n%s", buf.String())
	}
}
