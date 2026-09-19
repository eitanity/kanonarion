package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// What `local` and `callgraph` return under --json.
//
// Both go through printCallGraphSummary, and the document they return is the
// record document WITHOUT the two arrays. Not a new shape: every scalar stays at
// the key it had, in the order it had, because a consumer reading
// worktree_digest or the counts out of it has to go on reading them. The graph
// itself is read with `callgraph-show <coord> --limit-nodes 0 --limit-edges 0
// --json`, which does not change.
//
// `--json` is inherited from `preferences.json`, so whatever these commands emit
// can be in force with no flag typed. Both routes are asserted to produce one
// document.

// summaryDoc renders one record through the surface `local` and `callgraph`
// share, and returns the bytes a --json consumer receives.
func summaryDoc(t *testing.T, r cgdomain.CallGraphRecord, run callGraphRunJSON) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := printCallGraphSummary(r, false, true, "", &buf, run); err != nil {
		t.Fatalf("rendering the summary: %v", err)
	}
	return buf.Bytes()
}

// objectKeysInOrder reads a JSON object's top-level keys in the order they were
// written. Two documents' key ORDER is part of what this change promises not to
// move, and a decode into a map loses it.
func objectKeysInOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("expected a JSON object, got token %v (%v)", tok, err)
	}
	var keys []string
	for dec.More() {
		k, kerr := dec.Token()
		if kerr != nil {
			t.Fatalf("reading a key: %v", kerr)
		}
		name, ok := k.(string)
		if !ok {
			t.Fatalf("object key is not a string: %v", k)
		}
		keys = append(keys, name)
		// Consume the value whole, whatever its shape.
		if verr := skipJSONValue(dec); verr != nil {
			t.Fatalf("skipping the value of %q: %v", name, verr)
		}
	}
	return keys
}

// skipJSONValue consumes exactly one value, descending through arrays and
// objects so a nested delimiter is never mistaken for the end of the document.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("reading a value: %w", err)
	}
	depth := 0
	switch tok {
	case json.Delim('{'), json.Delim('['):
		depth = 1
	default:
		return nil
	}
	for depth > 0 {
		t, terr := dec.Token()
		if terr != nil {
			return fmt.Errorf("descending into a value: %w", terr)
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
	return nil
}

// TestCallGraphSummaryJSON_IsTheRecordDocumentWithoutTheTwoArrays is the
// decision itself, asserted as a key list rather than a field list: nothing is
// dropped, nothing is renamed, nothing moves, and exactly two keys go.
func TestCallGraphSummaryJSON_IsTheRecordDocumentWithoutTheTwoArrays(t *testing.T) {
	r := makeCGRecord(t)

	record, err := json.Marshal(toCallGraphJSON(r))
	if err != nil {
		t.Fatalf("marshalling the record document: %v", err)
	}
	recordKeys := objectKeysInOrder(t, record)
	summaryKeys := objectKeysInOrder(t, summaryDoc(t, r, callGraphRunJSON{}))

	var want []string
	for _, k := range recordKeys {
		if k == "nodes" || k == "edges" {
			continue
		}
		want = append(want, k)
	}
	if strings.Join(summaryKeys, ",") != strings.Join(want, ",") {
		t.Errorf("the summary's keys are not the record document's minus the two arrays.\n got: %v\nwant: %v",
			summaryKeys, want)
	}
	// Stated separately so a record document that stopped carrying the arrays
	// could not make the comparison above pass vacuously.
	for _, k := range []string{"nodes", "edges"} {
		if !slices.Contains(recordKeys, k) {
			t.Fatalf("the record document no longer carries %q; this test compares against it", k)
		}
	}
}

// TestCallGraphSummaryJSON_CarriesTheFactsAKnownRunUsed pins the fields the one
// recorded use of this surface read: benchmark run K2c took the worktree digest
// and the node and edge counts out of `local . --json` and used the delta as its
// answer. They are not optional.
func TestCallGraphSummaryJSON_CarriesTheFactsAKnownRunUsed(t *testing.T) {
	r := makeCGRecord(t)
	r.WorktreeDigest = "sha256:106255e0"
	r.WorktreeScanDigest = "sha256:deadbeef"
	r.AnalysisSource = cgdomain.AnalysisSourceWorktree

	var doc map[string]any
	if err := json.Unmarshal(summaryDoc(t, r, callGraphRunJSON{}), &doc); err != nil {
		t.Fatalf("decoding the summary: %v", err)
	}
	if got := doc["worktree_digest"]; got != "sha256:106255e0" {
		t.Errorf("worktree_digest = %v, want the record's", got)
	}
	if got := doc["worktree_scan_digest"]; got != "sha256:deadbeef" {
		t.Errorf("worktree_scan_digest = %v, want the record's", got)
	}
	if got := doc["node_count"]; got != float64(2) {
		t.Errorf("node_count = %v, want 2", got)
	}
	if got := doc["edge_count"]; got != float64(1) {
		t.Errorf("edge_count = %v, want 1", got)
	}
	if _, ok := doc["content_hash"]; !ok {
		t.Error("the summary does not name the record it is about: no content_hash")
	}
	if _, ok := doc["coordinate"]; !ok {
		t.Error("the summary does not name its coordinate, which is what callgraph-show is called with")
	}
}

// TestCallGraphSummaryJSON_CarriesWhatThisRunDid is the answer no later read can
// recover. Whether an invocation measured the tree or served a record it already
// held is a fact about the run, not about the record, and it is why these
// commands return a document at all rather than nothing.
func TestCallGraphSummaryJSON_CarriesWhatThisRunDid(t *testing.T) {
	run := callGraphRunJSON{Derivations: []derivationJSON{{
		Answer:                  localDerivationAnswer,
		DerivedByThisRun:        false,
		ReusedRecordExtractedAt: "2026-09-15T09:33:07.030882517Z",
		RemedyFlag:              localForceFlag,
	}}}
	var doc struct {
		Derivations []derivationJSON `json:"derivations"`
	}
	if err := json.Unmarshal(summaryDoc(t, makeCGRecord(t), run), &doc); err != nil {
		t.Fatalf("decoding the summary: %v", err)
	}
	if len(doc.Derivations) != 1 {
		t.Fatalf("derivations = %d, want the run's one", len(doc.Derivations))
	}
	if doc.Derivations[0].DerivedByThisRun {
		t.Error("a served record is reported as derived by this run")
	}
	if doc.Derivations[0].RemedyFlag != localForceFlag {
		t.Errorf("remedy_flag = %q, want %q", doc.Derivations[0].RemedyFlag, localForceFlag)
	}
}

// TestCallGraphSummaryJSON_MeasuredEmptyIsNotAbsent is the trap. A record that
// resolved no function at all is a real recorded state — conventions.md gives it
// exit 2 — so `"nodes": []` would be a WRONG answer here, not a thin one: a
// consumer could not tell it from a surface that does not carry the graph.
//
// Asserted as the pair, because either half alone proves nothing.
func TestCallGraphSummaryJSON_MeasuredEmptyIsNotAbsent(t *testing.T) {
	empty := makeCGRecord(t)
	empty.Nodes, empty.Edges = nil, nil
	empty.NodeCount, empty.EdgeCount = 0, 0
	empty.OverallStatus = cgdomain.CallGraphStatusPartial

	// The record document says the graph was measured and is empty.
	measured, err := json.Marshal(toCallGraphJSON(empty))
	if err != nil {
		t.Fatalf("marshalling the record document: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(measured, &m); err != nil {
		t.Fatalf("decoding the record document: %v", err)
	}
	if got, ok := m["nodes"]; !ok || string(got) != "[]" {
		t.Errorf("the record document renders a measured-empty graph as %s (present=%v), want []", got, ok)
	}
	if got, ok := m["edges"]; !ok || string(got) != "[]" {
		t.Errorf("the record document renders measured-empty edges as %s (present=%v), want []", got, ok)
	}

	// The summary says nothing about the graph, on the same record.
	var s map[string]json.RawMessage
	if err := json.Unmarshal(summaryDoc(t, empty, callGraphRunJSON{}), &s); err != nil {
		t.Fatalf("decoding the summary: %v", err)
	}
	if _, ok := s["nodes"]; ok {
		t.Error("the summary carries a nodes key: a consumer cannot tell it from a measured-empty graph")
	}
	if _, ok := s["edges"]; ok {
		t.Error("the summary carries an edges key: a consumer cannot tell it from measured-empty edges")
	}
	// And a graph that was measured and is not empty is a third document again,
	// so the absence above is not the only thing a consumer ever sees.
	full := summaryDoc(t, makeCGRecord(t), callGraphRunJSON{})
	if bytes.Equal(full, summaryDoc(t, empty, callGraphRunJSON{})) {
		t.Error("a 2-node record and a 0-node record produce the same summary")
	}
}

// TestCallGraphSummaryJSON_PartialCarriesItsFailureFields: the text surface
// prints the detail, the failed packages and the remedy, and the JSON surface
// must not say less than the text. That is the defect class this change belongs
// to, so it is asserted here rather than left to the record document.
func TestCallGraphSummaryJSON_PartialCarriesItsFailureFields(t *testing.T) {
	r := makeCGRecord(t)
	r.OverallStatus = cgdomain.CallGraphStatusPartial
	r.FailureDetail = "bad/bad.go:3:25: undefined: undefinedSymbol"
	r.FailureCause = cgdomain.FailureCauseModule
	r.FailedPackages = []string{"example.com/cg/bad"}

	var doc struct {
		OverallStatus  string   `json:"overall_status"`
		FailureDetail  string   `json:"failure_detail"`
		FailureCause   string   `json:"failure_cause"`
		FailedPackages []string `json:"failed_packages"`
	}
	if err := json.Unmarshal(summaryDoc(t, r, callGraphRunJSON{}), &doc); err != nil {
		t.Fatalf("decoding the summary: %v", err)
	}
	if doc.OverallStatus != cgdomain.CallGraphStatusPartial.String() {
		t.Errorf("overall_status = %q, want Partial", doc.OverallStatus)
	}
	if doc.FailureDetail != r.FailureDetail {
		t.Errorf("failure_detail = %q, want the record's", doc.FailureDetail)
	}
	if doc.FailureCause != string(cgdomain.FailureCauseModule) {
		t.Errorf("failure_cause = %q, want %q", doc.FailureCause, cgdomain.FailureCauseModule)
	}
	if len(doc.FailedPackages) != 1 || doc.FailedPackages[0] != "example.com/cg/bad" {
		t.Errorf("failed_packages = %v, want the record's one", doc.FailedPackages)
	}
}

// TestCallGraphSummaryText_IsUnchanged is the control. Nothing about the human
// path changes: these are the lines an operator already reads.
func TestCallGraphSummaryText_IsUnchanged(t *testing.T) {
	partial := makeCGRecord(t)
	partial.OverallStatus = cgdomain.CallGraphStatusPartial
	partial.FailureDetail = "bad/bad.go:3:25: undefined: undefinedSymbol"
	partial.FailureCause = cgdomain.FailureCauseModule
	partial.FailedPackages = []string{"example.com/cg/bad"}

	for _, tc := range []struct {
		name      string
		record    cgdomain.CallGraphRecord
		fromCache bool
		want      string
	}{
		{
			name:   "clean",
			record: makeCGRecord(t),
			want:   "example.com/cg@v1.0.0: Extracted — 2 nodes, 1 edges [CHA]\n",
		},
		{
			name:      "cached",
			record:    makeCGRecord(t),
			fromCache: true,
			want:      "example.com/cg@v1.0.0: Extracted — 2 nodes, 1 edges [CHA] (cached)\n",
		},
		{
			name:   "partial",
			record: partial,
			want: "example.com/cg@v1.0.0: Partial — 2 nodes, 1 edges [CHA]\n" +
				"  failure: bad/bad.go:3:25: undefined: undefinedSymbol\n" +
				"  failed packages (1): example.com/cg/bad\n" +
				cgdomain.IncompleteGraphRemedy(partial.Coordinate, partial.FailureCause, partial.FailureDetail, "") + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := printCallGraphSummary(tc.record, tc.fromCache, false, "", &buf, callGraphRunJSON{}); err != nil {
				t.Fatalf("rendering: %v", err)
			}
			if buf.String() != tc.want {
				t.Errorf("text surface changed.\n got: %q\nwant: %q", buf.String(), tc.want)
			}
		})
	}
}

// TestLocalJSON_FlagAndPreferenceProduceOneDocument runs the command end to end
// on both routes into --json.
//
// A preference that produced different output from the flag it stands in for
// would be the same defect one layer down, and `preferences.json` is the route
// this whole change exists for: it is where the dump arrived with nothing typed.
// Byte-compared, because a field comparison would pass on two documents that
// differ in order or in whitespace.
//
// Both routes run against a store that already holds the record, so the two
// invocations serve one generation and differ only in how --json came to be in
// force: a fresh measurement in each would differ at extracted_at for reasons
// that have nothing to do with the routes.
func TestLocalJSON_FlagAndPreferenceProduceOneDocument(t *testing.T) {
	root := t.TempDir()
	tree := writeTinyModule(t)

	// Warm the store, so both measured runs below are reuses of one record.
	writeConfig(t, root, "version: \"1\"\n")
	if _, _, code := runCLI(t, "local", tree, "--store-root", root); code != 0 {
		t.Fatalf("seeding the store with a record: exit %d", code)
	}

	flagOut, _, code := runCLI(t, "local", tree, "--json", "--store-root", root)
	if code != 0 {
		t.Fatalf("the flag route exited %d", code)
	}

	writeConfig(t, root, "version: \"1\"\npreferences:\n  json: true\n")
	prefOut, _, code := runCLI(t, "local", tree, "--store-root", root)
	if code != 0 {
		t.Fatalf("the preference route exited %d", code)
	}

	if flagOut != prefOut {
		t.Errorf("the two routes into --json produce different documents.\nflag:\n%s\npreference:\n%s", flagOut, prefOut)
	}

	doc := decodeDocument(t, "local --json", flagOut)
	for _, k := range []string{"nodes", "edges"} {
		if _, ok := doc[k]; ok {
			t.Errorf("local --json still carries %q", k)
		}
	}
	for _, k := range []string{"coordinate", "overall_status", "node_count", "edge_count", "content_hash", "derivations"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("local --json no longer carries %q", k)
		}
	}
	if len(flagOut) > 8192 {
		t.Errorf("local --json returned %d bytes: that is a dump, not a summary", len(flagOut))
	}

	// The escape still works, with the preference in force.
	textOut, _, code := runCLI(t, "local", tree, "--json=false", "--store-root", root)
	if code != 0 {
		t.Fatalf("--json=false exited %d", code)
	}
	if !strings.HasPrefix(textOut, "example.com/tiny@local: Extracted") {
		t.Errorf("--json=false did not select text: %q", textOut)
	}
}

// writeTinyModule writes the smallest module whose analysis resolves more than
// zero functions: one package, one internal call, one stdlib call. It requires
// nothing, so the load resolves inside the directory and never asks a proxy.
func writeTinyModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module example.com/tiny\n\ngo 1.24\n",
		"main.go": "package main\n\nimport \"fmt\"\n\n" +
			"func helper(n int) int { return n * 2 }\n\n" +
			"func Greet(name string) string { return fmt.Sprintf(\"hi %s (%d)\", name, helper(3)) }\n\n" +
			"func main() { fmt.Println(Greet(\"world\")) }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}
