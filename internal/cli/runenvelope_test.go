package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// restoreJSONFlagAfterRun puts the process-wide --json flag back after an
// in-process Run.
//
// Run binds --json afresh on every invocation, so a command run under it leaves
// jsonOut true when it returns, and the next test in this package that calls a
// render helper directly renders JSON where it expected text. The tests that
// already do this happen to sort late enough not to have hit it; that is
// ordering, not safety.
func restoreJSONFlagAfterRun(t *testing.T) {
	t.Helper()
	prev := jsonOut
	t.Cleanup(func() { jsonOut = prev })
}

// decodeEnvelope decodes one enveloped answer: the object's own fields, and the
// per-module documents in its modules array, undecoded.
//
// It fails rather than returning an error, and it fails on the two shapes the
// envelope exists to end — a bare array, and a document whose type follows the
// count — so a test that decodes an answer through it cannot silently accept
// either.
func decodeEnvelope(t *testing.T, what string, out []byte) (map[string]any, []json.RawMessage) {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%s: the answer is not one JSON object: %v\noutput: %s", what, err, out)
	}
	raw, ok := doc["modules"]
	if !ok {
		t.Fatalf("%s: the answer carries no modules array\noutput: %s", what, out)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("%s: modules is not an array: %v\noutput: %s", what, err, out)
	}
	if rows == nil {
		t.Errorf("%s: modules is null rather than [], so the empty answer decodes as a different type from a populated one", what)
	}
	fields := map[string]any{}
	for k, v := range doc {
		if k == "modules" {
			continue
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			t.Fatalf("%s: envelope field %q does not decode: %v", what, k, err)
		}
		fields[k] = val
	}
	return fields, rows
}

// envelopeRows decodes the modules array into a typed slice.
func envelopeRows(t *testing.T, what string, out []byte, into any) map[string]any {
	t.Helper()
	fields, rows := decodeEnvelope(t, what, out)
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("%s: re-encoding the modules array: %v", what, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: the modules array does not decode into %T: %v", what, into, err)
	}
	return fields
}

// TestJSONEnvelopeWriterFramesTheRowsUnchanged pins the two properties the
// streaming writer exists to hold at once.
//
// The document is one object, whatever the number of elements — including none,
// which is the count that used to decide a shape. And each element is the bytes
// json.Marshal produces for that document alone, which is what makes the move
// from a bare array to an envelope a change of framing and not of rows.
func TestJSONEnvelopeWriterFramesTheRowsUnchanged(t *testing.T) {
	type row struct {
		Module string `json:"module"`
		Count  int    `json:"count"`
	}
	head := struct {
		Scope string `json:"scope"`
	}{Scope: "code"}

	for _, tc := range []struct {
		name string
		rows []row
	}{
		{name: "no elements", rows: nil},
		{name: "one element", rows: []row{{Module: "example.com/a", Count: 1}}},
		{name: "several elements", rows: []row{
			{Module: "example.com/a", Count: 1}, {Module: "example.com/b", Count: 2}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := jsonEnvelopeWriter{out: &buf, head: head}
			for _, r := range tc.rows {
				if err := w.write(r); err != nil {
					t.Fatalf("writing %v: %v", r, err)
				}
			}
			if err := w.close(); err != nil {
				t.Fatalf("closing: %v", err)
			}

			fields, got := decodeEnvelope(t, "the envelope", buf.Bytes())
			if fields["scope"] != "code" {
				t.Errorf("scope = %v, want the head's own field", fields["scope"])
			}
			if len(got) != len(tc.rows) {
				t.Fatalf("modules holds %d element(s), want %d", len(got), len(tc.rows))
			}
			for i, r := range tc.rows {
				want, err := json.Marshal(r)
				if err != nil {
					t.Fatalf("marshalling the row alone: %v", err)
				}
				if string(got[i]) != string(want) {
					t.Errorf("element %d is not the bytes the row marshals to on its own:\n got: %s\nwant: %s",
						i, got[i], want)
				}
			}
		})
	}
}

// TestEnvelopeCarriesTheScopeItResolved pins the fields the scope notice's
// machine-readable half is made of, on the surface that builds them.
//
// The three are checked together because they are one disclosure: a scope name
// with no count does not say how much it selected, and a count with no test axis
// does not say what moved it.
func TestEnvelopeCarriesTheScopeItResolved(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resolution scopeResolution
		modules    int
		offerFlag  bool
		wantScope  string
		wantTests  string
		wantNarrow string
	}{
		{
			name:       "code scope with the test axis included offers the narrowing",
			resolution: newScopeResolution(scopeCode, false),
			modules:    20,
			offerFlag:  true,
			wantScope:  "code", wantTests: "included", wantNarrow: "--exclude-tests",
		},
		{
			name:       "a narrowed scope offers nothing further",
			resolution: newScopeResolution(scopeCode, true),
			modules:    18,
			offerFlag:  true,
			wantScope:  "code", wantTests: "excluded", wantNarrow: "",
		},
		{
			name:       "a command that refuses the flag offers it on neither channel",
			resolution: newScopeResolution(scopeCode, false),
			modules:    20,
			offerFlag:  false,
			wantScope:  "code", wantTests: "included", wantNarrow: "",
		},
		{
			name:       "the complete scope has no axis to narrow",
			resolution: newScopeResolution(scopeComplete, false),
			modules:    246,
			offerFlag:  true,
			wantScope:  "complete", wantTests: "unavailable", wantNarrow: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := newEnvelopeScope(tc.resolution, tc.modules, tc.offerFlag)
			if got.DependencyScope == nil {
				t.Fatal("dependency_scope is null on a resolved scope")
			}
			if got.DependencyScope.Scope != tc.wantScope {
				t.Errorf("scope = %q, want %q", got.DependencyScope.Scope, tc.wantScope)
			}
			if got.DependencyScope.TestScope != tc.wantTests {
				t.Errorf("test_scope = %q, want %q", got.DependencyScope.TestScope, tc.wantTests)
			}
			if got.ModuleCount != tc.modules {
				t.Errorf("module_count = %d, want %d", got.ModuleCount, tc.modules)
			}
			if got.NarrowWith != tc.wantNarrow {
				t.Errorf("narrow_with = %q, want %q", got.NarrowWith, tc.wantNarrow)
			}
			// The notice and the fields are built from one resolution and must
			// not disagree about whether a narrowing is on offer.
			var line bytes.Buffer
			if err := writeDepScopeNotice(&line, tc.resolution, tc.modules, tc.offerFlag); err != nil {
				t.Fatalf("writing the notice: %v", err)
			}
			if offered := strings.Contains(line.String(), "--exclude-tests)"); offered != (got.NarrowWith != "") {
				t.Errorf("the notice offers the narrowing (%v) and the field does not agree (%q)\nnotice: %s",
					offered, got.NarrowWith, line.String())
			}
		})
	}
}

// TestUnscopedEnvelopeStatesTheAbsentScope pins what a form that projected no
// go.mod scope says: null, rather than a key that is simply missing. A reader
// cannot tell an unstated scope from an absent one, and only one of them is a
// measurement.
func TestUnscopedEnvelopeStatesTheAbsentScope(t *testing.T) {
	raw, err := json.Marshal(unscopedEnvelope(3))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	scope, present := decoded["dependency_scope"]
	if !present {
		t.Error("dependency_scope is absent; an unstated scope and a missing key must not read alike")
	}
	if scope != nil {
		t.Errorf("dependency_scope = %v, want null: no scope was resolved", scope)
	}
	if decoded["module_count"] != float64(3) {
		t.Errorf("module_count = %v, want 3", decoded["module_count"])
	}
	if _, present := decoded["narrow_with"]; present {
		t.Error("narrow_with is offered on a form with no scope to narrow")
	}
}
