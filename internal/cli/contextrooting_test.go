package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

// contextRootingOf runs `context --json` and returns the rooting its envelope
// carries, failing when there is none.
func contextRootingOf(t *testing.T, what string, args ...string) map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := Run(append(args, "--json"), &stdout, &stderr); err != nil {
		t.Fatalf("%s: %v\nstderr:\n%s", what, err, stderr.String())
	}
	fields, rows := decodeEnvelope(t, what, stdout.Bytes())
	if len(rows) == 0 {
		t.Fatalf("%s: no modules in the answer, so the rooting describes nothing\nstderr:\n%s", what, stderr.String())
	}
	rooting, ok := fields["rooting"].(map[string]any)
	if !ok {
		t.Fatalf("%s: the envelope carries no rooting object (got %v)\nstderr:\n%s", what, fields["rooting"], stderr.String())
	}
	return rooting
}

// TestContextStatesWhetherTheWalkWasNamedOrChosen is what this envelope exists
// for.
//
// A verdict is a property of one build. When the caller names no walk,
// kanonarion picks one out of however many the store holds — and the document
// used to carry the winner's id and nothing else, so an agent reading verdicts
// could not tell a build it asked for from one the tool selected on its behalf.
// The id alone does not say it: it looks the same either way.
//
// Both directions are exercised against one store, because only the pair proves
// anything. A document that always said "chosen" would pass a test for the
// chosen leg while telling every caller the same thing.
func TestContextStatesWhetherTheWalkWasNamedOrChosen(t *testing.T) {
	fx := newJSONStdoutFixture(t)
	chdirWithGoMod(t, "")

	t.Run("no walk named: the basis is chosen, out of a stated candidate count", func(t *testing.T) {
		rooting := contextRootingOf(t, "context --gomod",
			"context", "--gomod", fx.populatedGoMod(), "--store-root", fx.storeRoot)

		if rooting["basis"] != "chosen" {
			t.Errorf("basis = %v, want \"chosen\": the caller named no walk and one was picked for them", rooting["basis"])
		}
		selection, ok := rooting["walk_selection"].(map[string]any)
		if !ok {
			t.Fatalf("walk_selection is not an object: %v", rooting["walk_selection"])
		}
		if selection["rule"] == "pinned" {
			t.Error("walk_selection.rule = \"pinned\" on a read that named no walk")
		}
		// The count is the other half. "One was chosen" without it does not say
		// what it was chosen from, and the fixture holds two project walks
		// precisely so the number is not 1.
		candidates, ok := selection["candidates"].(float64)
		if !ok {
			t.Fatalf("walk_selection.candidates is not a number: %v — a chosen walk with no candidate count "+
				"does not say what it was chosen from", selection["candidates"])
		}
		if candidates < 2 {
			t.Errorf("walk_selection.candidates = %v, want at least 2: with one candidate nothing was chosen", candidates)
		}
		// The rest of what the person is told, as fields.
		if rooting["walk_id"] == "" || rooting["walk_id"] == nil {
			t.Error("walk_id is absent")
		}
		if rooting["gomod"] != fx.populatedGoMod() {
			t.Errorf("gomod = %v, want the manifest that named the build (%s)", rooting["gomod"], fx.populatedGoMod())
		}
		if rooting["manifest_reresolved"] != false {
			t.Errorf("manifest_reresolved = %v, want false: this read compares require directives, it does not resolve",
				rooting["manifest_reresolved"])
		}
		if rooting["pin_with"] != "--walk-id" {
			t.Errorf("pin_with = %v, want the flag that takes the choice back", rooting["pin_with"])
		}
		if rooting["toolchain"] == "" || rooting["toolchain"] == nil {
			t.Error("toolchain is absent: the answer names no standard library")
		}
	})

	t.Run("--walk-id: the basis is named, and nothing was enumerated", func(t *testing.T) {
		rooting := contextRootingOf(t, "context --walk-id",
			"context", "--walk-id", jsonDocWalkID, "--store-root", fx.storeRoot)

		if rooting["basis"] != "named" {
			t.Errorf("basis = %v, want \"named\": the caller pinned this build with --walk-id", rooting["basis"])
		}
		if rooting["walk_id"] != jsonDocWalkID {
			t.Errorf("walk_id = %v, want the walk the caller named (%s)", rooting["walk_id"], jsonDocWalkID)
		}
		selection, ok := rooting["walk_selection"].(map[string]any)
		if !ok {
			t.Fatalf("walk_selection is not an object: %v", rooting["walk_selection"])
		}
		if selection["rule"] != "pinned" {
			t.Errorf("walk_selection.rule = %v, want \"pinned\"", selection["rule"])
		}
		// Null, not 0: nothing was enumerated, and a count of zero is never true
		// of a document that names a walk — the store holds at least that one.
		if got, present := selection["candidates"]; !present || got != nil {
			t.Errorf("walk_selection.candidates = %v (present %v), want null: nothing was chosen from anything",
				got, present)
		}
		// No manifest was consulted, so none is named.
		if got, present := rooting["gomod"]; present {
			t.Errorf("gomod = %v on a pinned read: no manifest named this build", got)
		}
	})
}

// TestContextRootingIsAbsentWhereNothingRootedTheRun pins the forms that anchor
// nothing for the run: a coordinate names one module, and every section of its
// document states its own basis. Null rather than an omitted key, so a consumer
// reads the same field at every form.
func TestContextRootingIsAbsentWhereNothingRootedTheRun(t *testing.T) {
	fx := newJSONStdoutFixture(t)
	chdirWithGoMod(t, "")

	var stdout, stderr bytes.Buffer
	if err := Run([]string{"context", jsonDocDepCoord, "--json", "--store-root", fx.storeRoot},
		&stdout, &stderr); err != nil {
		t.Fatalf("context <coordinate> --json: %v\nstderr:\n%s", err, stderr.String())
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("the answer is not one JSON object: %v\noutput: %s", err, stdout.String())
	}
	raw, present := doc["rooting"]
	if !present {
		t.Fatal("rooting is absent from the document; a consumer must read the same key at every form")
	}
	if string(raw) != "null" {
		t.Errorf("rooting = %s, want null: a coordinate anchors nothing for the run", raw)
	}
}
