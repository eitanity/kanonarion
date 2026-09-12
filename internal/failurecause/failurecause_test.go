package failurecause_test

import (
	"encoding/json"
	"testing"

	"github.com/eitanity/kanonarion/internal/failurecause"
)

// TestIsEnvironmentLimit pins the one question every reader of this axis asks:
// is this repaired by changing something on this box and running again?
func TestIsEnvironmentLimit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cause failurecause.Cause
		want  bool
	}{
		{failurecause.Environment, true},
		{failurecause.Module, false},
		{failurecause.Unrecorded, false},
		// A cause from a newer generation is not a stated environment limit, and
		// treating it as one would let an unknown word decide a re-run.
		{failurecause.Cause("cosmic-rays"), false},
	} {
		if got := tc.cause.IsEnvironmentLimit(); got != tc.want {
			t.Errorf("Cause(%q).IsEnvironmentLimit() = %v, want %v", string(tc.cause), got, tc.want)
		}
	}
}

// TestStringNamesTheZeroValue keeps "no cause stated" from rendering as a blank
// a reader would take for an absence of failure.
func TestStringNamesTheZeroValue(t *testing.T) {
	t.Parallel()
	if got := failurecause.Unrecorded.String(); got != "not recorded" {
		t.Errorf("Unrecorded.String() = %q, want %q", got, "not recorded")
	}
	if got := failurecause.Environment.String(); got != "environment" {
		t.Errorf("Environment.String() = %q, want %q", got, "environment")
	}
	if got := failurecause.Module.String(); got != "module" {
		t.Errorf("Module.String() = %q, want %q", got, "module")
	}
}

// TestWireValuesAreStable is the compatibility guard. These three strings are in
// a store column and inside sealed records; changing one silently reclassifies
// every row already written.
func TestWireValuesAreStable(t *testing.T) {
	t.Parallel()
	for cause, want := range map[failurecause.Cause]string{
		failurecause.Unrecorded:  "",
		failurecause.Module:      "module",
		failurecause.Environment: "environment",
	} {
		if string(cause) != want {
			t.Errorf("wire value %q, want %q", string(cause), want)
		}
	}
}

// TestOmitsItselfWhenUnrecorded is why the axis could join sealed records
// without a pipeline bump: the zero value marshals to nothing, so a record
// written before it existed hashes to the bytes it always did.
func TestOmitsItselfWhenUnrecorded(t *testing.T) {
	t.Parallel()
	type doc struct {
		Cause failurecause.Cause `json:"cause,omitempty"`
	}
	raw, err := json.Marshal(doc{})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Errorf("an unstated cause marshalled to %s, want {}", raw)
	}
	raw, err = json.Marshal(doc{Cause: failurecause.Environment})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"cause":"environment"}` {
		t.Errorf("marshalled to %s", raw)
	}
}
