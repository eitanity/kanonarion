package domain_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func droppedFixture() []domain.DroppedReplace {
	return []domain.DroppedReplace{
		{Path: "example.com/mod", Target: "../"},
		{Path: "example.com/mod/creds", Target: "../creds/"},
	}
}

// TestDroppedReplacesIsAbsentWhenEmpty is the migration guard. The field must not
// appear in the canonical encoding of a record that dropped nothing, or every
// record already in the store would stop verifying against its stored hash — which
// is what lets this land with no pipeline bump and no migration.
func TestDroppedReplacesIsAbsentWhenEmpty(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(makeTestRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshalling canonical bytes: %v", err)
	}
	if _, present := keys["dropped_replaces"]; present {
		t.Error("dropped_replaces is present in the canonical encoding of a record that dropped none: " +
			"every record written before the field existed would stop verifying")
	}
}

// TestDroppedReplacesIsHashCovered. Which directives were dropped decides which
// dependency versions the build resolved, so it is part of what the graph is. A
// field outside the seal could be edited without breaking the record's own
// integrity check, and a reader would be told the published tree was analysed.
func TestDroppedReplacesIsHashCovered(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	r := makeTestRecord()
	r.DroppedReplaces = droppedFixture()
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Fatalf("VerifyContentHash on an untampered record: %v", err)
	}

	tampered := sealed
	tampered.DroppedReplaces = nil
	if err := h.VerifyContentHash(tampered); err == nil {
		t.Error("erasing the dropped directives left the content hash valid: the field is outside the hash")
	}
}

// TestDroppedReplacesRoundTrips keeps the statement on the serialised record, so
// a reader sees what the analysis did rather than a zero value the decoder lost.
func TestDroppedReplacesRoundTrips(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	r := makeTestRecord()
	r.DroppedReplaces = droppedFixture()
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(back.DroppedReplaces) != 2 {
		t.Fatalf("DroppedReplaces = %v after round trip", back.DroppedReplaces)
	}
	if got, want := back.DroppedReplaces[0].String(), "example.com/mod => ../"; got != want {
		t.Errorf("DroppedReplaces[0] = %q, want %q", got, want)
	}
}

// TestDroppedReplacesHashIsOrderIndependent. The list is sorted on the way onto
// the wire, so two analyses that dropped the same directives in the order the
// file happened to list them seal to the same bytes.
func TestDroppedReplacesHashIsOrderIndependent(t *testing.T) {
	t.Parallel()

	var h domain.CallGraphRecordHasher
	a := makeTestRecord()
	a.DroppedReplaces = droppedFixture()
	b := makeTestRecord()
	b.DroppedReplaces = []domain.DroppedReplace{droppedFixture()[1], droppedFixture()[0]}

	sealedA, err := h.SetContentHash(a)
	if err != nil {
		t.Fatalf("SetContentHash(a): %v", err)
	}
	sealedB, err := h.SetContentHash(b)
	if err != nil {
		t.Fatalf("SetContentHash(b): %v", err)
	}
	if sealedA.ContentHash != sealedB.ContentHash {
		t.Errorf("two records dropping the same directives sealed differently: %s vs %s",
			sealedA.ContentHash, sealedB.ContentHash)
	}
}

// TestDroppedReplacesSummaryNamesEveryDirective. A count alone leaves a reader
// unable to tell whether the analysed build list is the one the module declares.
func TestDroppedReplacesSummaryNamesEveryDirective(t *testing.T) {
	t.Parallel()

	if got := domain.DroppedReplacesSummary(nil); got != "" {
		t.Errorf("DroppedReplacesSummary(nil) = %q, want the empty string so a caller can append it unconditionally", got)
	}
	summary := domain.DroppedReplacesSummary(droppedFixture())
	for _, want := range []string{"2 replace directives", "example.com/mod => ../", "example.com/mod/creds => ../creds/"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary does not contain %q: %s", want, summary)
		}
	}
	one := domain.DroppedReplacesSummary(droppedFixture()[:1])
	if !strings.Contains(one, "1 replace directive dropped") {
		t.Errorf("singular form is wrong: %s", one)
	}
}

// TestDroppedReplaceStringRendersTheVersionedForm. A replace can pin the version
// it replaces, and the record has to say which one it removed.
func TestDroppedReplaceStringRendersTheVersionedForm(t *testing.T) {
	t.Parallel()

	d := domain.DroppedReplace{Path: "example.com/mod", Version: "v1.2.3", Target: "../mod/"}
	if got, want := d.String(), "example.com/mod v1.2.3 => ../mod/"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
