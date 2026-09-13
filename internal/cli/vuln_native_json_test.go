package cli

import (
	"encoding/json"
	"testing"

	nativedomain "github.com/eitanity/kanonarion/internal/native/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// A record's verdict must not move because a surface started stating something
// beside it. These lock the two halves of that: the statement reaches the wire,
// and every other key comes out exactly as it did.

func nativeJSONRecord(t *testing.T) vuldomain.VulnerabilityRecord {
	t.Helper()
	return vuldomain.VulnerabilityRecord{
		Ecosystem:      "go",
		Coordinate:     natCoord(t, "example.com/go-sqlite3", "v1.14.12"),
		WalkID:         "walk-1",
		OverallStatus:  vuldomain.StatusClean,
		CoverageStatus: vuldomain.CoverageAnalysed,
		FindingsStatus: vuldomain.FindingsRecordClean,
	}
}

// TestVulnRecordNativeJSON_AddsTheStatementAndMovesNothingElse.
func TestVulnRecordNativeJSON_AddsTheStatementAndMovesNothingElse(t *testing.T) {
	rec := nativeJSONRecord(t)
	cov := nativeCoverageOf(natRecord(nativedomain.PresenceIdentified, sqliteComponent("3.38.0"), 4), true)

	plain, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatal(err)
	}
	withNative, err := json.Marshal(toVulnRecordNativeJSON(rec, nil, &cov))
	if err != nil {
		t.Fatal(err)
	}

	var before, after map[string]any
	if err := json.Unmarshal(plain, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(withNative, &after); err != nil {
		t.Fatal(err)
	}

	got, present := after["native_coverage"]
	if !present {
		t.Fatalf("the projection carries no native_coverage key:\n%s", withNative)
	}
	block := got.(map[string]any)
	if block["state"] != string(nativeStateIdentified) {
		t.Errorf("state = %v, want %q", block["state"], nativeStateIdentified)
	}
	if block["unsearched_components"] != float64(1) {
		t.Errorf("unsearched_components = %v, want 1", block["unsearched_components"])
	}

	delete(after, "native_coverage")
	a, _ := json.Marshal(after)
	b, _ := json.Marshal(before)
	if string(a) != string(b) {
		t.Errorf("a key other than native_coverage moved:\n before %s\n after  %s", b, a)
	}
	// The verdict itself, stated explicitly: a coverage gap must never become one.
	if after["overall_status"] != string(vuldomain.StatusClean) || after["findings_status"] != string(vuldomain.FindingsRecordClean) {
		t.Errorf("the verdict moved: overall=%v findings=%v", after["overall_status"], after["findings_status"])
	}
}

// TestVulnRecordNativeJSON_NoStatementLeavesTheKeyOff. An absent key says "this
// producer does not derive it"; present and empty would assert an absence
// nothing measured. The two are different and a consumer must be able to tell.
func TestVulnRecordNativeJSON_NoStatementLeavesTheKeyOff(t *testing.T) {
	rec := nativeJSONRecord(t)
	b, err := json.Marshal(toVulnRecordNativeJSON(rec, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if _, present := doc["native_coverage"]; present {
		t.Errorf("a producer deriving no statement still emitted the key:\n%s", b)
	}
}

// TestVulnRecordNativeJSON_EveryStateReachesTheWire, including the ones with
// nothing in them: a consumer reads one key rather than inferring a fact from a
// key's absence.
func TestVulnRecordNativeJSON_EveryStateReachesTheWire(t *testing.T) {
	rec := nativeJSONRecord(t)
	for _, tc := range []struct {
		found bool
		p     nativedomain.Presence
		want  nativeCoverageState
	}{
		{false, "", nativeStateNotExamined},
		{true, nativedomain.PresenceAbsent, nativeStateAbsent},
		{true, nativedomain.PresenceLinkedNotShipped, nativeStateLinkedNotShipped},
		{true, nativedomain.PresenceUnidentified, nativeStateUnidentified},
		{true, nativedomain.PresenceIdentified, nativeStateIdentified},
	} {
		cov := nativeCoverageOf(natRecord(tc.p, sqliteComponent("3.38.0"), 4), tc.found)
		b, err := json.Marshal(toVulnRecordNativeJSON(rec, nil, &cov))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Native struct {
				State string `json:"state"`
			} `json:"native_coverage"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Native.State != string(tc.want) {
			t.Errorf("state = %q, want %q", doc.Native.State, tc.want)
		}
	}
}
