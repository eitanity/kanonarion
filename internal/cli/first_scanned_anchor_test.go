package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// first_scanned_at is anchored per (module, version, pipeline version,
// snapshot), so a new advisory snapshot starts a new anchor and the stamp moves
// forward with no pipeline change at all. The value is right; its name reads as
// "first ever", and nothing on either surface said otherwise or sent a reader
// asking the historical question to the ledger that answers it. These tests pin
// the correction on both renderings, and pin the JSON key itself as unchanged:
// renaming it would break consumers to fix a wording problem.

func anchoredTestRecord(t *testing.T) vuldomain.VulnerabilityRecord {
	t.Helper()
	rec := unreadableTestRecord(t, "example.com/anchored", "v1.0.0")
	rec.FirstScannedAt = time.Date(2024, 12, 1, 9, 0, 0, 0, time.UTC)
	return rec
}

func TestVulnShowText_StatesWhatFirstValidatedIsAnchoredTo(t *testing.T) {
	rec := anchoredTestRecord(t)

	var out bytes.Buffer
	printVulnRecord(&out, rec, nil, nil)
	got := out.String()

	if !strings.Contains(got, "First validated:") {
		t.Fatalf("the record does not print the stamp at all:\n%s", got)
	}
	if !strings.Contains(got, "not first awareness") {
		t.Errorf("the stamp is printed without its grain; a reader takes it for first awareness:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion store ledger --event-type vuln_finding_observed --module example.com/anchored@v1.0.0") {
		t.Errorf("the reader that answers the historical question is not named:\n%s", got)
	}
}

// The pointer costs nothing on a record that carries no anchor, which is what
// keeps it off invocations where there is no stamp to misread.
func TestVulnShowText_SaysNothingWhereThereIsNoAnchor(t *testing.T) {
	rec := unreadableTestRecord(t, "example.com/unanchored", "v1.0.0")

	var out bytes.Buffer
	printVulnRecord(&out, rec, nil, nil)
	if strings.Contains(out.String(), "first observation:") {
		t.Errorf("a record with no first-validated stamp printed the pointer anyway:\n%s", out.String())
	}
}

func TestVulnRecordJSON_KeepsFirstScannedAtAndStatesItsAnchor(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.SetByID([]vuldomain.VulnerabilityRecord{anchoredTestRecord(t)})

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", true, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID(--json) = %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want one", len(rows))
	}

	// The key does not change. It is a stability contract and the value under it
	// is correct for the question the field answers.
	if _, present := rows[0]["first_scanned_at"]; !present {
		t.Error("first_scanned_at is gone from the wire; consumers read that key")
	}
	anchor, _ := rows[0]["first_scanned_at_anchor"].(string)
	if !strings.Contains(anchor, "not first awareness") {
		t.Errorf("first_scanned_at_anchor = %q, want it to state the grain", anchor)
	}
	if !strings.Contains(anchor, "kanonarion store ledger --event-type vuln_finding_observed --module example.com/anchored@v1.0.0") {
		t.Errorf("first_scanned_at_anchor = %q, want it to name the ledger reader", anchor)
	}
}

// A record with no anchor carries no anchor note either, so a consumer that
// never sees the stamp sees no change at all.
func TestVulnRecordJSON_AnchorNoteRidesWithTheStamp(t *testing.T) {
	uc := testfakes.NewFakeQueryVuln()
	uc.SetByID([]vuldomain.VulnerabilityRecord{unreadableTestRecord(t, "example.com/unanchored", "v1.0.0")})

	var out bytes.Buffer
	if err := runVulnByID(context.Background(), "GO-2025-0001", "", true, uc, nil, &out); err != nil {
		t.Fatalf("runVulnByID(--json) = %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	if _, present := rows[0]["first_scanned_at_anchor"]; present {
		t.Error("a record with no first_scanned_at carries an anchor note for a stamp it does not have")
	}
}
