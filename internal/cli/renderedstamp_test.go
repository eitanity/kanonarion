package cli

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/recordstamp"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// trimmedFraction matches a stamp whose fraction is neither absent nor nine
// digits — the widths encoding/json's RFC3339Nano produces by stripping trailing
// zeros, and the widths no ledger writes.
var trimmedFraction = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,8}Z"`)

// stampedRecord is a record whose scan time ends in a zero nanosecond, which is
// the instant that makes the defect visible: RFC3339Nano strips the trailing
// zero and emits eight digits.
func stampedRecord(t *testing.T) vuldomain.VulnerabilityRecord {
	t.Helper()
	scanned := time.Date(2026, 9, 6, 22, 30, 52, 53770680, time.UTC)
	return vuldomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coordinatetest.MustNew("github.com/golang-jwt/jwt/v4", "v4.5.1"),
		OverallStatus:    vuldomain.StatusClean,
		DatabaseSnapshot: vulntest.MustNewAt("govulndb", "v2026-09-06", scanned.Truncate(time.Second)),
		ScannedAt:        scanned,
		FirstScannedAt:   scanned,
		PipelineVersion:  vulnPipelineVersion,
	}
}

// A stored record's stamp reaches --json in the ledger's own encoding, not in
// encoding/json's RFC3339Nano.
//
// The record's own wire shape carries the trimmed spelling and keeps it — that
// spelling is what its seal covers, and re-spelling it would darken every stored
// record whose nanoseconds end in a zero. The RENDERED answer is where the width
// is fixed, so the reader gets one spelling without the ledger moving.
func TestVulnRecordJSON_StampsAreFixedWidth(t *testing.T) {
	rec := stampedRecord(t)

	// The defect, stated: the domain type's own JSON trims.
	sealed, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshalling the record: %v", err)
	}
	if want := `"scanned_at":"2026-09-06T22:30:52.05377068Z"`; !strings.Contains(string(sealed), want) {
		t.Fatalf("the record's own wire shape no longer carries %s — the seal has moved, which this "+
			"rendering fix exists to avoid", want)
	}

	out, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling the rendered record: %v", err)
	}
	for _, want := range []string{
		`"scanned_at":"2026-09-06T22:30:52.053770680Z"`,
		`"first_scanned_at":"2026-09-06T22:30:52.053770680Z"`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered JSON does not carry %s\ngot: %s", want, out)
		}
	}
	if m := trimmedFraction.Find(out); m != nil {
		t.Errorf("rendered JSON carries a trimmed stamp %s; a reader cannot match that width against "+
			"a record or a log line", m)
	}
}

// The run document is the same shape and the same rule.
func TestVulnScanDocument_StampsAreFixedWidth(t *testing.T) {
	at := time.Date(2026, 9, 6, 22, 30, 52, 53770680, time.UTC)
	doc := vulnScanDocument{
		WalkScanRun: vuldomain.WalkScanRun{
			ID: "run-1", WalkID: "walk-1", StartedAt: at, CompletedAt: at.Add(time.Minute),
		},
		StartedAt:   ledgerStamp(at),
		CompletedAt: ledgerStamp(at.Add(time.Minute)),
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling the run document: %v", err)
	}
	if want := `"started_at":"2026-09-06T22:30:52.053770680Z"`; !strings.Contains(string(out), want) {
		t.Errorf("run document does not carry %s\ngot: %s", want, out)
	}
	if m := trimmedFraction.Find(out); m != nil {
		t.Errorf("run document carries a trimmed stamp %s", m)
	}
}

// Text and --json spell one instant one way. Two surfaces disagreeing about the
// same record is what a reader hits when they check an answer they were shown
// against the answer a script parsed.
func TestVulnRecord_TextAndJSONAgreeOnTheStamp(t *testing.T) {
	rec := stampedRecord(t)

	var text bytes.Buffer
	printVulnRecord(&text, rec, nil)

	out, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var fields map[string]any
	if uerr := json.Unmarshal(out, &fields); uerr != nil {
		t.Fatalf("decoding: %v", uerr)
	}
	stamp, ok := fields["scanned_at"].(string)
	if !ok {
		t.Fatalf("rendered JSON carries no scanned_at: %s", out)
	}
	if !strings.Contains(text.String(), stamp) {
		t.Errorf("the text surface does not carry the stamp --json emits (%s)\ntext:\n%s", stamp, text.String())
	}
	// And it is the encoding the ledgers and the logger write.
	if want := recordstamp.Format(rec.ScannedAt); stamp != want {
		t.Errorf("rendered stamp %q is not the ledger's encoding %q", stamp, want)
	}
}

// The rendered documents decode back into the types they shadow. A consumer
// reading `vuln-show --json` or `vuln-scan --json` parses the record and the run
// out of them, so a shadow that changed a field's presence — an always-present
// stamp rendered as "" — would break the parse rather than the spelling.
func TestRenderedDocumentsDecodeBackIntoTheirRecordTypes(t *testing.T) {
	out, err := json.Marshal(toVulnRecordJSON(stampedRecord(t), nil))
	if err != nil {
		t.Fatalf("marshalling the record: %v", err)
	}
	var rec vuldomain.VulnerabilityRecord
	if uerr := json.Unmarshal(out, &rec); uerr != nil {
		t.Fatalf("the rendered record does not decode back into a VulnerabilityRecord: %v\n%s", uerr, out)
	}

	// The zero run is the case that fails if a shadow empties an always-present
	// stamp: production never writes one, and a unit test is where it shows up.
	doc := vulnScanDocument{
		WalkScanRun: vuldomain.WalkScanRun{ID: "run-1"},
		StartedAt:   recordstamp.Format(time.Time{}),
		CompletedAt: recordstamp.Format(time.Time{}),
	}
	runOut, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling the run document: %v", err)
	}
	var run vuldomain.WalkScanRun
	if uerr := json.Unmarshal(runOut, &run); uerr != nil {
		t.Fatalf("the rendered run does not decode back into a WalkScanRun: %v\n%s", uerr, runOut)
	}
	if run.ID != "run-1" {
		t.Errorf("decoded run id = %q, want run-1", run.ID)
	}
}

// ledgerStamp keeps an absent stamp absent. An anchor a record never carried
// must not be rendered as year one, and an empty string is what the omitempty
// tag on the wire field needs to see.
func TestLedgerStamp_ZeroRendersEmpty(t *testing.T) {
	if got := ledgerStamp(time.Time{}); got != "" {
		t.Errorf("ledgerStamp(zero) = %q, want the empty string", got)
	}
	rec := stampedRecord(t)
	rec.FirstScannedAt = time.Time{}
	out, err := json.Marshal(toVulnRecordJSON(rec, nil))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(out), "first_scanned_at") {
		t.Errorf("an unset anchor was rendered: %s", out)
	}
}
