package domain_test

import (
	"encoding/json"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// The four licence enums a CLI surface publishes. Every constant is listed with
// the name it must carry and round-tripped, so one added without a decode case
// fails here rather than marshalling to a name nothing reads back.

func TestLicenseStatusJSON(t *testing.T) {
	cases := []struct {
		s    domain.LicenseStatus
		want string
	}{
		{domain.LicenceStatusUnknown, `"Unknown"`},
		{domain.LicenseStatusDetected, `"Detected"`},
		{domain.LicenceStatusAmbiguous, `"Ambiguous"`},
		{domain.LicenseStatusMultiple, `"Multiple"`},
		{domain.LicenseStatusNone, `"None"`},
		{domain.LicenseStatusUnclassified, `"Unclassified"`},
		{domain.LicenseStatusExtractionFailed, `"ExtractionFailed"`},
		{domain.LicenseStatusCancelled, `"Cancelled"`},
		{domain.LicenseStatusPerFile, `"PerFile"`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.s)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tc.s, err)
		}
		if got := string(b); got != tc.want {
			t.Errorf("json.Marshal(%v) = %s, want %s", tc.s, got, tc.want)
		}
		var back domain.LicenseStatus
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", b, err)
		}
		if back != tc.s {
			t.Errorf("round trip of %v gave %v", tc.s, back)
		}
	}
}

func TestLicenseStatusUnmarshalRefusals(t *testing.T) {
	var s domain.LicenseStatus
	if err := json.Unmarshal([]byte(`"detected"`), &s); err == nil {
		t.Error("a name that is not a LicenseStatus must be refused")
	}
	if err := json.Unmarshal([]byte(`1`), &s); err == nil {
		t.Error("an ordinal must be refused: the wire form is the name")
	}
}

func TestCopyrightStatusJSON(t *testing.T) {
	cases := []struct {
		s    domain.CopyrightStatus
		want string
	}{
		{domain.CopyrightStatusNotAnalysed, `"not_analysed"`},
		{domain.CopyrightStatusFound, `"found"`},
		{domain.CopyrightStatusNoneFound, `"none_found"`},
		{domain.CopyrightStatusExtractionFailed, `"extraction_failed"`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.s)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tc.s, err)
		}
		if got := string(b); got != tc.want {
			t.Errorf("json.Marshal(%v) = %s, want %s", tc.s, got, tc.want)
		}
		var back domain.CopyrightStatus
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", b, err)
		}
		if back != tc.s {
			t.Errorf("round trip of %v gave %v", tc.s, back)
		}
	}
}

func TestCopyrightStatusUnmarshalRefusals(t *testing.T) {
	var s domain.CopyrightStatus
	if err := json.Unmarshal([]byte(`"none found"`), &s); err == nil {
		t.Error("the text view's label must not decode as the machine name")
	}
	if err := json.Unmarshal([]byte(`2`), &s); err == nil {
		t.Error("an ordinal must be refused: the wire form is the name")
	}
}

func TestProvenanceSignalJSON(t *testing.T) {
	cases := []struct {
		s    domain.ProvenanceSignal
		want string
	}{
		{domain.ProvenanceSignalInboundOutbound, `"inbound_outbound"`},
		{domain.ProvenanceSignalCLARequired, `"cla_required"`},
		{domain.ProvenanceSignalDCORequired, `"dco_required"`},
		{domain.ProvenanceSignalAuthorsFile, `"authors_file"`},
		{domain.ProvenanceSignalContributorsFile, `"contributors_file"`},
		{domain.ProvenanceSignalPatentsFile, `"patents_file"`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.s)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tc.s, err)
		}
		if got := string(b); got != tc.want {
			t.Errorf("json.Marshal(%v) = %s, want %s", tc.s, got, tc.want)
		}
		var back domain.ProvenanceSignal
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", b, err)
		}
		if back != tc.s {
			t.Errorf("round trip of %v gave %v", tc.s, back)
		}
	}
}

func TestProvenanceSignalUnmarshalRefusals(t *testing.T) {
	var s domain.ProvenanceSignal
	// "unknown" is what String reports for a value outside the constant block;
	// decoding it would produce a signal that names no evidence.
	if err := json.Unmarshal([]byte(`"unknown"`), &s); err == nil {
		t.Error("\"unknown\" must be refused, not decoded to a signal")
	}
	if err := json.Unmarshal([]byte(`2`), &s); err == nil {
		t.Error("an ordinal must be refused: the wire form is the name")
	}
}

// A value outside the constant block marshals to "unknown", which the decoder
// then refuses: the asymmetry is deliberate, since no signal decodes back from
// a name that stands for "no signal at all".
func TestProvenanceSignalOutsideConstantBlock(t *testing.T) {
	b, err := json.Marshal(domain.ProvenanceSignal(99))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if got, want := string(b), `"unknown"`; got != want {
		t.Errorf("json.Marshal(99) = %s, want %s", got, want)
	}
	var back domain.ProvenanceSignal
	if err := json.Unmarshal(b, &back); err == nil {
		t.Error("\"unknown\" decoded to a signal; it must be refused")
	}
}

func TestProvenanceSignalSliceJSON(t *testing.T) {
	in := []domain.ProvenanceSignal{
		domain.ProvenanceSignalCLARequired,
		domain.ProvenanceSignalAuthorsFile,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if got, want := string(b), `["cla_required","authors_file"]`; got != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}

func TestChainOfTitleConfidenceJSON(t *testing.T) {
	cases := []struct {
		c    domain.ChainOfTitleConfidence
		want string
	}{
		{domain.ChainOfTitleNotAnalysed, `"not_analysed"`},
		{domain.ChainOfTitleHigh, `"high"`},
		{domain.ChainOfTitleMedium, `"medium"`},
		{domain.ChainOfTitleLow, `"low"`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.c)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tc.c, err)
		}
		if got := string(b); got != tc.want {
			t.Errorf("json.Marshal(%v) = %s, want %s", tc.c, got, tc.want)
		}
		var back domain.ChainOfTitleConfidence
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", b, err)
		}
		if back != tc.c {
			t.Errorf("round trip of %v gave %v", tc.c, back)
		}
	}
}

func TestChainOfTitleConfidenceUnmarshalRefusals(t *testing.T) {
	var c domain.ChainOfTitleConfidence
	if err := json.Unmarshal([]byte(`"High"`), &c); err == nil {
		t.Error("a name that is not a ChainOfTitleConfidence must be refused")
	}
	if err := json.Unmarshal([]byte(`1`), &c); err == nil {
		t.Error("an ordinal must be refused: the wire form is the name")
	}
}

// The content hash must not move: the canonical shape declares these four
// fields as plain int, so a marshaller on the named type never reaches the seal.
func TestEnumMarshallersAreHashTransparent(t *testing.T) {
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Ecosystem:       "go",
		PrimarySPDX:     "Apache-2.0",
		OverallStatus:   domain.LicenseStatusDetected,
		CopyrightStatus: domain.CopyrightStatusNoneFound,
		Provenance: domain.ProvenanceSummary{
			Signals:    []domain.ProvenanceSignal{domain.ProvenanceSignalCLARequired},
			Confidence: domain.ChainOfTitleHigh,
		},
	}
	canonical, err := domain.LicenseRecordHasher{}.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var seen map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &seen); err != nil {
		t.Fatalf("decoding canonical JSON: %v", err)
	}
	for field, want := range map[string]string{
		"overall_status":   "1",
		"copyright_status": "2",
	} {
		if got := string(seen[field]); got != want {
			t.Errorf("canonical %s = %s, want the ordinal %s: the seal must not follow the view",
				field, got, want)
		}
	}
	var prov struct {
		Confidence json.RawMessage `json:"confidence"`
		Signals    json.RawMessage `json:"signals"`
	}
	if err := json.Unmarshal(seen["provenance"], &prov); err != nil {
		t.Fatalf("decoding canonical provenance: %v", err)
	}
	if got := string(prov.Confidence); got != "1" {
		t.Errorf("canonical provenance.confidence = %s, want the ordinal 1", got)
	}
	if got := string(prov.Signals); got != "[2]" {
		t.Errorf("canonical provenance.signals = %s, want the ordinals [2]", got)
	}
}
