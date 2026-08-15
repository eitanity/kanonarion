package cli

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// auditRowKeys marshals a row and returns the object it produced, so an
// assertion can be about the KEY's presence and not only about its value. A
// field erased by `omitempty` is absent, which no assertion on the decoded
// value can distinguish from a zero.
func auditRowKeys(t *testing.T, res auditModuleResult) map[string]any {
	t.Helper()
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshalling audit row: %v", err)
	}
	var decoded map[string]any
	if uerr := json.Unmarshal(data, &decoded); uerr != nil {
		t.Fatalf("unmarshalling audit row: %v", uerr)
	}
	return decoded
}

// stdlibRowUnderScope derives a real audit row through the production builder,
// under the policy scope given. Deriving it rather than writing a struct
// literal is the point: a literal would assert the JSON tag and nothing about
// whether the field is ever filled.
func stdlibRowUnderScope(t *testing.T, policyScope string, rec *vulndomain.VulnerabilityRecord) auditModuleResult {
	t.Helper()
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	activeConfig = configdomain.DefaultConfig()

	coord, err := coordinate.NewModuleCoordinate("std", "v1.26.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	fake := testfakes.NewFakeQueryVuln()
	if rec != nil {
		fake.AddRecord(coord, *rec)
	}
	node := walkdomain.GraphNode{Coordinate: coord, ResolutionSource: walkdomain.ResolutionStdlib}
	ctr := &Container{QueryVuln: fake}
	return buildStdlibAuditResult(context.Background(), coord, node, policyScope,
		vulnFrameAnchor{walkID: "walk-1"}, ctr)
}

// TestAuditJSON_PolicyPairSeparatesEvaluatedFromUnevaluated is the acceptance
// the pair exists for.
//
// Both fields carried `omitempty`, and on a repo where nothing blocks both are
// false, so both keys vanished — leaving "the policy ran and nothing blocks"
// and "no policy ran at all" as the same document. A consumer had no key to
// read, and the distinction PolicyUnevaluated exists to draw was destroyed by
// the encoding rather than by the measurement.
//
// Both halves are derived, and the unevaluated half is the NON-ZERO control:
// the scope in force matches no rule, the real evaluator sets both flags, and
// the row must carry true rather than a value a literal put there.
func TestAuditJSON_PolicyPairSeparatesEvaluatedFromUnevaluated(t *testing.T) {
	// Evaluated, nothing blocks. Both keys must be present and false.
	evaluated := auditRowKeys(t, stdlibRowUnderScope(t, "production", nil))
	for _, key := range []string{"policy_blocking", "policy_unevaluated"} {
		v, present := evaluated[key]
		if !present {
			t.Fatalf("%s is absent on an evaluated row; absence is not an answer, and it is the only thing that separates this row from one no policy was run for", key)
		}
		if v != false {
			t.Errorf("%s = %v on an evaluated, non-blocking row, want false", key, v)
		}
	}

	// Non-zero control: a scope no rule covers. The gate evaluated nothing,
	// which is reported and blocking.
	unevaluated := auditRowKeys(t, stdlibRowUnderScope(t, "mystery", nil))
	for _, key := range []string{"policy_blocking", "policy_unevaluated"} {
		v, present := unevaluated[key]
		if !present {
			t.Fatalf("%s is absent on an unevaluated row", key)
		}
		if v != true {
			t.Errorf("%s = %v on a row whose scope matches no rule, want true", key, v)
		}
	}

	// The two rows must be tellable apart from the document alone — which is
	// the whole claim, and was false while both keys were omitted at zero.
	if evaluated["policy_unevaluated"] == unevaluated["policy_unevaluated"] {
		t.Error("an evaluated row and an unevaluated one carry the same policy_unevaluated; the document cannot separate them")
	}
}

// TestAuditJSON_VulnWithdrawnIsEmittedAtZero pins the count.
//
// `vuln_withdrawn` counts the retracted subset of `vuln_findings`. Omitted at
// zero it collapsed "no advisory covering this module was retracted" into "this
// build does not report retractions", in a tool that made Withdrawn a
// first-class state — and it sat on a different convention from
// `vuln_findings`, which is derived by the same call, from the same record, and
// is always emitted.
func TestAuditJSON_VulnWithdrawnIsEmittedAtZero(t *testing.T) {
	zero := auditRowKeys(t, stdlibRowUnderScope(t, "production", nil))
	got, present := zero["vuln_withdrawn"]
	if !present {
		t.Fatal("vuln_withdrawn is absent on a row with no retraction; vuln_findings is emitted at zero on the same row and the two are one fact")
	}
	if int(got.(float64)) != 0 {
		t.Errorf("vuln_withdrawn = %v, want 0", got)
	}
	if _, present := zero["vuln_findings"]; !present {
		t.Error("vuln_findings is absent; the sibling convention this field is being brought onto has itself changed")
	}

	// Non-zero control: a record carrying one live finding and one retraction.
	// The value is derived by vulnAuditStatus from the record, not written into
	// the row, so this fails if the count stops being computed as well as if
	// the key is erased.
	var res auditModuleResult
	rec := vulndomain.VulnerabilityRecord{
		OverallStatus: vulndomain.StatusAffected,
		Findings: []vulndomain.VulnerabilityFinding{
			{ID: "GO-2026-0001"},
			{ID: "GO-2026-0002", WithdrawnAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
		},
	}
	res.VulnStatus, res.VulnReason, res.VulnFindings, res.VulnWithdrawn = vulnAuditStatus(rec, true, nil, "")
	if res.VulnWithdrawn != 1 || res.VulnFindings != 2 {
		t.Fatalf("derived findings/withdrawn = %d/%d, want 2/1", res.VulnFindings, res.VulnWithdrawn)
	}
	nonZero := auditRowKeys(t, res)
	if got := nonZero["vuln_withdrawn"]; int(got.(float64)) != 1 {
		t.Errorf("vuln_withdrawn = %v on a row with one retraction, want 1", got)
	}
	if got := nonZero["vuln_findings"]; int(got.(float64)) != 2 {
		t.Errorf("vuln_findings = %v, want 2 (retracted advisories are counted in the total)", got)
	}
}

// TestAuditJSON_NoOmitemptyWhereZeroIsAnAnswer is the sibling of the staleness
// structural guard, and it is separate because the answer to "pointer or plain
// value" is different here.
//
// The staleness fields are pointers: a row genuinely may not have been measured
// — an offline run asks the proxy nothing — so there is a third state and null
// says it. These three have no third state to say:
//
//   - PolicyBlocking / PolicyUnevaluated: both row builders evaluate the licence
//     policy before returning, so no row exists on which the gate was not run.
//     PolicyUnevaluated is itself the "the gate decided nothing" flag, so a null
//     would be a second encoding of the state the field already names.
//   - VulnWithdrawn: derived by the same call, from the same record, as
//     VulnFindings, which is a plain int. Which absence an unscanned row is —
//     not scanned, superseded, unreadable — is stated by VulnStatus and
//     VulnReason. A pointer here would put a count and the total it is a subset
//     of on two different conventions, which is the defect this closes.
//
// So the guard is: no `omitempty`, and NOT a pointer.
func TestAuditJSON_NoOmitemptyWhereZeroIsAnAnswer(t *testing.T) {
	typ := reflect.TypeOf(auditModuleResult{})
	for _, name := range []string{"VulnWithdrawn", "VulnFindings", "PolicyBlocking", "PolicyUnevaluated", "LicenseResolved", "MajorProbed", "Direct"} {
		field, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("auditModuleResult has no field %s", name)
			continue
		}
		tag := field.Tag.Get("json")
		if strings.Contains(tag, "omitempty") {
			t.Errorf("auditModuleResult.%s carries omitempty (%q); zero and false are measurements here and would be erased", name, tag)
		}
		if field.Type.Kind() == reflect.Pointer {
			t.Errorf("auditModuleResult.%s is a pointer (%s); these fields have no unmeasured state, and a null would be a second way of saying what the value already says", name, field.Type)
		}
	}

	// Nothing else in the struct may reintroduce the shape. Strings and slices
	// are exempt: an empty string there means "does not apply" and a named
	// sibling says which state the row is in.
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if !strings.Contains(tag, "omitempty") {
			continue
		}
		switch field.Type.Kind() {
		case reflect.Bool, reflect.Int, reflect.Int64, reflect.Float64:
			t.Errorf("auditModuleResult.%s is %s with omitempty (%q); a scalar zero here is a measurement and would be erased",
				field.Name, field.Type, tag)
		default:
		}
	}
}
