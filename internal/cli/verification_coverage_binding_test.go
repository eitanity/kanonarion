package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// bindingFixture is a three-module graph, one per binding: a coordinate-derived
// clone URL, a proxy-named one, and a record written before the binding was
// measured. All three are Verified, which is the whole point — until now they
// were indistinguishable.
func bindingFixture(t *testing.T) ([]walkdomain.GraphNode, fakeFetchRecords) {
	t.Helper()

	derived := coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.0")
	proxyNamed := coordinatetest.MustNew("go.uber.org/zap", "v1.27.0")
	unrecorded := coordinatetest.MustNew("example.com/old", "v1.0.0")

	verified := func(binding fetchdomain.VCSURLBinding) fetchdomain.CompositeRecord {
		return fetchdomain.CompositeRecord{
			FactRecord: fetchdomain.FactRecord{
				VerificationStatus: string(fetchdomain.Verified),
				VCSURLBinding:      string(binding),
			},
			Legs: []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegVCS, Provenance: fetchdomain.LegRechecked}},
		}
	}

	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		derived:    verified(fetchdomain.VCSURLBindingCoordinateDerived),
		proxyNamed: verified(fetchdomain.VCSURLBindingProxyNamed),
		unrecorded: verified(fetchdomain.VCSURLBindingAbsent),
	}}
	nodes := []walkdomain.GraphNode{
		{Coordinate: derived, ResolutionSource: walkdomain.ResolutionMVS},
		{Coordinate: proxyNamed, ResolutionSource: walkdomain.ResolutionMVS},
		{Coordinate: unrecorded, ResolutionSource: walkdomain.ResolutionMVS},
	}
	return nodes, records
}

// TestGraphVerificationRows_SplitByBinding is the per-module half: the class a
// module reports must name its binding, and the row must carry the binding
// itself so a reader can name the modules behind a count.
func TestGraphVerificationRows_SplitByBinding(t *testing.T) {
	nodes, records := bindingFixture(t)
	rows := graphVerificationRows(context.Background(), nodes, records)

	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	want := map[string]struct{ class, binding string }{
		"github.com/spf13/cobra@v1.8.0": {
			class:   fetchdomain.BucketCrossVerifiedModulePathURL.String(),
			binding: string(fetchdomain.VCSURLBindingCoordinateDerived),
		},
		"go.uber.org/zap@v1.27.0": {
			class:   fetchdomain.BucketCrossVerifiedProxyNamedURL.String(),
			binding: string(fetchdomain.VCSURLBindingProxyNamed),
		},
		"example.com/old@v1.0.0": {
			class:   fetchdomain.BucketCrossVerified.String(),
			binding: "",
		},
	}
	for _, r := range rows {
		w, ok := want[r.Coordinate]
		if !ok {
			t.Errorf("unexpected row %q", r.Coordinate)
			continue
		}
		if r.Class != w.class {
			t.Errorf("%s: class = %q, want %q", r.Coordinate, r.Class, w.class)
		}
		if r.VCSURLBinding != w.binding {
			t.Errorf("%s: vcs_url_binding = %q, want %q", r.Coordinate, r.VCSURLBinding, w.binding)
		}
		// Every one of the three is still Verified. The split attributes; it
		// does not downgrade.
		if r.Status != string(fetchdomain.Verified) {
			t.Errorf("%s: status = %q, want Verified — the binding moved a verdict", r.Coordinate, r.Status)
		}
	}
}

// TestWriteVerificationCoverage_ShowsTheBindingSplit is the text half. The
// cross-verified total line is unchanged, and the split is stated beneath it so
// a reader of the ordinary output sees it without asking for --json.
func TestWriteVerificationCoverage_ShowsTheBindingSplit(t *testing.T) {
	nodes, records := bindingFixture(t)
	c := graphVerificationCoverage(context.Background(), nodes, records)

	var buf bytes.Buffer
	if err := writeVerificationCoverage(&buf, c); err != nil {
		t.Fatalf("writeVerificationCoverage: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"cross-verified (checksum db + VCS)     3  100.0%",
		"of which VCS URL from the module path",
		"of which VCS URL named by the proxy",
		"of which binding not recorded",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("coverage output does not contain %q:\n%s", want, out)
		}
	}
}

// TestWriteVerificationCoverage_NoSplitLinesWithoutCrossVerification keeps the
// collapsed graph's output as loud and as short as it was: there is no split to
// state when nothing was cross-verified.
func TestWriteVerificationCoverage_NoSplitLinesWithoutCrossVerification(t *testing.T) {
	c := fetchdomain.VerificationCoverageOf([]fetchdomain.CoverageObservation{
		{Bucket: fetchdomain.BucketChecksumDBOnly, Recorded: true},
	})
	var buf bytes.Buffer
	if err := writeVerificationCoverage(&buf, c); err != nil {
		t.Fatalf("writeVerificationCoverage: %v", err)
	}
	if strings.Contains(buf.String(), "of which") {
		t.Errorf("a graph with no cross-verification printed a binding split:\n%s", buf.String())
	}
}

// TestVerificationCoverageJSON_CarriesTheBindingSplit is the --json half,
// asserted separately from the text because a CI gate reads this document and
// never sees the prose. cross_verified keeps its meaning — the total — so a gate
// written before this change keeps working.
func TestVerificationCoverageJSON_CarriesTheBindingSplit(t *testing.T) {
	nodes, records := bindingFixture(t)
	c := graphVerificationCoverage(context.Background(), nodes, records)
	rows := graphVerificationRows(context.Background(), nodes, records)

	data, err := json.Marshal(verificationCoverageJSON("01TESTWALK", c, rows, buildVendoring{}, walkBuildJSON{}))
	if err != nil {
		t.Fatalf("marshalling coverage document: %v", err)
	}
	var doc struct {
		CrossVerified                  int `json:"cross_verified"`
		CrossVerifiedModulePathURL     int `json:"cross_verified_module_path_url"`
		CrossVerifiedProxyNamedURL     int `json:"cross_verified_proxy_named_url"`
		CrossVerifiedBindingUnrecorded int `json:"cross_verified_binding_unrecorded"`
		Modules                        []struct {
			Coordinate    string `json:"coordinate"`
			Class         string `json:"class"`
			VCSURLBinding string `json:"vcs_url_binding"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decoding coverage document: %v", err)
	}

	if doc.CrossVerified != 3 {
		t.Errorf("cross_verified = %d, want 3: the split changed the total a gate reads", doc.CrossVerified)
	}
	if doc.CrossVerifiedModulePathURL != 1 {
		t.Errorf("cross_verified_module_path_url = %d, want 1", doc.CrossVerifiedModulePathURL)
	}
	if doc.CrossVerifiedProxyNamedURL != 1 {
		t.Errorf("cross_verified_proxy_named_url = %d, want 1", doc.CrossVerifiedProxyNamedURL)
	}
	if doc.CrossVerifiedBindingUnrecorded != 1 {
		t.Errorf("cross_verified_binding_unrecorded = %d, want 1", doc.CrossVerifiedBindingUnrecorded)
	}
	if sum := doc.CrossVerifiedModulePathURL + doc.CrossVerifiedProxyNamedURL + doc.CrossVerifiedBindingUnrecorded; sum != doc.CrossVerified {
		t.Errorf("the three binding counts sum to %d, want cross_verified %d", sum, doc.CrossVerified)
	}

	byCoord := map[string]string{}
	for _, m := range doc.Modules {
		byCoord[m.Coordinate] = m.VCSURLBinding
	}
	if got := byCoord["go.uber.org/zap@v1.27.0"]; got != string(fetchdomain.VCSURLBindingProxyNamed) {
		t.Errorf("per-module vcs_url_binding for the vanity path = %q, want %q",
			got, fetchdomain.VCSURLBindingProxyNamed)
	}
	if got, present := byCoord["example.com/old@v1.0.0"]; got != "" {
		t.Errorf("a record with no binding emitted vcs_url_binding = %q (present=%v), want the key omitted",
			got, present)
	}
}
