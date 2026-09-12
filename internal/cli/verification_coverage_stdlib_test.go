package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The two sentences the acquirer now records where it used to record one. They
// are quoted here as a reader of the report would meet them: this test is about
// the report carrying the record's own words to both surfaces, not about which
// words the acquirer chooses.
const (
	godevUnreachableReason = "go.dev/dl published checksum unavailable for go1.26.4.src.tar.gz" +
		"; googlesource commit anchor unresolved"
	godevNotPublishedReason = "go.dev/dl lists no release go1.26.4, so no published checksum exists for go1.26.4.src.tar.gz" +
		"; googlesource commit anchor unresolved"
)

// stdlibCoverageWalk registers a one-node walk whose only member is the standard
// library, carrying a given custody status and reason, and returns its id.
func stdlibCoverageWalk(t *testing.T, walks *testfakes.FakeQueryWalks, id, status, reason string) string {
	t.Helper()
	walks.AddWalk(walkdomain.WalkRecord{
		ID: id,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{
			Coordinate:       coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.4"),
			ResolutionSource: walkdomain.ResolutionStdlib,
			Stdlib: &walkdomain.StdlibFacts{
				VerificationStatus: status,
				VerificationDetail: reason,
			},
		}}},
	})
	return id
}

// TestRunVerificationCoverage_StdlibAnchorCauseReachesBothSurfaces is the read
// half of the acceptance.
//
// Two different things leave the standard library without a published-checksum
// anchor: go.dev/dl could not be reached, and go.dev/dl answered and publishes
// no checksum for this toolchain version. They ask opposite things of a reader —
// retry the network, or check which toolchain the project pins — and both used
// to arrive here as the same status and the same sentence. This asserts they are
// now told apart on the rendering AND on --json, which is the surface a caller
// parses.
func TestRunVerificationCoverage_StdlibAnchorCauseReachesBothSurfaces(t *testing.T) {
	walks := testfakes.NewFakeQueryWalks()
	unreachableID := stdlibCoverageWalk(t, walks, "01KQDBVW092ER1HNXZ60X27CM1",
		string(stdlibdomain.UnverifiedGoDevUnavailable), godevUnreachableReason)
	notPublishedID := stdlibCoverageWalk(t, walks, "01KQDBVW092ER1HNXZ60X27CM2",
		string(stdlibdomain.UnverifiedGoDevNotPublished), godevNotPublishedReason)
	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{}}

	type row struct {
		Coordinate string `json:"coordinate"`
		Class      string `json:"class"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
	}
	readJSON := func(t *testing.T, id string) row {
		t.Helper()
		jsonOut = true
		t.Cleanup(func() { jsonOut = false })
		var buf bytes.Buffer
		if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf, io.Discard); err != nil {
			t.Fatalf("runVerificationCoverage --json: %v", err)
		}
		var doc struct {
			Modules []row `json:"modules"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("decoding coverage document: %v\n%s", err, buf.String())
		}
		if len(doc.Modules) != 1 {
			t.Fatalf("the document lists %d module(s) for a one-node walk", len(doc.Modules))
		}
		return doc.Modules[0]
	}
	readText := func(t *testing.T, id string) string {
		t.Helper()
		var buf bytes.Buffer
		if err := runVerificationCoverage(context.Background(), id, walks, records, true, &buf, io.Discard); err != nil {
			t.Fatalf("runVerificationCoverage --detail: %v", err)
		}
		return buf.String()
	}

	unreachableJSON, notPublishedJSON := readJSON(t, unreachableID), readJSON(t, notPublishedID)

	if unreachableJSON.Status == notPublishedJSON.Status {
		t.Errorf("both causes report the status %q, so --json cannot tell them apart", unreachableJSON.Status)
	}
	if unreachableJSON.Reason == notPublishedJSON.Reason {
		t.Errorf("both causes report the reason %q, so --json cannot tell them apart", unreachableJSON.Reason)
	}
	if unreachableJSON.Status != string(stdlibdomain.UnverifiedGoDevUnavailable) {
		t.Errorf("unreachable manifest: status = %q", unreachableJSON.Status)
	}
	if notPublishedJSON.Status != string(stdlibdomain.UnverifiedGoDevNotPublished) {
		t.Errorf("nothing published: status = %q", notPublishedJSON.Status)
	}
	if strings.Contains(notPublishedJSON.Reason, "unavailable") {
		t.Errorf("nothing published still calls go.dev/dl unavailable: %q", notPublishedJSON.Reason)
	}
	// The coarse bucket is unchanged: neither carries an anchor, and the class is
	// the word that counts them. Only the status and the reason distinguish them,
	// which is where the distinction belongs.
	for name, got := range map[string]row{"unreachable": unreachableJSON, "nothing published": notPublishedJSON} {
		if got.Class != fetchdomain.BucketUnverified.String() {
			t.Errorf("%s: class = %q, want %q", name, got.Class, fetchdomain.BucketUnverified.String())
		}
	}

	unreachableText, notPublishedText := readText(t, unreachableID), readText(t, notPublishedID)
	for want, out := range map[string]string{
		string(stdlibdomain.UnverifiedGoDevUnavailable):  unreachableText,
		godevUnreachableReason:                           unreachableText,
		string(stdlibdomain.UnverifiedGoDevNotPublished): notPublishedText,
		godevNotPublishedReason:                          notPublishedText,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--detail does not print %q:\n%s", want, out)
		}
	}
	if strings.Contains(notPublishedText, godevUnreachableReason) {
		t.Errorf("--detail printed the unavailable sentence for a manifest that answered:\n%s", notPublishedText)
	}
}

// The two sentences the stdlib record carries when the licence could not be
// identified. As above, they are quoted as a reader meets them.
const (
	licenceAbsentReason = "SHA-256 matched go.dev/dl published checksum for go1.26.4.src.tar.gz" +
		"; googlesource commit anchor unresolved" +
		"; no LICENSE text was found to classify, so no licence is recorded"
	licenceUnrecognisedReason = "SHA-256 matched go.dev/dl published checksum for go1.26.4.src.tar.gz" +
		"; googlesource commit anchor unresolved" +
		"; the licence classifier read the LICENSE text and matched no licence it knows"
)

// TestRunVerificationCoverage_StdlibLicenceCauseReachesBothSurfaces is the
// licence half of the same acceptance.
//
// A source tarball with no LICENSE file and a classifier that recognises nothing
// both leave the SPDX identifier empty. The record now says which, and
// this asserts the report relays it to the rendering and to --json rather than
// stopping at the record.
func TestRunVerificationCoverage_StdlibLicenceCauseReachesBothSurfaces(t *testing.T) {
	walks := testfakes.NewFakeQueryWalks()
	absentID := stdlibCoverageWalk(t, walks, "01KQDBVW092ER1HNXZ60X27CM3",
		string(stdlibdomain.VerifiedGoDevChecksum), licenceAbsentReason)
	unrecognisedID := stdlibCoverageWalk(t, walks, "01KQDBVW092ER1HNXZ60X27CM4",
		string(stdlibdomain.VerifiedGoDevChecksum), licenceUnrecognisedReason)
	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{}}

	reasonFromJSON := func(t *testing.T, id string) string {
		t.Helper()
		jsonOut = true
		t.Cleanup(func() { jsonOut = false })
		var buf bytes.Buffer
		if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf, io.Discard); err != nil {
			t.Fatalf("runVerificationCoverage --json: %v", err)
		}
		var doc struct {
			Modules []struct {
				Reason string `json:"reason"`
			} `json:"modules"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("decoding coverage document: %v\n%s", err, buf.String())
		}
		if len(doc.Modules) != 1 {
			t.Fatalf("the document lists %d module(s) for a one-node walk", len(doc.Modules))
		}
		return doc.Modules[0].Reason
	}
	textOf := func(t *testing.T, id string) string {
		t.Helper()
		var buf bytes.Buffer
		if err := runVerificationCoverage(context.Background(), id, walks, records, true, &buf, io.Discard); err != nil {
			t.Fatalf("runVerificationCoverage --detail: %v", err)
		}
		return buf.String()
	}

	absentJSON, unrecognisedJSON := reasonFromJSON(t, absentID), reasonFromJSON(t, unrecognisedID)
	if absentJSON == unrecognisedJSON {
		t.Errorf("both licence causes report the reason %q, so --json cannot tell them apart", absentJSON)
	}
	if absentJSON != licenceAbsentReason {
		t.Errorf("--json reason = %q, want the recorded one", absentJSON)
	}
	if unrecognisedJSON != licenceUnrecognisedReason {
		t.Errorf("--json reason = %q, want the recorded one", unrecognisedJSON)
	}

	absentText, unrecognisedText := textOf(t, absentID), textOf(t, unrecognisedID)
	if !strings.Contains(absentText, "no LICENSE text was found to classify") {
		t.Errorf("--detail does not say the LICENSE file was absent:\n%s", absentText)
	}
	if !strings.Contains(unrecognisedText, "matched no licence it knows") {
		t.Errorf("--detail does not say the classifier recognised nothing:\n%s", unrecognisedText)
	}
	if strings.Contains(unrecognisedText, "no LICENSE text was found") {
		t.Errorf("--detail confused the two licence causes:\n%s", unrecognisedText)
	}
}
