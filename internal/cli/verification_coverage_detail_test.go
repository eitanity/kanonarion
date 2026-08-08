package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// reasonedCoverageFixture is coverageFixture with a recorded reason on the
// degraded module — the case the report exists for. It also takes the project
// directory the walk was rooted at, because the disclosure is keyed on it.
func reasonedCoverageFixture(t *testing.T, projectDir string) (*testfakes.FakeQueryWalks, fakeFetchRecords, string) {
	t.Helper()

	anchored := coordinatetest.MustNew("example.com/anchored", "v1.0.0")
	degraded := coordinatetest.MustNew("example.com/degraded", "v2.0.0")
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}

	records := fakeFetchRecords{byCoord: map[coordinate.ModuleCoordinate]fetchdomain.CompositeRecord{
		anchored: {
			FactRecord: fetchdomain.FactRecord{VerificationStatus: string(fetchdomain.Verified)},
			Legs:       []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegVCS, Provenance: fetchdomain.LegRechecked}},
		},
		degraded: {
			FactRecord: fetchdomain.FactRecord{
				VerificationStatus: string(fetchdomain.VerifiedBySumDBOnly),
				VerificationDetail: degradedReason,
			},
			Legs: []fetchdomain.ValidationLeg{{Kind: fetchdomain.LegSumDB, Provenance: fetchdomain.LegRechecked}},
		},
	}}

	walks := testfakes.NewFakeQueryWalks()
	const id = "01KQDBVW092ER1HNXZ60X27CME"
	walks.AddWalk(walkdomain.WalkRecord{
		ID:         id,
		ProjectDir: projectDir,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
			{Coordinate: anchored, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: degraded, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: local, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		}},
	})
	return walks, records, id
}

// degradedReason is the kind of thing a record actually records: the forge that
// could not be reached. Establishing this used to require python3 over another
// command's JSON.
const degradedReason = "resolving tag refs/tags/v2.0.0: ls-remote https://example.com/degraded: connection refused"

// TestRunVerificationCoverage_JSONCarriesEveryModuleWithItsReason is the failing
// scenario: the command emitted class COUNTS and nothing per module, so the
// question the counts are asked in service of — WHY are these modules only
// checksum-database-verified — could not be answered from this command at all.
func TestRunVerificationCoverage_JSONCarriesEveryModuleWithItsReason(t *testing.T) {
	walks, records, id := reasonedCoverageFixture(t, "")

	jsonOut = true
	t.Cleanup(func() { jsonOut = false })

	var buf bytes.Buffer
	if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf, io.Discard); err != nil {
		t.Fatalf("runVerificationCoverage: %v", err)
	}

	var got struct {
		Total   int `json:"total"`
		Modules []struct {
			Coordinate string `json:"coordinate"`
			Class      string `json:"class"`
			Status     string `json:"status"`
			Reason     string `json:"reason"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding coverage document: %v\n%s", err, buf.String())
	}

	if len(got.Modules) != got.Total {
		t.Fatalf("the document lists %d module(s) for a graph of %d; every node must be accounted for", len(got.Modules), got.Total)
	}
	for _, m := range got.Modules {
		if m.Class == "" {
			t.Errorf("%s carries no class", m.Coordinate)
		}
		if m.Status == "" && m.Reason == "" {
			t.Errorf("%s carries neither a recorded status nor a reason; a class without its basis is the claim the reader cannot check", m.Coordinate)
		}
	}

	var found bool
	for _, m := range got.Modules {
		if m.Coordinate != "example.com/degraded@v2.0.0" {
			continue
		}
		found = true
		if m.Class != fetchdomain.BucketChecksumDBOnly.String() {
			t.Errorf("degraded module's class is %q, want %q", m.Class, fetchdomain.BucketChecksumDBOnly.String())
		}
		if m.Reason != degradedReason {
			t.Errorf("degraded module's reason is %q, want the reason the record recorded", m.Reason)
		}
	}
	if !found {
		t.Error("the checksum-database-only module is absent from the per-module list")
	}
}

// TestRunVerificationCoverage_DetailPrintsClassAndReason covers the text path's
// opt-in. The flag is an opt-in to length, never to the answer being checkable.
func TestRunVerificationCoverage_DetailPrintsClassAndReason(t *testing.T) {
	walks, records, id := reasonedCoverageFixture(t, "")

	var without bytes.Buffer
	if err := runVerificationCoverage(context.Background(), id, walks, records, false, &without, io.Discard); err != nil {
		t.Fatalf("runVerificationCoverage: %v", err)
	}
	if strings.Contains(without.String(), degradedReason) {
		t.Errorf("the default text output printed the per-module list unasked:\n%s", without.String())
	}

	var with bytes.Buffer
	if err := runVerificationCoverage(context.Background(), id, walks, records, true, &with, io.Discard); err != nil {
		t.Fatalf("runVerificationCoverage --detail: %v", err)
	}
	out := with.String()
	for _, want := range []string{
		"example.com/degraded@v2.0.0",
		fetchdomain.BucketChecksumDBOnly.String(),
		degradedReason,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--detail does not print %q:\n%s", want, out)
		}
	}
}

// TestRunVerificationCoverage_StatesAVendoredBuild pairs the disclosure with its
// zero: coverage describes the modules the manifest resolved, and a vendored
// project compiles something else.
func TestRunVerificationCoverage_StatesAVendoredBuild(t *testing.T) {
	for name, vendored := range map[string]bool{"vendored": true, "not vendored": false} {
		root := t.TempDir()
		if vendored {
			if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o750); err != nil {
				t.Fatalf("creating vendor/: %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte("# example.com/anchored v1.0.0\n"), 0o600); err != nil {
				t.Fatalf("writing modules.txt: %v", err)
			}
		}
		walks, records, id := reasonedCoverageFixture(t, root)

		var buf bytes.Buffer
		if err := runVerificationCoverage(context.Background(), id, walks, records, false, &buf, io.Discard); err != nil {
			t.Fatalf("%s: runVerificationCoverage: %v", name, err)
		}
		if got := strings.Contains(buf.String(), "vendored build:"); got != vendored {
			t.Errorf("%s: disclosure present = %t, want %t:\n%s", name, got, vendored, buf.String())
		}
	}
}
