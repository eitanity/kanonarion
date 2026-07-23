package cli

import (
	"strings"
	"testing"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestUnscanDisplays_CoversEveryReason is the durable half of the fix: every
// declared UnscanReason must have an explicit display entry. A reason with no
// entry used to fall through to the raw status string, so the module rendered as
// a bare "Unscannable" with no explanation while a module carrying a mapped
// reason got one — a difference in presentation that no difference in analysis
// backs. Failing here is how a newly added reason is caught, instead of it
// reaching a scan log unexplained.
func TestUnscanDisplays_CoversEveryReason(t *testing.T) {
	for _, reason := range vuldomain.AllUnscanReasons() {
		d, ok := unscanDisplays[reason]
		if !ok {
			t.Errorf("reason %q has no display entry: add one to unscanDisplays", reason)
			continue
		}
		if d.label == "" {
			t.Errorf("reason %q has an empty per-module label", reason)
		}
		if d.heading == "" {
			t.Errorf("reason %q has an empty roll-up heading", reason)
		}
		if strings.TrimSpace(d.label) == string(vuldomain.StatusUnscannable) {
			t.Errorf("reason %q renders as the bare status, which is the defect this table exists to prevent", reason)
		}
	}
	for reason := range unscanDisplays {
		if unscanDisplayFor(reason).label == "" {
			t.Errorf("display lookup for %q returned an empty label", reason)
		}
	}
}

// TestUnscanDisplays_OnlyOutOfToolchainCarriesADirection pins the one reason
// that gets a next-step line. The reachability --local direction answers a
// project-rooted question for a module whose isolated build re-resolved
// versions; it is the wrong remedy for a toolchain or host limitation, where no
// operator action on this host changes the outcome.
func TestUnscanDisplays_OnlyOutOfToolchainCarriesADirection(t *testing.T) {
	for reason, d := range unscanDisplays {
		wantHint := reason == vuldomain.UnscanReasonVersionNotInToolchain
		if wantHint && d.hint == "" {
			t.Errorf("reason %q must keep the reachability direction", reason)
		}
		if !wantHint && d.hint != "" {
			t.Errorf("reason %q must not carry a direction line, got %q", reason, d.hint)
		}
	}
}

// TestUnscanDisplays_ProjectFaultsReadAsOneFault covers the fan-out case: a
// single project-rooted failure is stamped onto every coordinate in the walk, so
// its heading must not read as N independent module problems.
func TestUnscanDisplays_ProjectFaultsReadAsOneFault(t *testing.T) {
	for _, reason := range []vuldomain.UnscanReason{
		vuldomain.UnscanReasonProjectNoGoMod,
		vuldomain.UnscanReasonProjectDirUnavailable,
	} {
		heading := unscanDisplayFor(reason).heading
		if !strings.Contains(heading, "one project-level fault") {
			t.Errorf("reason %q heading must name the single project-level fault, got %q", reason, heading)
		}
	}
}

// TestUnscanDisplayFor_UnmappedReasonIsLoud covers the fallback. An unmapped or
// absent reason still names itself rather than degrading to a bare status: the
// exhaustiveness test above makes this unreachable for a declared reason, and
// the fallback keeps a record readable if one ever slips through.
func TestUnscanDisplayFor_UnmappedReasonIsLoud(t *testing.T) {
	d := unscanDisplayFor(vuldomain.UnscanReason("some-future-reason"))
	if !strings.Contains(d.label, "some-future-reason") || !strings.Contains(d.label, "no display mapping") {
		t.Errorf("unmapped reason label must name itself and the missing mapping, got %q", d.label)
	}

	empty := unscanDisplayFor("")
	if !strings.Contains(empty.label, "no reason recorded") {
		t.Errorf("empty reason must say no reason was recorded, got %q", empty.label)
	}
	if empty.label == string(vuldomain.StatusUnscannable) {
		t.Errorf("empty reason must not render as the bare status")
	}
}

// TestUnscannableRollup_SectionsAreStableAndComplete covers the roll-up: every
// reason present gets its own section, sections come out in AllUnscanReasons
// order regardless of the order records arrived in, and a reason outside that
// list is still printed rather than dropped.
func TestUnscannableRollup_SectionsAreStableAndComplete(t *testing.T) {
	r := newUnscannableRollup()
	r.add(vuldomain.UnscanReasonCHeadersMissing, "example.com/c@v1.0.0", "")
	// Two unlisted reasons, added out of order, so the tail's own ordering is
	// exercised rather than assumed.
	r.add(vuldomain.UnscanReason("zz-unknown-reason"), "example.com/z@v1.0.0", "")
	r.add(vuldomain.UnscanReason("aa-unknown-reason"), "example.com/u@v1.0.0", "")
	r.add(vuldomain.UnscanReasonVersionNotInToolchain, "example.com/a@v1.0.0", "")
	r.add(vuldomain.UnscanReasonPackageDeclarationsMissing, "example.com/p@v1.0.0", "")
	r.add(vuldomain.UnscanReasonVersionNotInToolchain, "example.com/b@v1.0.0", "")

	if r.total() != 6 {
		t.Errorf("total = %d, want 6", r.total())
	}

	sections := r.sections()
	if len(sections) != 5 {
		t.Fatalf("got %d sections, want 5 (one per distinct reason)", len(sections))
	}
	// AllUnscanReasons order: version-not-in-toolchain, then
	// package-declarations-missing, then c-headers-missing; the unlisted reasons
	// sort to the tail among themselves.
	wantHeadings := []string{
		unscanDisplayFor(vuldomain.UnscanReasonVersionNotInToolchain).heading,
		unscanDisplayFor(vuldomain.UnscanReasonPackageDeclarationsMissing).heading,
		unscanDisplayFor(vuldomain.UnscanReasonCHeadersMissing).heading,
		unscanDisplayFor(vuldomain.UnscanReason("aa-unknown-reason")).heading,
		unscanDisplayFor(vuldomain.UnscanReason("zz-unknown-reason")).heading,
	}
	for i, want := range wantHeadings {
		if sections[i].display.heading != want {
			t.Errorf("section %d heading = %q, want %q", i, sections[i].display.heading, want)
		}
	}
	if len(sections[0].coords) != 2 {
		t.Errorf("out-of-toolchain section holds %d coords, want 2", len(sections[0].coords))
	}
}

// TestWriteUnscannableRollup_EveryReasonAppears is the roll-up half of the
// defect: a record whose reason was not out-of-toolchain used to appear in no
// end-of-run summary at all, so its count was invisible without reading every
// progress line.
func TestWriteUnscannableRollup_EveryReasonAppears(t *testing.T) {
	r := newUnscannableRollup()
	r.add(vuldomain.UnscanReasonPackageDeclarationsMissing, "github.com/bytedance/sonic/loader@v0.1.1", "")
	r.add(vuldomain.UnscanReasonPackageDeclarationsMissing, "github.com/cloudwego/base64x@v0.1.4", "")
	r.add(vuldomain.UnscanReasonCHeadersMissing, "gopkg.in/mgo.v2@v2.0.0", "")
	r.add(vuldomain.UnscanReasonVersionNotInToolchain, "cel.dev/expr@v0.25.1", "")

	var out strings.Builder
	writeUnscannableRollup(r, &out)
	got := out.String()

	for _, want := range []string{
		"no buildable files for this toolchain (2):",
		"github.com/bytedance/sonic/loader@v0.1.1",
		"github.com/cloudwego/base64x@v0.1.4",
		"needs C headers absent on this host (1):",
		"gopkg.in/mgo.v2@v2.0.0",
		"version not in project build (1):",
		"cel.dev/expr@v0.25.1",
		reachabilityLocalHint,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("roll-up is missing %q; got:\n%s", want, got)
		}
	}
	// The direction belongs to one section only, which is why sections are
	// printed per reason rather than merged.
	if n := strings.Count(got, reachabilityLocalHint); n != 1 {
		t.Errorf("reachability direction appears %d times, want exactly 1; got:\n%s", n, got)
	}
}

// TestWriteUnscannableRollup_EmptyPrintsNothing keeps a clean run clean: no
// heading is printed when no module was Unscannable.
func TestWriteUnscannableRollup_EmptyPrintsNothing(t *testing.T) {
	var out strings.Builder
	writeUnscannableRollup(newUnscannableRollup(), &out)
	writeUnscannableRollup(nil, &out)
	if out.Len() != 0 {
		t.Errorf("empty roll-up wrote %q, want nothing", out.String())
	}
}

// TestPrintVulnScanResult_FailedModulesListedOnAffectedRun covers the failed
// half of the same roll-up defect. A run is Affected as soon as one module has
// findings, so gating the failed list on a Partial run hid every scan fault
// behind the first finding.
func TestPrintVulnScanResult_FailedModulesListedOnAffectedRun(t *testing.T) {
	run := vuldomain.WalkScanRun{ID: "01JSCANRUN0000000000000009", OverallStatus: vuldomain.WalkStatusAffected}

	var out strings.Builder
	if err := printVulnScanResult(run, nil, []string{"example.com/broken@v1.0.0"}, nil, false, &out); err != nil {
		t.Fatalf("printVulnScanResult: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Failed modules (1):") || !strings.Contains(got, "example.com/broken@v1.0.0") {
		t.Errorf("failed modules must be listed on an Affected run; got:\n%s", got)
	}
}
