package osv_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// toolchainSnapshotZip is a stored snapshot shaped like the published one: an
// index listing the toolchain key beside a module key, and one ID record per
// listed advisory. The checksum-bypass record carries the real two-branch range
// — fixed 1.25.10 on the 1.25 line, 1.26.3 on the 1.26 line — because that is
// the shape the index's single collapsed "fixed" field cannot express.
func toolchainSnapshotZip(t *testing.T) []byte {
	t.Helper()
	return buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2026-07-27T20:14:16Z"}`)},
		{name: "index/modules.json", content: []byte(`[
			{"path":"example.com/mod","vulns":[{"id":"GO-2026-0001","modified":"2026-01-01T00:00:00Z","fixed":"1.2.0"}]},
			{"path":"toolchain","vulns":[
				{"id":"GO-2026-4984","modified":"2026-05-07T19:21:40Z","fixed":"1.26.3"},
				{"id":"GO-2026-4923","modified":"2026-04-08T00:00:00Z","fixed":"1.26.0"}
			]}
		]`)},
		{name: "ID/GO-2026-0001.json", content: []byte(`{"id":"GO-2026-0001"}`)},
		{name: "ID/GO-2026-4984.json", content: []byte(`{
			"id":"GO-2026-4984",
			"summary":"Malicious module proxy can bypass checksum database in cmd/go",
			"affected":[{"package":{"name":"toolchain","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[
				{"introduced":"0"},{"fixed":"1.25.10"},{"introduced":"1.26.0-0"},{"fixed":"1.26.3"}]}]}]
		}`)},
		{name: "ID/GO-2026-4923.json", content: []byte(`{
			"id":"GO-2026-4923",
			"summary":"WITHDRAWN: out-of-range index",
			"withdrawn":"2026-04-08T00:00:00Z",
			"affected":[{"package":{"name":"toolchain","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[
				{"introduced":"0"},{"fixed":"1.26.0"}]}]}]
		}`)},
	})
}

// TestSnapshotToolchainAdvisories_ReadsRangesAndRetractionsFromTheStoredBody:
// the index states one collapsed fixed version per advisory, which cannot
// express a backport and says nothing about a retraction. Both are in the
// snapshot's own ID records, and both are read from there — over a nil HTTP
// client, so a read that reached the network could not have completed at all.
func TestSnapshotToolchainAdvisories_ReadsRangesAndRetractionsFromTheStoredBody(t *testing.T) {
	db := osv.New(nil, &fakeVulnStore{content: string(toolchainSnapshotZip(t))}, testClock)

	set, err := db.SnapshotToolchainAdvisories(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"))
	if err != nil {
		t.Fatalf("SnapshotToolchainAdvisories: %v", err)
	}
	if !set.KeyPresent {
		t.Fatal("the snapshot lists a toolchain key and the read reported it absent")
	}
	if len(set.Advisories) != 2 {
		t.Fatalf("advisories = %+v, want the two the index lists", set.Advisories)
	}

	byID := map[string]domain.ToolchainAdvisory{}
	for _, a := range set.Advisories {
		byID[a.ID] = a
	}

	bypass := byID["GO-2026-4984"]
	want := []domain.ToolchainRange{{Introduced: "0", Fixed: "1.25.10"}, {Introduced: "1.26.0-0", Fixed: "1.26.3"}}
	if len(bypass.Ranges) != len(want) {
		t.Fatalf("ranges = %+v, want both branches: %+v", bypass.Ranges, want)
	}
	for i, r := range want {
		if bypass.Ranges[i] != r {
			t.Errorf("range %d = %+v, want %+v", i, bypass.Ranges[i], r)
		}
	}
	if bypass.IsWithdrawn() {
		t.Error("a live advisory was read as withdrawn")
	}
	if !byID["GO-2026-4923"].IsWithdrawn() {
		t.Error("the retraction stamp in the stored record was not read")
	}
}

// The whole point of the read is that it judges the key rather than the stdlib
// node: a module block naming some other package must contribute no range, or
// an unrelated advisory would cover a toolchain version.
func TestSnapshotToolchainAdvisories_IgnoresBlocksNamingAnotherPackage(t *testing.T) {
	zipBody := buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2026-07-27T20:14:16Z"}`)},
		{name: "index/modules.json", content: []byte(`[{"path":"toolchain","vulns":[{"id":"GO-2026-4984"}]}]`)},
		{name: "ID/GO-2026-4984.json", content: []byte(`{
			"id":"GO-2026-4984",
			"affected":[{"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[
				{"introduced":"0"},{"fixed":"1.99.0"}]}]}]
		}`)},
	})
	db := osv.New(nil, &fakeVulnStore{content: string(zipBody)}, testClock)

	set, err := db.SnapshotToolchainAdvisories(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"))
	if err != nil {
		t.Fatalf("SnapshotToolchainAdvisories: %v", err)
	}
	if len(set.Advisories) != 1 || len(set.Advisories[0].Ranges) != 0 {
		t.Fatalf("advisories = %+v, want the id kept with no toolchain range", set.Advisories)
	}
	j := domain.JudgeToolchain("go1.26.5", vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"), set)
	if j.Status != domain.ToolchainClear {
		t.Errorf("status = %q: a stdlib-only block covered a toolchain version", j.Status)
	}
}

// TestSnapshotToolchainAdvisories_ASnapshotWithoutTheKeyIsNotAnError: an older
// generation that never listed the key is a database that cannot judge a
// toolchain. That is an answer — reported as KeyPresent false — and the caller
// turns it into a stated "could not be judged" rather than a silent clear.
func TestSnapshotToolchainAdvisories_ASnapshotWithoutTheKeyIsNotAnError(t *testing.T) {
	zipBody := buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2026-07-27T20:14:16Z"}`)},
		{name: "index/modules.json", content: []byte(`[{"path":"example.com/mod","vulns":[{"id":"GO-2026-0001"}]}]`)},
	})
	db := osv.New(nil, &fakeVulnStore{content: string(zipBody)}, testClock)

	set, err := db.SnapshotToolchainAdvisories(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"))
	if err != nil {
		t.Fatalf("a snapshot without the toolchain key was refused: %v", err)
	}
	if set.KeyPresent || len(set.Advisories) != 0 {
		t.Fatalf("set = %+v, want the key reported absent", set)
	}
}

// An index entry naming an advisory whose record is missing is refused. Keeping
// the id with no range would make it cover every version, and dropping it would
// delete an advisory the database listed; neither is evidence, so the snapshot
// is reported unusable for this judgment.
func TestSnapshotToolchainAdvisories_RefusesAListedAdvisoryWithNoRecord(t *testing.T) {
	zipBody := buildVulnDBZip(t, []zipEntry{
		{name: "index/db.json", content: []byte(`{"modified":"2026-07-27T20:14:16Z"}`)},
		{name: "index/modules.json", content: []byte(`[{"path":"toolchain","vulns":[{"id":"GO-2026-4984"}]}]`)},
	})
	db := osv.New(nil, &fakeVulnStore{content: string(zipBody)}, testClock)

	_, err := db.SnapshotToolchainAdvisories(t.Context(), vulntest.MustNew("vuln.go.dev", "2026-07-27T20:14:16Z"))
	if err == nil {
		t.Fatal("a listed advisory with no stored record was accepted")
	}
}
