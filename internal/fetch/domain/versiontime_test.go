package domain_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
)

// A 0.6.0 record written before version_time existed, as that build sealed it.
const preVersionTimeRecord = `{"acquisition_mode":"proxy","content_hash":"sha256:ce83d1fa05f767444d7c18c144ccf7ff0e910a369790575d35f8e484dc69c04b","content_location":"sha256:deadbeef","ecosystem":"go","fetched_at":"2026-10-01T12:00:00Z","git_commit_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","git_ref":"refs/tags/compute/metadata/v0.9.0","git_subdir":"compute/metadata","git_url":"https://github.com/googleapis/google-cloud-go","go_mod_hash":"h1:def=","measurement_kind":"acquired","module_hash":"h1:abc=","module_path":"cloud.google.com/go/compute/metadata","module_version":"v0.9.0","pipeline_version":"0.6.0","retracted":false,"schema_version":"4","sumdb_check":"rechecked","vcs_check":"rechecked","vcs_url_binding":"proxy_named","verification_detail":"","verification_status":"Verified"}`

// A record from before the field still verifies, re-marshals to the same bytes
// and reads its version time as unknown.
func TestVersionTime_PreFieldRecordIsHashTransparent(t *testing.T) {
	t.Parallel()
	h := domain2.CanonicalHasher{}
	r, err := h.Unmarshal([]byte(preVersionTimeRecord))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err = h.VerifyContentHash(r); err != nil {
		t.Fatalf("pre-field record no longer verifies: %v", err)
	}
	if r.VersionTime != "" {
		t.Errorf("VersionTime = %q, want unknown", r.VersionTime)
	}
	back, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(back) != preVersionTimeRecord {
		t.Errorf("canonical bytes moved:\n got %s\nwant %s", back, preVersionTimeRecord)
	}
}

// The version time reaches the record from the measurement, is covered by its
// seal and survives a canonical round trip.
func TestVersionTime_RecordedSealedAndRoundTripped(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 8, 18, 29, 55, 123000000, time.FixedZone("CEST", 2*3600))
	r := domain2.NewFactRecord(domain2.FetchedModule{
		Coordinate:  coordinatetest.MustNew("golang.org/x/text", "v0.42.0"),
		VersionTime: at,
	})
	if r.VersionTime != "2026-09-08T16:29:55.123Z" {
		t.Fatalf("VersionTime = %q, want the UTC instant with its precision", r.VersionTime)
	}
	if got := domain2.NewFactRecord(domain2.FetchedModule{}).VersionTime; got != "" {
		t.Errorf("a source with no time recorded %q, want unknown", got)
	}

	h := domain2.CanonicalHasher{}
	rec := sampleRecord()
	rec.VersionTime = r.VersionTime
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	moved := sealed
	moved.VersionTime = "2026-09-20T21:11:10Z"
	if h.VerifyContentHash(moved) == nil {
		t.Error("rewriting version_time left the content hash valid")
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"version_time":"2026-09-08T16:29:55.123Z","zip_sha256"`) &&
		!strings.HasSuffix(string(data), `"version_time":"2026-09-08T16:29:55.123Z"}`) {
		t.Errorf("version_time is not in key order: %s", data)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.VersionTime != r.VersionTime || h.VerifyContentHash(back) != nil {
		t.Errorf("round trip lost version_time or its seal: %q", back.VersionTime)
	}
}

func TestParseVersionTime(t *testing.T) {
	t.Parallel()
	if _, ok, err := domain2.ParseVersionTime(""); ok || err != nil {
		t.Errorf("unknown = (%v, %v), want not ok and no error", ok, err)
	}
	got, ok, err := domain2.ParseVersionTime("2026-09-08T16:29:55Z")
	if !ok || err != nil || !got.Equal(time.Date(2026, 9, 8, 16, 29, 55, 0, time.UTC)) {
		t.Errorf("Time() = (%v, %v, %v)", got, ok, err)
	}
	if _, ok, err := domain2.ParseVersionTime("yesterday"); ok || err == nil || !strings.Contains(err.Error(), `"yesterday"`) {
		t.Errorf("an unparseable value = (%v, %v), want the value named", ok, err)
	}
}

// fetch --json always carries version_time: null where it is unknown.
func TestVersionTime_RecordJSONSaysNullOrTime(t *testing.T) {
	t.Parallel()
	for v, want := range map[domain2.VersionTime]string{
		"":                     `"version_time":null`,
		"2026-09-08T16:29:55Z": `"version_time":"2026-09-08T16:29:55Z"`,
	} {
		data, err := json.Marshal(domain2.CompositeRecord{FactRecord: domain2.FactRecord{VersionTime: v}})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("version_time %q renders as %s, want %s", v, data, want)
		}
	}
}
