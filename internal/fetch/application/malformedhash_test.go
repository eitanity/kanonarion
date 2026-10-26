package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/fetch/application"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"
)

// malformedGoModHash is a go.mod hash that does not parse on a record whose zip
// hash does, so the record composes and the identity derivation is what refuses.
const malformedGoModHash = "h1:"

// seedMalformedGoModRecord stores a cache-eligible record for testCoord whose
// go.mod hash does not parse, with its zip held, and returns a use case logging
// JSON at debug into the returned buffer.
func seedMalformedGoModRecord(t *testing.T) (*application.FetchModuleUseCase, *fakeProxy, *bytes.Buffer) {
	t.Helper()
	blobs, facts := newFakeBlob(), newFakeFacts()
	seeded := fetchtest.Record(t,
		fetchtest.Coordinate(testCoord),
		fetchtest.ModuleHash(fetchtest.H1("seed==")),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(fixedTime),
		fetchtest.PipelineVersion("test-0.1.0"),
		fetchtest.Content("held-zip"),
		func(r *domain2.FactRecord) { r.GoModHash = malformedGoModHash },
	)
	if err := blobs.Put(context.Background(), fetchtest.ZipIdentity(t, seeded), strings.NewReader("held zip")); err != nil {
		t.Fatalf("seed zip: %v", err)
	}
	if err := facts.PutFetchRecord(context.Background(), mustSealRecord(t, seeded)); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxy := newProxyWithOrigin()
	uc := application.NewFetchModuleUseCase(proxy, &fakeVCS{checkoutErr: errors.New("no checkout in test")},
		blobs, facts, availableSumDB(fetchtest.H1("fakehash==")), fixedClock{fixedTime}, fakeStopwatch{}, "test-0.1.0", log)
	return uc, proxy, &buf
}

// warnLines returns the JSON log lines at WARN whose message is msg.
func warnLines(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for raw := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var l map[string]any
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("log line %q: %v", raw, err)
		}
		if l["level"] == "WARN" && l["msg"] == msg {
			out = append(out, l)
		}
	}
	return out
}

// assertNamesTheModuleAndHash checks there is a warn line and each carries the
// coordinate and the parse error. The cache check runs again before a weaker
// write is refused, so one run can state it twice.
func assertNamesTheModuleAndHash(t *testing.T, lines []map[string]any, buf *bytes.Buffer) {
	t.Helper()
	if len(lines) == 0 {
		t.Fatalf("no warn line; logs:\n%s", buf)
	}
	for _, l := range lines {
		if l["module_path"] != testCoord.Path() || l["module_version"] != testCoord.Version() {
			t.Errorf("warn names module %v@%v, want %s", l["module_path"], l["module_version"], testCoord)
		}
		if e := fmt.Sprint(l["error"]); !strings.Contains(e, `"`+malformedGoModHash+`"`) {
			t.Errorf("warn error = %q, want the parse error naming %q", e, malformedGoModHash)
		}
	}
}

// A forced run over a record whose hash does not parse states it at warn, then
// re-acquires as before.
func TestForcedRun_AStoredHashThatDoesNotParseIsStatedThenReacquired(t *testing.T) {
	uc, proxy, buf := seedMalformedGoModRecord(t)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache || proxy.zipDownloads != 1 {
		t.Errorf("FromCache = %v, zip downloads = %d; want one re-acquisition", res.FromCache, proxy.zipDownloads)
	}
	assertNamesTheModuleAndHash(t, warnLines(t, buf, "stored fact record carries a hash that does not parse; re-acquiring"), buf)
}

// An unforced run's cache check over the same record states it at warn, then
// re-fetches as before.
func TestCacheCheck_AStoredHashThatDoesNotParseIsStatedThenRefetched(t *testing.T) {
	uc, proxy, buf := seedMalformedGoModRecord(t)

	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache || proxy.zipDownloads != 1 {
		t.Errorf("FromCache = %v, zip downloads = %d; want one re-fetch", res.FromCache, proxy.zipDownloads)
	}
	assertNamesTheModuleAndHash(t, warnLines(t, buf, "cache_reverify_identity_underivable"), buf)
}
