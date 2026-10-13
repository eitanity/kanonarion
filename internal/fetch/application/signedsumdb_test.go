package application_test

import (
	"context"
	"crypto/rand"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/sumdb/gosum"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"
)

// signedSumDB serves record from a checksum database this test signs and
// returns the production client pointed at it, so a fetch verifies against
// what the real adapter returns rather than what a fake was told to.
func signedSumDB(t *testing.T, record string) *gosum.Client {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, "test.sumdb")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	db := sumdb.NewTestServer(skey, func(string, string) ([]byte, error) { return []byte(record), nil })
	ts := httptest.NewServer(sumdb.NewServer(db))
	t.Cleanup(ts.Close)
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	for _, k := range []string{"GOPROXY", "GOPRIVATE", "GONOSUMCHECK", "GONOSUMDB"} {
		t.Setenv(k, "")
	}
	t.Setenv("GOSUMDB", ts.Listener.Addr().String()+" "+vkey)
	return gosum.New(t.TempDir())
}

// sumDBRecord is the database's record for testCoord: its zip line and its
// go.mod line.
func sumDBRecord(zipHash, goModHash domain2.ModuleHash) string {
	rec := testCoord.Path() + " " + testCoord.Version() + " " + zipHash.String() + "\n"
	if !goModHash.IsZero() {
		rec += testCoord.Path() + " " + testCoord.Version() + "/go.mod " + goModHash.String() + "\n"
	}
	return rec
}

func TestSignedSumDB_GoModOnlyFetchWithAMatchingGoModIsVerified(t *testing.T) {
	sdb := signedSumDB(t, sumDBRecord(fakeZipHash, fakeGoModHash))
	uc := newUseCaseWithSumDB(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts(), sdb)
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.VerificationStatus != string(domain2.VerifiedBySumDBOnly) {
		t.Errorf("status = %q (%s), want %q", res.Record.VerificationStatus, res.Record.VerificationDetail, domain2.VerifiedBySumDBOnly)
	}
}

func TestSignedSumDB_GoModOnlyFetchWithATamperedGoModIsAMismatch(t *testing.T) {
	recorded := fetchtest.H1("recordedgomod==")
	sdb := signedSumDB(t, sumDBRecord(fakeZipHash, recorded))
	uc := newUseCaseWithSumDB(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts(), sdb)
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertGoModMismatch(t, res.Record.VerificationStatus, res.Record.VerificationDetail, recorded)
}

// Control: a database with no go.mod line keeps the existing verdict.
func TestSignedSumDB_GoModOnlyFetchWithNoGoModLineKeepsTheNoHashVerdict(t *testing.T) {
	sdb := signedSumDB(t, sumDBRecord(fakeZipHash, domain2.ModuleHash{}))
	uc := newUseCaseWithSumDB(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts(), sdb)
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, GoModOnly: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Record.VerificationStatus != string(domain2.UnverifiedNoSumDB) ||
		!strings.Contains(res.Record.VerificationDetail, "returned no go.mod hash") {
		t.Errorf("status = %q (%s), want %q naming the absent go.mod hash",
			res.Record.VerificationStatus, res.Record.VerificationDetail, domain2.UnverifiedNoSumDB)
	}
}

func TestSignedSumDB_FullFetchWithATamperedGoModIsAMismatch(t *testing.T) {
	recorded := fetchtest.H1("recordedgomod==")
	sdb := signedSumDB(t, sumDBRecord(fakeZipHash, recorded))
	uc := newUseCaseWithSumDB(fullFetchProxy(), &fakeVCS{}, newFakeBlob(), newFakeFacts(), sdb)
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertGoModMismatch(t, res.Record.VerificationStatus, res.Record.VerificationDetail, recorded)
}

// Control: the same full fetch with the database's go.mod hash matching is not
// a mismatch, so the tampered case above fails on the go.mod alone.
func TestSignedSumDB_FullFetchWithAMatchingGoModIsNotAMismatch(t *testing.T) {
	sdb := signedSumDB(t, sumDBRecord(fakeZipHash, fakeGoModHash))
	uc := newUseCaseWithSumDB(fullFetchProxy(), &fakeVCS{}, newFakeBlob(), newFakeFacts(), sdb)
	res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	t.Logf("status %s: %s", res.Record.VerificationStatus, res.Record.VerificationDetail)
	if res.Record.VerificationStatus == string(domain2.UnverifiedHashMismatch) {
		t.Errorf("status = %q (%s), want no mismatch", res.Record.VerificationStatus, res.Record.VerificationDetail)
	}
}

// fullFetchProxy serves testCoord with a zip whose go.mod agrees with the
// standalone go.mod, so no content check fires before the database is asked.
func fullFetchProxy() *fakeProxy {
	goMod := "module " + testCoord.Path() + "\n"
	return &fakeProxy{downloads: map[string]fakeDownload{testCoord.String(): {
		zipData:   string(buildZip(map[string]string{testCoord.String() + "/go.mod": goMod})),
		goModData: goMod,
		zipHash:   fakeZipHash,
		goModHash: fakeGoModHash,
	}}}
}

func assertGoModMismatch(t *testing.T, status, detail string, recorded domain2.ModuleHash) {
	t.Helper()
	if status != string(domain2.UnverifiedHashMismatch) {
		t.Errorf("status = %q (%s), want %q", status, detail, domain2.UnverifiedHashMismatch)
	}
	if !strings.Contains(detail, recorded.String()) || !strings.Contains(detail, fakeGoModHash.String()) {
		t.Errorf("detail = %q, want it to name the database's go.mod hash %s and the computed %s",
			detail, recorded, fakeGoModHash)
	}
}
