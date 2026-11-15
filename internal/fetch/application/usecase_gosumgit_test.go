package application_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/ziparchive"
	"code.eitanity.com/kanonarion/internal/fetch/application"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// treeVCS checks out a one-file module tree for testCoord.
type treeVCS struct{ fakeVCS }

func (v *treeVCS) CheckoutToDir(_ context.Context, _, _, dir string) error {
	for name, body := range map[string]string{"go.mod": "module " + testCoord.Path() + "\n", "mux.go": "package mux\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	return nil
}

// treeHash is the h1 the git leg computes for treeVCS's checkout.
func treeHash(t *testing.T) domain2.ModuleHash {
	t.Helper()
	dir := t.TempDir()
	if err := (&treeVCS{}).CheckoutToDir(context.Background(), "", "", dir); err != nil {
		t.Fatal(err)
	}
	h, err := domain2.NewVerifier(ziparchive.Hasher{}).HashDirAsModuleZip(dir, testCoord)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// With the checksum database unable to answer, git is the only check
// independent of the project go.sum: its mismatch outranks the go.sum match.
// A database-verified zip keeps the weaker reading of a git mismatch.
func TestExecute_ProjectGoSum_GitMismatchOutranksTheGoSumMatch(t *testing.T) {
	matching := treeHash(t)
	for _, tc := range []struct {
		name    string
		zipHash domain2.ModuleHash
		sumdb   ports.SumDBClient
		skipVCS bool
		want    domain2.VerificationStatus
		detail  []string
	}{
		{"git mismatch", fakeZipHash, disabledSumDB(), false, domain2.UnverifiedHashMismatch,
			[]string{"verified against local go.sum", "does not match git checkout hash"}},
		{"git match", matching, disabledSumDB(), false, domain2.VerifiedByGoSum, nil},
		{"git skipped", fakeZipHash, disabledSumDB(), true, domain2.VerifiedByGoSum, nil},
		{"database verified, git mismatch", fakeZipHash, availableSumDB(fakeZipHash), false, domain2.VerifiedBySumDBOnly, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := &fakeProxy{downloads: map[string]fakeDownload{testCoord.String(): {
				zipData: "fake-zip", goModData: "module " + testCoord.Path(), zipHash: tc.zipHash, goModHash: fakeGoModHash,
			}}}
			uc := newUseCaseWithSumDB(proxy, &treeVCS{}, newFakeBlob(), newFakeFacts(), tc.sumdb).
				WithProjectGoSum(&fakeSumDB{result: ports.SumDBResult{Available: true, ZipHash: tc.zipHash}})
			res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord, SkipVCSVerify: tc.skipVCS})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if res.Record.VerificationStatus != string(tc.want) {
				t.Errorf("VerificationStatus = %q, want %q (detail %q)", res.Record.VerificationStatus, tc.want, res.Record.VerificationDetail)
			}
			for _, d := range tc.detail {
				if !strings.Contains(res.Record.VerificationDetail, d) {
					t.Errorf("detail %q does not name %q", res.Record.VerificationDetail, d)
				}
			}
		})
	}
}
