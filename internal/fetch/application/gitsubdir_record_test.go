package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/fetch/application"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// subdirCheckoutVCS checks out a repository holding one module at sub/, and a
// root go.mod for github.com/acme/repo.
type subdirCheckoutVCS struct{ fakeVCS }

func (v *subdirCheckoutVCS) CheckoutToDir(_ context.Context, _, _, dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/acme/repo\n"), 0o600); err != nil {
		return fmt.Errorf("writing go.mod: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		return fmt.Errorf("creating sub: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "go.mod"), []byte("module github.com/acme/repo/sub\n"), 0o600); err != nil {
		return fmt.Errorf("writing sub/go.mod: %w", err)
	}
	return nil
}

// The directory the VCS leg hashed reaches the persisted record, and a later
// run that inherits the leg carries the directory with it.
func TestRecordNamesTheDirectoryHashed_AndInheritsIt(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/acme/repo/sub", "v1.0.0")
	proxy := &fakeProxy{infos: map[string]ports.ModuleInfo{coord.String(): {
		Version: "v1.0.0", Time: fixedTime,
		Origin: &ports.ModuleOrigin{VCS: "git", URL: "https://github.com/acme/repo",
			Ref: "refs/tags/sub/v1.0.0", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Subdir: "sub"},
	}}}
	uc := newUseCase(proxy, &subdirCheckoutVCS{}, newFakeBlob(), newFakeFacts())
	ctx := context.Background()

	first, err := uc.Execute(ctx, application.FetchRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	if first.Record.GitSubdir != "sub" {
		t.Fatalf("first record git_subdir = %q (detail %q), want sub", first.Record.GitSubdir, first.Record.VerificationDetail)
	}

	second, err := uc.Execute(ctx, application.FetchRequest{Coordinate: coord, SkipVCSVerify: true, Force: true})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if domain2.LegProvenance(second.Record.VCSCheck) != domain2.LegInherited {
		t.Fatalf("second run VCS leg = %q, want inherited", second.Record.VCSCheck)
	}
	if second.Record.GitSubdir != "sub" {
		t.Errorf("inherited leg names directory %q, want the source record's sub", second.Record.GitSubdir)
	}
}

// The record says which directory was hashed in all three cases the field
// distinguishes: a subdirectory, the root ("."), and none at all, where the
// leg stopped before a directory was selected. fetch --json prints that last
// one as null, never as a directory.
func TestRecordGitSubdir_RootSubdirAndNone(t *testing.T) {
	origin := func(subdir, ref string) *ports.ModuleOrigin {
		return &ports.ModuleOrigin{VCS: "git", URL: "https://github.com/acme/repo",
			Ref: ref, Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Subdir: subdir}
	}
	cases := []struct {
		coord  string
		origin *ports.ModuleOrigin
		want   string
		json   string
	}{
		{"github.com/acme/repo/sub@v1.0.0", origin("sub", "refs/tags/sub/v1.0.0"), "sub", `"git_subdir":"sub"`},
		{"github.com/acme/repo@v1.0.0", origin("", "refs/tags/v1.0.0"), domain2.RepoRoot, `"git_subdir":"."`},
		{"github.com/acme/repo/missing@v1.0.0", origin("missing", "refs/tags/missing/v1.0.0"), "", `"git_subdir":null`},
	}
	for _, tc := range cases {
		t.Run(tc.coord, func(t *testing.T) {
			path, version, _ := strings.Cut(tc.coord, "@")
			coord := coordinatetest.MustNew(path, version)
			proxy := &fakeProxy{infos: map[string]ports.ModuleInfo{coord.String(): {
				Version: version, Time: fixedTime, Origin: tc.origin}}}
			uc := newUseCase(proxy, &subdirCheckoutVCS{}, newFakeBlob(), newFakeFacts())
			res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: coord})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if string(res.Record.GitSubdir) != tc.want {
				t.Errorf("git_subdir = %q (detail %q), want %q", res.Record.GitSubdir, res.Record.VerificationDetail, tc.want)
			}
			data, err := json.Marshal(res.Record)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !strings.Contains(string(data), tc.json) {
				t.Errorf("record JSON lacks %s: %s", tc.json, data)
			}
		})
	}
}
