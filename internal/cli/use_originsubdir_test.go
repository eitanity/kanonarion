package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The .info use writes carries Origin.Subdir as the go command writes it: the
// code directory, without a major-version subdirectory the go command selected,
// and nothing at all where the record names no directory.
func TestWriteDerivedModCacheFiles_OriginSubdir(t *testing.T) {
	cases := []struct {
		name, path, version string
		gitSubdir           fetchdomain.RepoSubdir
		want                *string
	}{
		{"root", "github.com/google/uuid", "v1.6.0", fetchdomain.RepoRoot, nil},
		{"depth 2", "cloud.google.com/go/compute/metadata", "v0.9.0", "compute/metadata", ptr("compute/metadata")},
		{"code directory major subdirectory", "go.etcd.io/etcd/client/v3", "v3.6.14", "client/v3", ptr("client")},
		{"root major subdirectory", "modernc.org/gc/v3", "v3.1.4", "v3", nil},
		{"record before the field", "go.etcd.io/etcd/client/v3", "v3.6.14", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			coord := coordinatetest.MustNew(tc.path, tc.version)
			rec := fetchdomain.CompositeRecord{FactRecord: fetchdomain.FactRecord{
				GitURL: "https://example.com/repo", GitRef: "refs/tags/x", GitCommitHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				GitSubdir: tc.gitSubdir}}
			if err = writeDerivedModCacheFiles(root, rec, coord, "."); err != nil {
				t.Fatalf("writeDerivedModCacheFiles: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(dir, tc.version+".info"))
			if err != nil {
				t.Fatal(err)
			}
			var info struct{ Origin map[string]any }
			if err = json.Unmarshal(data, &info); err != nil {
				t.Fatal(err)
			}
			got, present := info.Origin["Subdir"]
			switch {
			case tc.want == nil && present:
				t.Errorf("Origin.Subdir = %v, want none: %s", got, data)
			case tc.want != nil && got != *tc.want:
				t.Errorf("Origin.Subdir = %v, want %q: %s", got, *tc.want, data)
			}
		})
	}
}

func ptr(s string) *string { return &s }
