package domain_test

import (
	"encoding/json"
	"strings"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The directory the VCS leg hashed reaches the record, is covered by its seal,
// survives a round trip, and is absent from the canonical bytes when empty, so a
// record written before the field existed keeps its content hash.
func TestGitSubdir_RecordedSealedAndHashTransparent(t *testing.T) {
	t.Parallel()

	r := domain2.NewFactRecord(domain2.FetchedModule{GitReference: domain2.GitReference{Subdir: "client/v3"}})
	if r.GitSubdir != "client/v3" {
		t.Fatalf("GitSubdir = %q, want client/v3", r.GitSubdir)
	}

	h := domain2.CanonicalHasher{}
	withDir := sampleRecord()
	withDir.GitSubdir = "service/s3"
	sealed, err := h.SetContentHash(withDir)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	moved := sealed
	moved.GitSubdir = "service/ec2"
	if h.VerifyContentHash(moved) == nil {
		t.Error("rewriting git_subdir left the content hash valid")
	}
	data, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.GitSubdir != "service/s3" || h.VerifyContentHash(back) != nil {
		t.Errorf("round trip lost git_subdir or its seal: %q", back.GitSubdir)
	}

	// The hash a build without the field computed for sampleRecord().
	const preFieldHash = "sha256:665d38c6fa170026fc7a338dff9aa0baba534f3b73001e1d2b3fc08b0859525f"
	plain, err := h.SetContentHash(sampleRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if plain.ContentHash != preFieldHash {
		t.Errorf("ContentHash = %q, want the pre-field %q", plain.ContentHash, preFieldHash)
	}
	plainBytes, err := h.Marshal(plain)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(plainBytes), "git_subdir") {
		t.Errorf("canonical JSON carries git_subdir when unset: %s", plainBytes)
	}
}

// fetch --json always carries git_subdir: null where the record names no
// directory (a pre-field record among them), "." for the root, else the
// directory. A root record seals ".", so it is never read as "none".
func TestGitSubdir_RecordJSONSaysNullRootOrDirectory(t *testing.T) {
	t.Parallel()

	for subdir, want := range map[domain2.RepoSubdir]string{
		"":               `"git_subdir":null`,
		domain2.RepoRoot: `"git_subdir":"."`,
		"v3":             `"git_subdir":"v3"`,
	} {
		data, err := json.Marshal(domain2.CompositeRecord{FactRecord: domain2.FactRecord{GitSubdir: subdir}})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(data), want) {
			t.Errorf("git_subdir %q renders as %s, want %s", subdir, data, want)
		}
	}

	h := domain2.CanonicalHasher{}
	root := sampleRecord()
	root.GitSubdir = domain2.RepoRoot
	sealed, err := h.SetContentHash(root)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	canonical, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(canonical), `"git_subdir":"."`) {
		t.Errorf("a root record does not seal \".\": %s", canonical)
	}
}

func TestValidateOriginSubdir(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"", "client", "service/s3", "a/b/c/d/e"} {
		if err := domain2.ValidateOriginSubdir(ok); err != nil {
			t.Errorf("ValidateOriginSubdir(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{"/abs", "..", "../x", "a/../../b", `a\b`, "a\x00b", "./a", "a/", "a//b"} {
		if err := domain2.ValidateOriginSubdir(bad); err == nil {
			t.Errorf("ValidateOriginSubdir(%q) accepted, want refused", bad)
		}
	}
}
