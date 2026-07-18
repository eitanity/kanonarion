package domain_test

import (
	"testing"
	"testing/fstest"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

func TestSourceManifest_OrderIndependent(t *testing.T) {
	a := fstest.MapFS{
		"fmt/print.go":    {Data: []byte("package fmt\n")},
		"runtime/proc.go": {Data: []byte("package runtime\n")},
	}
	// Same content, different insertion order (map iteration is random anyway,
	// but the manifest must sort so the bytes are identical).
	b := fstest.MapFS{
		"runtime/proc.go": {Data: []byte("package runtime\n")},
		"fmt/print.go":    {Data: []byte("package fmt\n")},
	}

	ma, err := domain.SourceManifest(a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := domain.SourceManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ma) != string(mb) {
		t.Errorf("manifest not order-independent:\n%s\nvs\n%s", ma, mb)
	}
}

func TestSourceManifest_ContentSensitive(t *testing.T) {
	base := fstest.MapFS{"fmt/print.go": {Data: []byte("package fmt\n")}}
	changed := fstest.MapFS{"fmt/print.go": {Data: []byte("package fmt // edit\n")}}

	mb, err := domain.SourceManifest(base)
	if err != nil {
		t.Fatal(err)
	}
	mc, err := domain.SourceManifest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if string(mb) == string(mc) {
		t.Error("manifest should change when file content changes")
	}
}

func TestComputeSourceDigests_NonZeroAndStable(t *testing.T) {
	fsys := fstest.MapFS{
		"fmt/print.go":    {Data: []byte("package fmt\n")},
		"runtime/proc.go": {Data: []byte("package runtime\n")},
	}
	d1, err := domain.ComputeSourceDigests(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if d1.IsZero() {
		t.Fatal("digests should not be zero for a populated tree")
	}
	d2, err := domain.ComputeSourceDigests(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Errorf("digests unstable: %+v vs %+v", d1, d2)
	}
}

func TestSourceManifest_SkipsDirectories(t *testing.T) {
	fsys := fstest.MapFS{
		"pkg/a.go":     {Data: []byte("a")},
		"pkg/sub/b.go": {Data: []byte("b")},
	}
	m, err := domain.SourceManifest(fsys)
	if err != nil {
		t.Fatal(err)
	}
	// Two regular files → exactly two manifest lines, no directory entries.
	lines := 0
	for _, c := range m {
		if c == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("manifest has %d lines, want 2 (regular files only)", lines)
	}
}
