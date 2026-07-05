package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

func TestNewSnapshot_VersionIDPrefix(t *testing.T) {
	s := domain.NewSnapshot(map[string][]byte{
		"/workspace/main.go": []byte("package main"),
	})
	if !strings.HasPrefix(s.VersionID, "local-") {
		t.Errorf("VersionID %q does not start with 'local-'", s.VersionID)
	}
}

func TestNewSnapshot_VersionIDLength(t *testing.T) {
	s := domain.NewSnapshot(map[string][]byte{
		"/workspace/main.go": []byte("package main"),
	})
	// "local-" (6) + 64 hex chars = 70 total
	const want = 70
	if len(s.VersionID) != want {
		t.Errorf("VersionID length = %d, want %d: %q", len(s.VersionID), want, s.VersionID)
	}
}

func TestNewSnapshot_Deterministic(t *testing.T) {
	files := map[string][]byte{
		"/workspace/main.go":   []byte("package main\nfunc main() {}"),
		"/workspace/go.mod":    []byte("module example.com/app\n\ngo 1.21"),
		"/workspace/util/a.go": []byte("package util"),
	}
	s1 := domain.NewSnapshot(files)
	s2 := domain.NewSnapshot(files)
	if s1.VersionID != s2.VersionID {
		t.Errorf("VersionID is not deterministic: %q vs %q", s1.VersionID, s2.VersionID)
	}
}

func TestNewSnapshot_DifferentContentDifferentID(t *testing.T) {
	a := domain.NewSnapshot(map[string][]byte{
		"/workspace/main.go": []byte("package main"),
	})
	b := domain.NewSnapshot(map[string][]byte{
		"/workspace/main.go": []byte("package main\n// changed"),
	})
	if a.VersionID == b.VersionID {
		t.Error("different file contents produced the same VersionID")
	}
}

func TestNewSnapshot_DifferentPathDifferentID(t *testing.T) {
	a := domain.NewSnapshot(map[string][]byte{
		"/workspace/a.go": []byte("package main"),
	})
	b := domain.NewSnapshot(map[string][]byte{
		"/workspace/b.go": []byte("package main"),
	})
	if a.VersionID == b.VersionID {
		t.Error("different file paths produced the same VersionID")
	}
}

func TestNewSnapshot_EmptyFiles(t *testing.T) {
	s := domain.NewSnapshot(map[string][]byte{})
	if !strings.HasPrefix(s.VersionID, "local-") {
		t.Errorf("empty snapshot VersionID %q does not start with 'local-'", s.VersionID)
	}
	if len(s.VersionID) != 70 {
		t.Errorf("empty snapshot VersionID length = %d, want 70", len(s.VersionID))
	}
}

func TestNewSnapshot_FilesMapIsRetained(t *testing.T) {
	input := map[string][]byte{
		"/workspace/main.go": []byte("package main"),
	}
	s := domain.NewSnapshot(input)
	if len(s.Files) != 1 {
		t.Errorf("Files map length = %d, want 1", len(s.Files))
	}
	if string(s.Files["/workspace/main.go"]) != "package main" {
		t.Errorf("Files[main.go] = %q, want %q", s.Files["/workspace/main.go"], "package main")
	}
}

func TestNewSnapshot_MapIterationOrderIndependent(t *testing.T) {
	// Build two snapshots with the same logical contents but constructed from
	// different map literals (Go maps have random iteration order).
	files1 := map[string][]byte{
		"/ws/a.go": []byte("a"),
		"/ws/b.go": []byte("b"),
		"/ws/c.go": []byte("c"),
	}
	files2 := map[string][]byte{
		"/ws/c.go": []byte("c"),
		"/ws/a.go": []byte("a"),
		"/ws/b.go": []byte("b"),
	}
	s1 := domain.NewSnapshot(files1)
	s2 := domain.NewSnapshot(files2)
	if s1.VersionID != s2.VersionID {
		t.Errorf("VersionID differs with different map insertion order: %q vs %q", s1.VersionID, s2.VersionID)
	}
}
