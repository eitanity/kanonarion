package yaml

import (
	"context"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestStore_LoadOverrides(t *testing.T) {
	s := New(map[string]string{
		"golang.org/x/mod":          "MIT",
		"github.com/old/pkg@v1.2.3": "BSD-2-Clause",
	})
	set, err := s.LoadOverrides(context.Background())
	if err != nil {
		t.Fatalf("LoadOverrides: %v", err)
	}
	ov, ok := set.Resolve(fetchdomain.ModuleCoordinate{Path: "golang.org/x/mod", Version: "v0.36.0"})
	if !ok || ov.SPDX != "MIT" {
		t.Fatalf("got %+v ok=%v, want MIT", ov, ok)
	}
}

func TestStore_EmptyNeverOverrides(t *testing.T) {
	set, err := New(nil).LoadOverrides(context.Background())
	if err != nil {
		t.Fatalf("LoadOverrides: %v", err)
	}
	if _, ok := set.Resolve(fetchdomain.ModuleCoordinate{Path: "x", Version: "v1"}); ok {
		t.Fatal("empty store must never override")
	}
}
