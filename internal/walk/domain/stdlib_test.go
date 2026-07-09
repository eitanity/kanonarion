package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestNormaliseStdlibVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"go env GOVERSION form", "go1.26.4", "v1.26.4"},
		{"toolchain directive form", "go1.26.4", "v1.26.4"},
		{"go directive minimum", "1.26", "v1.26"},
		{"already v-prefixed", "v1.26.4", "v1.26.4"},
		{"surrounding whitespace", "  go1.26.4\n", "v1.26.4"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.NormaliseStdlibVersion(tc.in); got != tc.want {
				t.Errorf("NormaliseStdlibVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStdlibNode(t *testing.T) {
	node, ok := domain.StdlibNode("go1.26.4")
	if !ok {
		t.Fatalf("StdlibNode(go1.26.4): ok = false, want true")
	}
	if node.Coordinate.Path != domain.StdlibModulePath {
		t.Errorf("path = %q, want %q", node.Coordinate.Path, domain.StdlibModulePath)
	}
	if node.Coordinate.Version != "v1.26.4" {
		t.Errorf("version = %q, want v1.26.4", node.Coordinate.Version)
	}
	if node.ResolutionSource != domain.ResolutionStdlib {
		t.Errorf("source = %q, want stdlib", node.ResolutionSource)
	}
	if !node.DirectDependency {
		t.Errorf("stdlib node should be a direct dependency of the project root")
	}
}

func TestStdlibNode_UndeterminableVersion(t *testing.T) {
	if _, ok := domain.StdlibNode(""); ok {
		t.Errorf("StdlibNode(\"\"): ok = true, want false (no version → no node)")
	}
}

func TestBuildEnv_IsZero(t *testing.T) {
	if !(domain.BuildEnv{}).IsZero() {
		t.Errorf("empty BuildEnv should report IsZero")
	}
	if (domain.BuildEnv{GOOS: "linux"}).IsZero() {
		t.Errorf("BuildEnv with a field set should not report IsZero")
	}
}
