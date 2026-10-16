package gotoolchain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

func TestIgnoredDir(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		dir, file bool
	}{
		{"_examples", true, true},
		{".hidden", true, true},
		{"_x.go", true, true},
		{".x.go", true, true},
		{"testdata", true, false},
		{"vendor", false, false},
		{"pkg", false, false},
		{"x_test.go", false, false},
		{"a_b", false, false},
	} {
		if got := gotoolchain.IgnoredDir(tc.name); got != tc.dir {
			t.Errorf("IgnoredDir(%q) = %v, want %v", tc.name, got, tc.dir)
		}
		if got := gotoolchain.IgnoredName(tc.name); got != tc.file {
			t.Errorf("IgnoredName(%q) = %v, want %v", tc.name, got, tc.file)
		}
	}
}

func TestIgnoredPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rel  string
		want bool
	}{
		{".", false},
		{"", false},
		{"pkg", false},
		{"pkg/sub", false},
		{"vendor/example.com/x", false},
		{"_x", true},
		{".hidden", true},
		{"pkg/_internal", true},
		{"a/b/_c/d", true},
		{"testdata", true},
		{"x/testdata/y", true},
		{"./pkg", false},
		{"_", true},
	} {
		if got := gotoolchain.IgnoredPath(tc.rel); got != tc.want {
			t.Errorf("IgnoredPath(%q) = %v, want %v", tc.rel, got, tc.want)
		}
	}
}
