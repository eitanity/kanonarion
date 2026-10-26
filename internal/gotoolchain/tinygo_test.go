package gotoolchain_test

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/gotoolchain"
)

func TestMissingStdPackages(t *testing.T) {
	detail := "main.go:4:2: package machine is not in std (src/machine); " +
		"x.go:5:2: package device/arm is not in std (/usr/local/go/src/device/arm); " +
		"y.go:3:2: package machine is not in std (src/machine)"
	if got := gotoolchain.MissingStdPackages(detail); !slices.Equal(got, []string{"machine", "device/arm"}) {
		t.Errorf("MissingStdPackages = %q", got)
	}
	if got := gotoolchain.MissingStdPackages("could not import machine"); got != nil {
		t.Errorf("a detail without the go command's sentence named %q", got)
	}
}

func TestIsTinyGoOwnPackage(t *testing.T) {
	for pkg, want := range map[string]bool{
		"machine": true, "machine/usb": true, "device/arm": true, "runtime/interrupt": true,
		"runtime/volatile": true, "tinygo": true, "runtime": false, "machinery": false, "foo/bar": false,
	} {
		if got := gotoolchain.IsTinyGoOwnPackage(pkg); got != want {
			t.Errorf("IsTinyGoOwnPackage(%q) = %v, want %v", pkg, got, want)
		}
	}
}

func TestTinyGoPackageRemedy(t *testing.T) {
	one := gotoolchain.TinyGoPackageRemedy([]string{"machine"}, "kanonarion local ."+gotoolchain.TinyGoFlag)
	want := "  machine is provided by TinyGo, not Go: analyse the TinyGo build with\n" +
		"  kanonarion local . --tinygo <target>\n  (`tinygo targets` lists the targets)"
	if one != want {
		t.Errorf("one package:\n%s\nwant:\n%s", one, want)
	}
	if two := gotoolchain.TinyGoPackageRemedy([]string{"machine", "device/arm"}, "x"); !strings.HasPrefix(two, "  machine, device/arm are provided by TinyGo") {
		t.Errorf("two packages: %s", two)
	}
}

func TestBuildsOnlyUnderTinyGo(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      bool
	}{
		{"tinygo", "//go:build tinygo\n\npackage p\n", true},
		{"tinygo and wasm", "// Copyright\n\n//go:build tinygo && wasm\n\npackage p\n", true},
		{"not tinygo", "//go:build !tinygo\n\npackage p\n", false},
		{"tinygo or windows", "//go:build tinygo || windows\n\npackage p\n", false},
		{"legacy line", "// +build tinygo\n\npackage p\n", true},
		{"legacy lines are ANDed", "// +build tinygo\n// +build arm\n\npackage p\n", true},
		{"legacy lines ANDed with a negation", "// +build linux\n// +build !tinygo\n\npackage p\n", false},
		{"go:build wins over +build", "//go:build windows\n// +build tinygo\n\npackage p\n", false},
		{"first go:build wins", "//go:build tinygo\n//go:build windows\n\npackage p\n", true},
		{"control", "//go:build windows\n\npackage p\n", false},
		{"no constraint", "package p\n", false},
		{"unsatisfiable", "//go:build tinygo && !tinygo\n\npackage p\n", false},
		{"after the package clause", "package p\n\n//go:build tinygo\n", false},
		{"unparsable", "//go:build tinygo &&\n\npackage p\n", false},
		{"too many tags", "//go:build tinygo && (a||b||c||d||e||f||g||h||i||j||k||l||m||n||o||p||q)\n\npackage p\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gotoolchain.BuildsOnlyUnderTinyGo(strings.NewReader(tc.src))
			if err != nil || got != tc.want {
				t.Errorf("BuildsOnlyUnderTinyGo = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("disk gone") }

func TestBuildsOnlyUnderTinyGo_AReadErrorIsReturned(t *testing.T) {
	got, err := gotoolchain.BuildsOnlyUnderTinyGo(io.MultiReader(strings.NewReader("//go:build tinygo\n"), failingReader{}))
	if err == nil || got {
		t.Errorf("BuildsOnlyUnderTinyGo = %v, %v; want the read error", got, err)
	}
}
