package domain

import (
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func coord(path, version string) fetchdomain.ModuleCoordinate {
	return fetchdomain.ModuleCoordinate{Path: path, Version: version}
}

func TestLicenseOverrideSet_Resolve(t *testing.T) {
	set := NewLicenseOverrideSet(map[string]string{
		"golang.org/x/mod":                   "MIT",
		"github.com/some/old-package@v1.2.3": "BSD-2-Clause",
		"github.com/blank/entry":             "",
	})

	t.Run("module-level applies to all versions", func(t *testing.T) {
		ov, ok := set.Resolve(coord("golang.org/x/mod", "v0.36.0"))
		if !ok || ov.SPDX != "MIT" || ov.VersionPinned {
			t.Fatalf("got %+v ok=%v, want MIT module-level", ov, ok)
		}
	})

	t.Run("version-pinned takes precedence", func(t *testing.T) {
		ov, ok := set.Resolve(coord("github.com/some/old-package", "v1.2.3"))
		if !ok || ov.SPDX != "BSD-2-Clause" || !ov.VersionPinned {
			t.Fatalf("got %+v ok=%v, want BSD-2-Clause version-pinned", ov, ok)
		}
	})

	t.Run("version-pinned does not match other versions", func(t *testing.T) {
		if _, ok := set.Resolve(coord("github.com/some/old-package", "v2.0.0")); ok {
			t.Fatal("v2.0.0 should not match a v1.2.3-pinned entry")
		}
	})

	t.Run("no entry resolves to no override", func(t *testing.T) {
		if _, ok := set.Resolve(coord("github.com/unknown/pkg", "v1.0.0")); ok {
			t.Fatal("unrelated module should not match")
		}
	})

	t.Run("blank SPDX is treated as no override", func(t *testing.T) {
		if _, ok := set.Resolve(coord("github.com/blank/entry", "v1.0.0")); ok {
			t.Fatal("blank SPDX entry should not count as an override")
		}
	})
}

func TestLicenseOverrideSet_PinnedBeatsModuleLevel(t *testing.T) {
	set := NewLicenseOverrideSet(map[string]string{
		"example.com/m":        "Apache-2.0",
		"example.com/m@v1.0.0": "MIT",
	})
	ov, ok := set.Resolve(coord("example.com/m", "v1.0.0"))
	if !ok || ov.SPDX != "MIT" || !ov.VersionPinned {
		t.Fatalf("got %+v ok=%v, want pinned MIT to win over module-level", ov, ok)
	}
	// A different version still falls back to the module-level entry.
	ov, ok = set.Resolve(coord("example.com/m", "v2.0.0"))
	if !ok || ov.SPDX != "Apache-2.0" || ov.VersionPinned {
		t.Fatalf("got %+v ok=%v, want module-level Apache-2.0 fallback", ov, ok)
	}
}

func TestNewLicenseOverrideSet_EmptyAndCopy(t *testing.T) {
	if _, ok := NewLicenseOverrideSet(nil).Resolve(coord("x", "v1")); ok {
		t.Fatal("nil set must never match")
	}
	src := map[string]string{"x": "MIT"}
	set := NewLicenseOverrideSet(src)
	src["x"] = "GPL-3.0-only" // mutate caller's map after construction
	ov, _ := set.Resolve(coord("x", "v1"))
	if ov.SPDX != "MIT" {
		t.Fatalf("set must copy input; got %q after caller mutation", ov.SPDX)
	}
}
