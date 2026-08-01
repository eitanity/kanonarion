package application

import "testing"

// TestIsLicenceFilename pins the filename matcher, including the bare-name
// shorthands and the reversed <NAME>-LICENSE form. The shorthand list carries
// the permissive names observed in the module-cache sweep alongside the GPL
// ones: listing only GPLV2/GPLV3 biased detection toward copyleft on
// dual-licensed modules (gorhill/cronexpr's APLv2 arm was invisible) and let a
// licensed module (mrjones/oauth's MIT-LICENSE.txt) read as unlicensed.
func TestIsLicenceFilename(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Stems, forward variants (pre-existing behaviour).
		{"LICENSE", true},
		{"LICENCE", true},
		{"COPYING", true},
		{"UNLICENSE", true},
		{"LICENSE-MIT", true},
		{"LICENSE.txt", true},
		{"LICENSE.MPL-2.0", true},
		{"license.go", false},
		{"COPYRIGHT", true},
		{"NOTICE", true},
		// Bare licence-name shorthands: the GPL pair, and the permissive
		// equivalents observed in the wild.
		{"GPLv2", true},
		{"GPLv3", true},
		{"APLv2", true},
		{"APACHE-LICENSE-2.0", true},
		{"MIT-LICENSE", true},
		{"GO-LICENSE", true},
		// Reversed form <NAME>-LICENSE[.ext], both spellings.
		{"MIT-LICENSE.txt", true},
		{"BSD-LICENCE", true},
		{"MIT-LICENSE.md", true},
		// Reversed form still rejects source files and non-extension tails.
		{"MIT-LICENSE.go", false},
		{"THIRD-PARTY-LICENSES", false},
		// Nested paths match on the base name.
		{"sub/dir/GPLv3", true},
		{"sub/dir/MIT-LICENSE.txt", true},
		// Non-licence names stay out.
		{"README.md", false},
		{"main.go", false},
	}
	for _, tc := range cases {
		if got := isLicenceFilename(tc.path); got != tc.want {
			t.Errorf("isLicenceFilename(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
