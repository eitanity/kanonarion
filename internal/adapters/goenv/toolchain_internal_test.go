package goenv

import "testing"

// TestIsToolchainTooOld pins the marker against the wording the go command
// emits and against two strings that must not match it. Both halves of the
// sentence are required, because the phrase alone appears in module prose.
func TestIsToolchainTooOld(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		detail string
		want   bool
	}{
		{
			name:   "unpinned",
			detail: "meta load: err: exit status 1: stderr: go: go.mod requires go >= 1.26.6 (running go 1.26.5)\n",
			want:   true,
		},
		{
			name:   "pinned names the setting too",
			detail: "go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)\n",
			want:   true,
		},
		{
			name:   "the message this replaces",
			detail: "go: golang.org/toolchain@v0.0.1-go1.26.6.linux-amd64: verifying module: checksum database disabled by GOSUMDB=off\n",
			want:   false,
		},
		{
			name:   "half the phrase in the module's own prose",
			detail: "./doc.go:3:2: this package requires go >= 1.22 to build",
			want:   false,
		},
	} {
		if got := IsToolchainTooOld(tc.detail); got != tc.want {
			t.Errorf("%s: IsToolchainTooOld = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRequiredGoVersion reads the versions out of the go command's own sentence.
// The highest requirement wins because one load can refuse for several modules
// at once and a toolchain satisfying the largest satisfies them all.
func TestRequiredGoVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		detail           string
		required, runing string
		ok               bool
	}{
		{
			name:     "the main module's own go line",
			detail:   "meta load: err: exit status 1: stderr: go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)",
			required: "1.26.6", runing: "1.26.5", ok: true,
		},
		{
			name:     "a dependency deeper in the graph",
			detail:   "go: module example.com/dep@v1.2.3 requires go >= 1.28 (running go 1.26.5)",
			required: "1.28", runing: "1.26.5", ok: true,
		},
		{
			name: "several refusals in one load",
			detail: "go: a.mod requires go >= 1.27.0 (running go 1.26.5; GOTOOLCHAIN=local)\n" +
				"go: b.mod requires go >= 1.30.2 (running go 1.26.5; GOTOOLCHAIN=local)",
			required: "1.30.2", runing: "1.26.5", ok: true,
		},
		{
			name:   "a module quoting the phrase",
			detail: "package doc says: requires go >= 1.30 to build",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			required, running, ok := requiredGoVersion(c.detail)
			if ok != c.ok || required != c.required || running != c.runing {
				t.Errorf("requiredGoVersion = (%q, %q, %t), want (%q, %q, %t)",
					required, running, ok, c.required, c.runing, c.ok)
			}
		})
	}
}
