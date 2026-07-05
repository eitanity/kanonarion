package gitexec

import (
	"strings"
	"testing"
)

// FuzzResolveTagParse fuzzes the pure parser over git ls-remote output — the
// untrusted-input surface of the VCS cross-verify egress. A hostile remote (or
// a proxy steering cross-verify at one) controls these bytes entirely.
// Invariants asserted: the parser never panics, and any commit it accepts is
// exactly 40 bytes with no whitespace (it is later passed as a git positional
// argument, so it must never smuggle extra fields).
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzResolveTagParse./internal/adapters/vcs/gitexec
func FuzzResolveTagParse(f *testing.F) {
	const ref = "refs/tags/v1.0.0"
	commit := strings.Repeat("a", 40)

	// Well-formed single match.
	f.Add([]byte(commit+"\t"+ref), ref)
	// Multiple lines, match not first.
	f.Add([]byte(commit+"\trefs/heads/main\n"+commit+"\t"+ref+"\n"), ref)
	// Wrong hash lengths.
	f.Add([]byte("abc\t"+ref), ref)
	f.Add([]byte(strings.Repeat("a", 64)+"\t"+ref), ref)
	// No tab separator / missing fields.
	f.Add([]byte(commit), ref)
	f.Add([]byte(""), ref)
	f.Add([]byte("\n\n\t\n"), ref)
	// Garbled and adversarial bytes.
	f.Add([]byte("\x00\x01 garbage"), ref)
	f.Add([]byte(commit+" \t "+ref+" extra trailing fields"), ref)
	f.Add([]byte(strings.Repeat(commit+"\trefs/heads/spam\n", 100)), ref)
	// Ref that is itself field-splitting-hostile.
	f.Add([]byte(commit+"\ta b"), "a b")

	f.Fuzz(func(t *testing.T, out []byte, ref string) {
		got, err := parseLsRemoteOutput(out, "https://example.com/repo", ref)
		if err != nil {
			if got != "" {
				t.Errorf("non-empty commit %q returned alongside error %v", got, err)
			}
			return
		}
		if len(got) != 40 {
			t.Errorf("accepted commit %q with length %d, want 40", got, len(got))
		}
		if strings.ContainsAny(got, " \t\r\n") {
			t.Errorf("accepted commit %q containing whitespace", got)
		}
	})
}
