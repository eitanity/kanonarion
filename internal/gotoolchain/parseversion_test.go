package gotoolchain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// TestParseVersion refuses everything a record could not hold.
//
// The value is only ever compared against what records state, so a form no
// record uses is a preference that sits in a config file resolving nothing — the
// silent failure this validation exists to make loud. The rejected cases are the
// ones people actually type: the bare number from a go directive, a GOROOT, a
// toolchain module's own version, and a word.
func TestParseVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want gotoolchain.Version
		ok   bool
	}{
		{in: "go1.26.6", want: "go1.26.6", ok: true},
		{in: "go1.27", want: "go1.27", ok: true},
		{in: "go1.27rc1", want: "go1.27rc1", ok: true},
		{in: "1.26.6"},
		{in: ""},
		{in: "go"},
		{in: "latest"},
		{in: "/usr/local/go"},
		{in: "v0.0.1-go1.26.8.linux-amd64"},
		{in: "go1.26.6 "},
		{in: "GO1.26.6"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := gotoolchain.ParseVersion(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("ParseVersion(%q) = %v, want it accepted", tc.in, err)
				}
				if got != tc.want {
					t.Errorf("ParseVersion(%q) = %q, want %q", tc.in, got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseVersion(%q) = %q with no error, want it refused", tc.in, got)
			}
			if got != gotoolchain.Unrecorded {
				t.Errorf("ParseVersion(%q) returned %q alongside its error, want the zero value", tc.in, got)
			}
		})
	}
}

// TestParseVersion_AcceptsWhatFromGOROOTProduces keeps the two halves of this
// package in step. A version read out of a toolchain module's own path is a
// value a record states, so it must be a value an operator may state back: if
// FromGOROOT can produce it and ParseVersion refuses it, the preference cannot
// name the very toolchain the ledger recorded.
func TestParseVersion_AcceptsWhatFromGOROOTProduces(t *testing.T) {
	t.Parallel()
	const root = "/home/u/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.8.linux-amd64"
	derived, ok := gotoolchain.FromGOROOT(root)
	if !ok {
		t.Fatalf("FromGOROOT(%q) established no version", root)
	}
	parsed, err := gotoolchain.ParseVersion(string(derived))
	if err != nil {
		t.Fatalf("ParseVersion refuses %q, which FromGOROOT produced: %v", derived, err)
	}
	if parsed != derived {
		t.Errorf("ParseVersion(%q) = %q, want it unchanged", derived, parsed)
	}
}
