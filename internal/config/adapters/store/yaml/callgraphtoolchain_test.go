package yaml_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// TestParse_CallgraphToolchain: the preference reaches the typed config, and an
// absent key leaves it unset.
//
// The absent case is the one that matters. The preference resolves a tie and
// must never become a filter, so the value a store that has chosen nothing loads
// has to be the zero value and nothing else — a stand-in would narrow reads for
// every store that never asked for one.
func TestParse_CallgraphToolchain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  gotoolchain.Version
	}{
		{
			name:  "a stated version is loaded",
			input: "version: \"2\"\ncallgraph:\n  toolchain: go1.26.6\n",
			want:  "go1.26.6",
		},
		{
			name:  "an absent key leaves no preference",
			input: "version: \"2\"\ncallgraph:\n  exclude: [example.com/pkg]\n",
			want:  gotoolchain.Unrecorded,
		},
		{
			name:  "an absent callgraph block leaves no preference",
			input: "version: \"2\"\n",
			want:  gotoolchain.Unrecorded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := yaml.Parse([]byte(tc.input))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if cfg.Callgraph.Toolchain != tc.want {
				t.Errorf("callgraph.toolchain = %q, want %q", cfg.Callgraph.Toolchain, tc.want)
			}
		})
	}
}

// TestParse_CallgraphToolchain_RefusesAValueNoRecordCouldHold.
//
// A hand-edited file is the other way this key gets written, so the loader
// refuses the same forms `config set` does. Accepting "1.26.6" would store a
// preference that matches no record and therefore resolves nothing, which is a
// silent no-op rather than a setting.
func TestParse_CallgraphToolchain_RefusesAValueNoRecordCouldHold(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"1.26.6", "/usr/local/go", "latest"} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			_, err := yaml.Parse([]byte("version: \"2\"\ncallgraph:\n  toolchain: \"" + bad + "\"\n"))
			if err == nil {
				t.Fatalf("Parse accepted callgraph.toolchain %q", bad)
			}
			if !strings.Contains(err.Error(), "callgraph.toolchain") {
				t.Errorf("the refusal does not name the key it is about: %v", err)
			}
		})
	}
}
