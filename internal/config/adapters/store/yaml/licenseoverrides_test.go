package yaml_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
)

// TestParse_LicenseOverrideBothForms: an entry written as a bare identifier and
// one written with its provenance both load, from the same block. The bare form
// is what `config set` writes and what every file written before the attributed
// form holds, so it has to keep working exactly as it did.
func TestParse_LicenseOverrideBothForms(t *testing.T) {
	input := `
version: "2"
license_overrides:
  golang.org/x/mod: MIT
  example.com/ungranted:
    spdx: "Apache-2.0"
    declared_by: "test-operator@example.invalid"
    declared_on: "2026-09-19"
    basis: "synthetic fixture; no upstream source was read"
  example.com/pinned@v1.2.3: BSD-3-Clause
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LicenseOverrides) != 3 {
		t.Fatalf("got %d overrides, want 3: %+v", len(cfg.LicenseOverrides), cfg.LicenseOverrides)
	}
	bare := cfg.LicenseOverrides["golang.org/x/mod"]
	if bare.SPDX != "MIT" {
		t.Errorf("bare form: spdx = %q, want MIT", bare.SPDX)
	}
	if bare.Attributed() {
		t.Errorf("bare form reports as attributed: %+v", bare)
	}
	attributed := cfg.LicenseOverrides["example.com/ungranted"]
	if attributed.SPDX != "Apache-2.0" || attributed.DeclaredBy != "test-operator@example.invalid" ||
		attributed.DeclaredOn != "2026-09-19" || attributed.Basis == "" {
		t.Errorf("attributed form not read back: %+v", attributed)
	}
	if !attributed.Attributed() {
		t.Error("attributed form reports as unattributed")
	}
	if cfg.LicenseOverrides["example.com/pinned@v1.2.3"].SPDX != "BSD-3-Clause" {
		t.Error("version-pinned key was not read")
	}
}

// TestParse_LicenseOverridePartialProvenanceIsRefused: half a provenance is an
// unfinished edit. Refusing it at load names the config line; carried through,
// it would publish a determination naming an author with no date, or a date
// with no basis, in an attribution document.
func TestParse_LicenseOverridePartialProvenanceIsRefused(t *testing.T) {
	const header = "version: \"2\"\nlicense_overrides:\n  example.com/mod:\n"
	cases := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name:      "no declarer",
			body:      "    spdx: MIT\n    declared_on: \"2026-09-19\"\n    basis: \"a fixture\"\n",
			wantField: "declared_by",
		},
		{
			name:      "no date",
			body:      "    spdx: MIT\n    declared_by: \"t@example.invalid\"\n    basis: \"a fixture\"\n",
			wantField: "declared_on",
		},
		{
			name:      "no basis",
			body:      "    spdx: MIT\n    declared_by: \"t@example.invalid\"\n    declared_on: \"2026-09-19\"\n",
			wantField: "basis",
		},
		{
			name:      "no identifier",
			body:      "    declared_by: \"t@example.invalid\"\n    declared_on: \"2026-09-19\"\n    basis: \"a fixture\"\n",
			wantField: "spdx",
		},
		{
			name:      "a date nobody can compare against a release",
			body:      "    spdx: MIT\n    declared_by: \"t@example.invalid\"\n    declared_on: \"last week\"\n    basis: \"a fixture\"\n",
			wantField: "declared_on",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := yaml.Parse([]byte(header + tc.body))
			if err == nil {
				t.Fatal("an unfinished determination loaded")
			}
			if !strings.Contains(err.Error(), "license_overrides.example.com/mod") {
				t.Errorf("error does not name the config entry: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("error does not name the missing field %q: %v", tc.wantField, err)
			}
		})
	}
}

// TestParse_LicenseOverrideBlankEntryLoads: a key written with no value has
// always resolved to no override. It stays a no-op rather than becoming a load
// failure — a file that loads today must keep loading.
func TestParse_LicenseOverrideBlankEntryLoads(t *testing.T) {
	cfg, err := yaml.Parse([]byte("version: \"2\"\nlicense_overrides:\n  example.com/mod:\n"))
	if err != nil {
		t.Fatalf("a blank entry was refused: %v", err)
	}
	if _, ok := cfg.LicenseOverrides["example.com/mod"]; ok {
		t.Errorf("a blank entry became an override: %+v", cfg.LicenseOverrides)
	}
}

// TestParse_LicenseOverrideRejectsAList: the two accepted forms are a scalar
// and a mapping. Anything else is a typo, and naming it beats decoding it to a
// zero value that silently overrides nothing.
func TestParse_LicenseOverrideRejectsAList(t *testing.T) {
	_, err := yaml.Parse([]byte("version: \"2\"\nlicense_overrides:\n  example.com/mod: [MIT]\n"))
	if err == nil {
		t.Fatal("a sequence loaded as a determination")
	}
	if !strings.Contains(err.Error(), "SPDX identifier or a mapping") {
		t.Errorf("error does not say what the two forms are: %v", err)
	}
}
