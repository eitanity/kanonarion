package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustHash(t *testing.T, c Config) string {
	t.Helper()
	h, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 {
		t.Fatalf("Hash = %q, want sha256:<64 hex>", h)
	}
	return h
}

// A spelling that means the same thing hashes the same: unset outcomes and the
// defaults they resolve to, reordered or repeated set members, nil and empty.
func TestHash_SameMeaningSameHash(t *testing.T) {
	base := DefaultConfig()
	want := mustHash(t, base)

	same := DefaultConfig()
	same.LicensePolicy.Rules[0].Default = ""
	same.LicensePolicy.Rules[0].UnknownLicense = ""
	same.LicensePolicy.Rules[0].Warn = []string{"restricted", "strong_copyleft", "restricted"}
	same.LicensePolicy.Categories["permissive"] = []string{"ISC", "MIT", "BSD-3-Clause", "BSD-2-Clause", "Apache-2.0"}
	same.Callgraph.Exclude = nil
	same.LicenseOverrides = nil
	same.CopyrightDeclarations = nil
	same.GoDebugPolicy.Green = ""
	same.FIPSPolicy.OnDeviation = ""
	same.VulnDB.URL = DefaultVulnDBURL + "/"
	same.Staleness.ProbeConcurrency = DefaultStalenessProbeConcurrency
	if got := mustHash(t, same); got != want {
		t.Errorf("same meaning, different hash:\n got %s\nwant %s", got, want)
	}

	serial := DefaultConfig()
	serial.Staleness.TTL, serial.Staleness.ProbeConcurrency = 0, 0
	negative := DefaultConfig()
	negative.Staleness.TTL, negative.Staleness.ProbeConcurrency = -time.Second, -1
	if mustHash(t, serial) != mustHash(t, negative) {
		t.Error("a negative ttl/probe count means the same as zero and must hash alike")
	}
}

// Sections that change no answer are outside the hash.
func TestHash_IgnoresPreferencesStorageAndVersion(t *testing.T) {
	want := mustHash(t, DefaultConfig())
	c := DefaultConfig()
	c.Version = "2"
	c.Preferences = Preferences{JSON: true, LogLevel: "debug"}
	c.Storage = StorageConfig{Backend: "other", SumDBCache: "/x"}
	c.Sections = map[string][]byte{"other": []byte("dsn: x\n")}
	if got := mustHash(t, c); got != want {
		t.Errorf("display/storage settings moved the hash: %s != %s", got, want)
	}
}

// Every section that decides an answer moves the hash.
func TestHash_EverySectionThatDecidesMovesIt(t *testing.T) {
	base := mustHash(t, DefaultConfig())
	edits := map[string]func(*Config){
		"license category": func(c *Config) { c.LicensePolicy.Categories["permissive"] = []string{"MIT"} },
		"license rule":     func(c *Config) { c.LicensePolicy.Rules[1].UnknownLicense = UnknownLicenseBlock },
		"license rule order": func(c *Config) {
			c.LicensePolicy.Rules[0], c.LicensePolicy.Rules[1] = c.LicensePolicy.Rules[1], c.LicensePolicy.Rules[0]
		},
		"license override": func(c *Config) { c.LicenseOverrides = map[string]LicenseOverride{"example.com/m": {SPDX: "MIT"}} },
		"copyright declaration": func(c *Config) {
			c.CopyrightDeclarations = map[string]CopyrightDeclaration{"example.com/m": {Copyright: "x"}}
		},
		"callgraph exclude":   func(c *Config) { c.Callgraph.Exclude = []string{"example.com/p"} },
		"callgraph toolchain": func(c *Config) { c.Callgraph.Toolchain = "go1.26.6" },
		"staleness ttl":       func(c *Config) { c.Staleness.TTL = 2 * time.Hour },
		"staleness probes":    func(c *Config) { c.Staleness.ProbeConcurrency = 4 },
		"directive policy":    func(c *Config) { c.DirectivePolicy.LocalPathReplace = PolicyOutcomeAllow },
		"godebug policy":      func(c *Config) { c.GoDebugPolicy.Red = PolicyOutcomeNotify },
		"vendor policy":       func(c *Config) { c.VendorPolicy.OnDrift = PolicyOutcomeAllow },
		"vendor only":         func(c *Config) { c.VendorPolicy.VendorOnly = true },
		"fips required":       func(c *Config) { c.FIPSPolicy.Required = true },
		"fips on deviation":   func(c *Config) { c.FIPSPolicy.OnDeviation = PolicyOutcomeNotify },
		"vcs hosts enforcing": func(c *Config) { c.FetchPolicy.AllowedVCSHosts = []string{"github.com"} },
		"vulndb mirror":       func(c *Config) { c.VulnDB.URL = "https://mirror.example.com" },
	}
	seen := map[string]string{}
	for name, edit := range edits {
		c := DefaultConfig()
		edit(&c)
		got := mustHash(t, c)
		if got == base {
			t.Errorf("%s: edit did not move the hash", name)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("%s and %s hash alike", name, other)
		}
		seen[got] = name
	}
}

func TestHash_MarshalFailureIsReturned(t *testing.T) {
	orig := marshalCanonical
	t.Cleanup(func() { marshalCanonical = orig })
	boom := errors.New("boom")
	marshalCanonical = func(any) ([]byte, error) { return nil, boom }
	if _, err := DefaultConfig().Hash(); !errors.Is(err, boom) {
		t.Fatalf("Hash error = %v, want %v", err, boom)
	}
}
