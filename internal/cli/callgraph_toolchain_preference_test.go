package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// prefCoord is the coordinate the two-toolchain cases hold generations of.
var prefCoord = coordinatetest.MustNew("example.com/mod", "v1.2.3")

// prefSpec is one generation as these tests state it: which toolchain built it,
// and — through the callee — which graph it claims.
type prefSpec struct {
	toolchain gotoolchain.Version
	callee    string
	at        time.Time
}

// prefStore lays the generations down through the real write leg and returns a
// use case reading them back.
//
// A real store rather than a fake, because the behaviour under test is
// composition's, and composition runs inside the store's read leg. A fake that
// modelled "the preference resolves the tie" would be asserting the test's own
// model of the rule rather than the rule.
func prefStore(t *testing.T, specs ...prefSpec) *cgapp.QueryCallGraphUseCase {
	t.Helper()
	store, err := cgsqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	for _, spec := range specs {
		if perr := store.PutCallGraphRecord(context.Background(), prefRecord(t, spec)); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}
	return cgapp.NewQueryCallGraphUseCase(store)
}

func prefRecord(t *testing.T, spec prefSpec) cgdomain.CallGraphRecord {
	t.Helper()
	callee := spec.callee
	if callee == "" {
		callee = "example.com/mod.Bar"
	}
	at := spec.at
	if at.IsZero() {
		at = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	}
	r := cgdomain.CallGraphRecord{
		SchemaVersion:  cgdomain.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Coordinate:     prefCoord,
		Algorithm:      cgdomain.AlgorithmCHA,
		Completeness:   cgdomain.CompletenessBuiltWithBodies,
		AnalysisSource: cgdomain.AnalysisSourceModuleZip,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/mod.Foo", Package: "example.com/mod", Symbol: "Foo"},
		},
		Edges: []cgdomain.CallEdge{
			{
				FromID:     "example.com/mod.Foo",
				ToID:       callee,
				CallSite:   cgdomain.SourcePosition{File: "foo.go", Line: 10},
				Confidence: cgdomain.ConfidenceDirect,
			},
		},
		OverallStatus:    cgdomain.CallGraphStatusExtracted,
		ArtefactIdentity: "zip:h1:a",
		NodeCount:        1,
		EdgeCount:        1,
		ExtractedAt:      at,
		PipelineVersion:  cgapp.PipelineVersion,
		Toolchain:        spec.toolchain,
	}
	var h cgdomain.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// withStoredToolchainPreference pins activeConfig for one test and restores it,
// so a case that sets a preference cannot leak it into the next.
func withStoredToolchainPreference(t *testing.T, v gotoolchain.Version) {
	t.Helper()
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	cfg := configdomain.DefaultConfig()
	cfg.Callgraph.Toolchain = v
	activeConfig = cfg
}

// showRecord runs callgraph-show over the given ledger and returns what it
// printed.
func showRecord(t *testing.T, uc QueryCallGraphUseCase, f callGraphShowFlags) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runCallGraphShow(context.Background(), prefCoord.String(), f, false, uc, &out)
	return out.String(), err
}

// conflictingLedger is the fixture the ticket is about: one coordinate, two
// toolchains, two different graphs. The graphs must differ — an identical graph
// claim is never a disagreement, whatever the labels say — so the two
// generations name different callees.
func conflictingLedger(t *testing.T) *cgapp.QueryCallGraphUseCase {
	t.Helper()
	return prefStore(t,
		prefSpec{toolchain: "go1.26.5", callee: "example.com/mod.Bar"},
		prefSpec{toolchain: "go1.27.1", callee: "example.com/mod.Baz", at: time.Date(2026, 9, 15, 13, 0, 0, 0, time.UTC)},
	)
}

// TestCallGraphShow_StoredToolchainPreferenceResolvesTheRefusal is the ticket's
// observable, in both directions.
//
// With no preference the read refuses, which is correct and must stay: two
// toolchains are two answers and serving either silently is the defect the gate
// exists to stop. With one recorded it composes, without --toolchain anywhere on
// the command line — which is the whole point, because --toolchain is per
// invocation and a store holding such a coordinate otherwise needs it forever.
func TestCallGraphShow_StoredToolchainPreferenceResolvesTheRefusal(t *testing.T) {
	uc := conflictingLedger(t)

	withStoredToolchainPreference(t, gotoolchain.Unrecorded)
	if _, err := showRecord(t, uc, callGraphShowFlags{}); !errors.Is(err, cgports.ErrCallGraphConflict) {
		t.Fatalf("with no preference the read did not refuse: %v", err)
	} else if code := ExitCodeForError(err); code != ExitIntegrity {
		t.Errorf("the refusal exits %d, want %d", code, ExitIntegrity)
	}

	withStoredToolchainPreference(t, "go1.27.1")
	out, err := showRecord(t, uc, callGraphShowFlags{})
	if err != nil {
		t.Fatalf("with callgraph.toolchain set the read still refused: %v", err)
	}
	if !strings.Contains(out, "go1.27.1") {
		t.Errorf("the served record does not name the preferred toolchain:\n%s", out)
	}
	if strings.Contains(out, "example.com/mod.Bar") {
		t.Errorf("the preference served the other toolchain's graph:\n%s", out)
	}
}

// TestCallGraphShow_ExplicitToolchainBeatsTheStoredPreference.
//
// The stored value answers only where the invocation did not. An invocation that
// names a toolchain has said which measurement it wants, and a config file
// overriding that would make the flag unusable on any store that had ever set
// one.
func TestCallGraphShow_ExplicitToolchainBeatsTheStoredPreference(t *testing.T) {
	uc := conflictingLedger(t)
	withStoredToolchainPreference(t, "go1.27.1")

	out, err := showRecord(t, uc, callGraphShowFlags{toolchain: "go1.26.5"})
	if err != nil {
		t.Fatalf("runCallGraphShow: %v", err)
	}
	if !strings.Contains(out, "go1.26.5") || strings.Contains(out, "go1.27.1") {
		t.Errorf("--toolchain go1.26.5 did not win over the stored go1.27.1:\n%s", out)
	}
}

// TestCallGraphShow_PreferenceNeverNarrowsTheRead is the control that makes the
// change safe.
//
// A preference that FILTERED would answer "no record" for the hundreds of
// modules that state no toolchain at all, and for every coordinate built by some
// other one — turning a disambiguation into a silently short answer. So a
// coordinate with nothing to disambiguate must be served byte-for-byte as it is
// with no preference, including when the preferred toolchain is one the ledger
// has never held.
func TestCallGraphShow_PreferenceNeverNarrowsTheRead(t *testing.T) {
	tests := []struct {
		name string
		spec prefSpec
	}{
		{name: "a coordinate built by one toolchain", spec: prefSpec{toolchain: "go1.26.5"}},
		{name: "a coordinate that states no toolchain", spec: prefSpec{toolchain: gotoolchain.Unrecorded}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uc := prefStore(t, tc.spec)

			withStoredToolchainPreference(t, gotoolchain.Unrecorded)
			unset, uerr := showRecord(t, uc, callGraphShowFlags{})
			if uerr != nil {
				t.Fatalf("with no preference: %v", uerr)
			}

			// A toolchain the ledger has never held, which is the strongest form of
			// the check: if the preference narrowed at all, this read would find
			// nothing.
			withStoredToolchainPreference(t, "go1.99.9")
			set, serr := showRecord(t, uc, callGraphShowFlags{})
			if serr != nil {
				t.Fatalf("with a preference set the read failed: %v", serr)
			}
			if set != unset {
				t.Errorf("the preference changed a read it must not touch:\n--- unset ---\n%s\n--- set ---\n%s", unset, set)
			}
		})
	}
}

// TestToolchainPreference_ResolvesWhereTheFlagIsRead.
//
// The flag and the stored value are settled in one place, so the seven
// ComposeRequest sites downstream inherit the preference without any of them
// knowing a config file exists. Asserting it here rather than at those sites is
// what stops the next read path from having to remember.
func TestToolchainPreference_ResolvesWhereTheFlagIsRead(t *testing.T) {
	tests := []struct {
		name   string
		flag   string
		stored gotoolchain.Version
		want   gotoolchain.Version
	}{
		{name: "neither states one", want: gotoolchain.Unrecorded},
		{name: "the stored value answers when the flag does not", stored: "go1.27.1", want: "go1.27.1"},
		{name: "the flag answers when nothing is stored", flag: "go1.26.5", want: "go1.26.5"},
		{name: "the flag beats the stored value", flag: "go1.26.5", stored: "go1.27.1", want: "go1.26.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withStoredToolchainPreference(t, tc.stored)
			if got := toolchainPreferenceOf(tc.flag); got != tc.want {
				t.Errorf("toolchainPreferenceOf(%q) = %q, want %q", tc.flag, got, tc.want)
			}
			f := buildScopeFlags{toolchain: tc.flag}
			if got := f.toolchainPreference(); got != tc.want {
				t.Errorf("buildScopeFlags.toolchainPreference() = %q, want %q", got, tc.want)
			}
			// The scope is what every scoped read carries, so the preference has to
			// survive into it — an unrestricted resolve is the path a store-wide
			// traversal takes.
			sc, err := f.resolve(context.Background(), nil)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if sc.toolchain != tc.want {
				t.Errorf("buildScope.toolchain = %q, want %q", sc.toolchain, tc.want)
			}
		})
	}
}

// TestStoredToolchainPreference_RoundTripsThroughConfig: set it, read it back,
// and see `config show` name where the value came from.
//
// The source matters as much as the value. A preference in force because an
// operator wrote it and one in force by default are different facts, and
// `config show` is where a reader who is about to be served a disambiguated
// answer finds out which.
func TestStoredToolchainPreference_RoundTripsThroughConfig(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	if err := runConfigSet(root, "callgraph.toolchain", "go1.26.6", false, &buf); err != nil {
		t.Fatalf("runConfigSet: %v", err)
	}

	cfg, err := loadStoreConfig(root)
	if err != nil {
		t.Fatalf("loadStoreConfig: %v", err)
	}
	if cfg.Callgraph.Toolchain != "go1.26.6" {
		t.Errorf("callgraph.toolchain loaded as %q, want go1.26.6", cfg.Callgraph.Toolchain)
	}

	got, err := configGetValue(cfg, "callgraph.toolchain")
	if err != nil {
		t.Fatalf("configGetValue: %v", err)
	}
	if got != "go1.26.6" {
		t.Errorf("config get callgraph.toolchain = %q, want go1.26.6", got)
	}

	source, err := configKeySource(root, "callgraph.toolchain")
	if err != nil {
		t.Fatalf("configKeySource: %v", err)
	}
	if source != configSourceFile {
		t.Errorf("config get reports source %q, want %q", source, configSourceFile)
	}

	var shown bytes.Buffer
	if err := runStoreConfigShow(root, false, &shown); err != nil {
		t.Fatalf("runStoreConfigShow: %v", err)
	}
	if !strings.Contains(shown.String(), "callgraph.toolchain") ||
		!strings.Contains(shown.String(), "go1.26.6") {
		t.Errorf("config show does not list callgraph.toolchain:\n%s", shown.String())
	}
}

// TestStoredToolchainPreference_UnsetIsStated: a store that has chosen nothing
// says so rather than printing a blank line a reader would take for a setting
// with no value.
func TestStoredToolchainPreference_UnsetIsStated(t *testing.T) {
	cfg := configdomain.DefaultConfig()
	got, err := configGetValue(cfg, "callgraph.toolchain")
	if err != nil {
		t.Fatalf("configGetValue: %v", err)
	}
	if !strings.Contains(got, "unset") {
		t.Errorf("config get callgraph.toolchain with none set = %q, want it to say so", got)
	}

	root := t.TempDir()
	source, err := configKeySource(root, "callgraph.toolchain")
	if err != nil {
		t.Fatalf("configKeySource: %v", err)
	}
	if source != configSourceDefault {
		t.Errorf("an unwritten key reports source %q, want %q", source, configSourceDefault)
	}
}

// TestParseConfigValue_CallgraphToolchain refuses the forms that would sit in a
// config file resolving nothing, by the same path that refuses a bad
// callgraph.exclude.
func TestParseConfigValue_CallgraphToolchain(t *testing.T) {
	tests := []struct {
		value   string
		wantErr bool
	}{
		{value: "go1.26.6"},
		{value: "go1.27rc1"},
		{value: "1.26.6", wantErr: true},
		{value: "/usr/local/go", wantErr: true},
		{value: "[go1.26.6]", wantErr: true},
		{value: "latest", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			_, err := parseConfigValue("callgraph.toolchain", tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseConfigValue accepted %q", tc.value)
				}
				var ee *exitError
				if !errors.As(err, &ee) || ee.code != ExitConfig {
					t.Errorf("refusal for %q does not carry ExitConfig: %v", tc.value, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseConfigValue refused %q: %v", tc.value, err)
			}
		})
	}
}

// TestParseConfigValue_VCSHostAllowlist covers the sibling validator this
// change moved out of parseConfigValue's switch.
//
// It was uncovered while it was inline, which the function-level report could
// not show; extracting it made the gap visible, so it is closed here rather than
// left. The rule under test is the domain's, and the point is that the refusal
// happens while the operator is typing rather than halfway through the next
// walk.
func TestParseConfigValue_VCSHostAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "a list of bare hostnames", value: "[github.com, git.example.org]"},
		// The domain refuses an empty list rather than reading it as "trust
		// nothing": the list selects WHICH forges are trusted, not whether the git
		// leg runs at all.
		{name: "an empty list is not a way to turn the check off", value: "[]", wantErr: true},
		{name: "a scalar is not a list", value: "github.com", wantErr: true},
		{name: "a URL is not a bare hostname", value: "[https://github.com/x]", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigValue("fetch_policy.allowed_vcs_hosts", tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseConfigValue accepted %q", tc.value)
				}
				var ee *exitError
				if !errors.As(err, &ee) || ee.code != ExitConfig {
					t.Errorf("refusal for %q does not carry ExitConfig: %v", tc.value, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseConfigValue refused %q: %v", tc.value, err)
			}
		})
	}
}
