package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	blobstore "github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// allMigrations returns every migration the binary knows about.
// Its length is the binary's expected schema version. The aggregation lives in
// the neutral composition root so the CLI and the public façade open mirror.db
// against an identical schema.
func allMigrations() []sqlitestore.Migration {
	return composition.Migrations()
}

func newStoreCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "store",
		Short: "Inspect and manage the kanonarion store",
	}
	cmd.AddCommand(newStoreInfoCmd(stdout, stderr))
	cmd.AddCommand(newStoreConfigCmd(stdout))
	cmd.AddCommand(newStoreCleanCmd(stdout))
	return cmd
}

// tempPrefixes lists all kanonarion-owned temp dir/file prefixes created in os.TempDir.
var tempPrefixes = []string{
	"kanonarion-vuln-scan-",
	"kanonarion-modcache-",
	"kanonarion-vulndb-",
	"kanonarion-vuln-scan-zip-",
	"kanonarion-vulndb-zip-",
	"kanonarion-verify-",
	"kanonarion-cg-",
	"kanonarion-bin-",
}

func newStoreCleanCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Remove orphaned temp files left by interrupted operations",
		Long: `Remove orphaned temporary files left by interrupted kanonarion operations.

Cleans two categories:
  1. Incomplete blob writes (.tmp-* in the store blobs directory)
  2. Leftover scan and analysis temp directories in the system temp directory

Safe to run while kanonarion is idle. Do not run while other kanonarion
processes are actively scanning.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStoreClean(storeRoot, os.TempDir(), stdout)
		},
	}
}

// runStoreClean removes orphaned blob temp files under root, and kanonarion-owned
// temp entries directly under tmpDir.
//
// tmpDir is a parameter rather than a call to os.TempDir inside the sweep so that
// tests can point it at a directory of their own. The sweep deletes by prefix and
// does not check whether an entry is in use, so running it against the real shared
// temp directory destroys the working files of any kanonarion process scanning on
// the same machine — which is what the command's own help warns about. A test that
// called os.TempDir() would do exactly that to a concurrent scan, and did.
func runStoreClean(root, tmpDir string, stdout io.Writer) error {
	total := 0

	// 1. Orphaned blob temp files.
	blobs := blobstore.New(root)
	n, err := blobs.CleanOrphanedTemps()
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "warning: cleaning blob temps: %v\n", err)
	}
	if n > 0 {
		_, _ = fmt.Fprintf(stdout, "removed %d orphaned blob temp file(s) from %s\n", n, filepath.Join(root, "blobs"))
		total += n
	}

	// 2. Scan and analysis temp dirs/files in tmpDir.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return fmt.Errorf("reading temp dir %s: %w", tmpDir, err)
	}
	for _, e := range entries {
		name := e.Name()
		for _, prefix := range tempPrefixes {
			if strings.HasPrefix(name, prefix) {
				full := filepath.Join(tmpDir, name)
				if rerr := os.RemoveAll(full); rerr != nil {
					_, _ = fmt.Fprintf(stdout, "warning: removing %s: %v\n", full, rerr)
				} else {
					_, _ = fmt.Fprintf(stdout, "removed %s\n", full)
					total++
				}
				break
			}
		}
	}

	if total == 0 {
		_, _ = fmt.Fprintln(stdout, "nothing to clean")
	} else {
		_, _ = fmt.Fprintf(stdout, "cleaned %d item(s)\n", total)
	}
	return nil
}

func newStoreConfigCmd(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and manage the store configuration",
	}
	cmd.AddCommand(newStoreConfigShowCmd(stdout))
	return cmd
}

type configShowResult struct {
	Version          string                `json:"version"`
	Preferences      configPrefsResult     `json:"preferences"`
	LicensePolicy    configPolicyResult    `json:"license_policy"`
	LicenseOverrides map[string]string     `json:"license_overrides"`
	Callgraph        configCGResult        `json:"callgraph"`
	Staleness        configStalenessResult `json:"staleness"`

	// Unified supply-chain governance blocks (schema v2). Surfaced
	// in the effective-config view so the schema bump and the resolved
	// posture are observable by agentic consumers; rules are wired by the
	// directive and godebug policy blocks below.
	DirectivePolicy configDirectiveResult `json:"directive_policy"`
	GoDebugPolicy   configGoDebugResult   `json:"godebug_policy"`
	VendorPolicy    configVendorResult    `json:"vendor_policy"`
	FIPSPolicy      configFIPSResult      `json:"fips_policy"`
	FetchPolicy     configFetchResult     `json:"fetch_policy"`
}

// configFetchResult reports the resolved cross-verification posture.
//
// Enforcing is stated alongside the list because the list alone cannot say it:
// an absent allowed_vcs_hosts still has a host set behind it (the built-in
// one), and the difference that matters to a reader is whether an off-list host
// is refused or merely reported.
type configFetchResult struct {
	AllowedVCSHosts []string `json:"allowed_vcs_hosts"`
	Enforcing       bool     `json:"enforcing"`
}

type configDirectiveResult struct {
	LocalPathReplace  string `json:"local_path_replace"`
	ModulePathReplace string `json:"module_path_replace"`
	VersionReplace    string `json:"version_replace"`
	ExcludeNewer      string `json:"exclude_newer"`
	ExcludeOlder      string `json:"exclude_older"`
	Default           string `json:"default"`
}

type configGoDebugResult struct {
	Red   string `json:"red"`
	Amber string `json:"amber"`
	Green string `json:"green"`
}

type configVendorResult struct {
	OnDrift         string `json:"on_drift"`
	OnInconsistency string `json:"on_inconsistency"`
	VendorOnly      bool   `json:"vendor_only"`
}

type configFIPSResult struct {
	Required    bool   `json:"required"`
	OnDeviation string `json:"on_deviation"`
}

type configPrefsResult struct {
	JSON     bool   `json:"json"`
	LogLevel string `json:"log_level"`
	Progress bool   `json:"progress"`
}

type configPolicyResult struct {
	Categories map[string][]string `json:"categories"`
	Rules      []configRuleResult  `json:"rules"`
}

type configRuleResult struct {
	Scope          string   `json:"scope"`
	Allow          []string `json:"allow"`
	Notify         []string `json:"notify"`
	Warn           []string `json:"warn"`
	Default        string   `json:"default"`
	UnknownLicense string   `json:"unknown_license"`
}

type configCGResult struct {
	Exclude []string `json:"exclude"`
}

// configStalenessResult reports the resolved latest-version ledger TTL.
//
// Rendered as a duration string rather than a number: "1h0m0s" says what unit
// it is in, and a bare 3600000000000 does not.
type configStalenessResult struct {
	TTL string `json:"ttl"`
}

func newStoreConfigShowCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the effective configuration for this store",
		Example: `  kanonarion store config show
  kanonarion store config show --json`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStoreConfigShow(storeRoot, jsonOut, stdout)
		},
	}
}

func runStoreConfigShow(root string, asJSON bool, stdout io.Writer) error {
	if asJSON {
		cfg := activeConfig
		rules := make([]configRuleResult, 0, len(cfg.LicensePolicy.Rules))
		for _, r := range cfg.LicensePolicy.Rules {
			rules = append(rules, configRuleResult{
				Scope:          r.Scope,
				Allow:          r.Allow,
				Notify:         r.Notify,
				Warn:           r.Warn,
				Default:        string(r.Default),
				UnknownLicense: string(r.UnknownLicense),
			})
		}
		result := configShowResult{
			Version: cfg.Version,
			Preferences: configPrefsResult{
				JSON:     cfg.Preferences.JSON,
				LogLevel: cfg.Preferences.LogLevel,
				Progress: cfg.Preferences.Progress,
			},
			LicensePolicy: configPolicyResult{
				Categories: cfg.LicensePolicy.Categories,
				Rules:      rules,
			},
			LicenseOverrides: cfg.LicenseOverrides,
			Callgraph:        configCGResult{Exclude: cfg.Callgraph.Exclude},
			Staleness:        configStalenessResult{TTL: cfg.Staleness.TTL.String()},
			DirectivePolicy: configDirectiveResult{
				LocalPathReplace:  string(cfg.DirectivePolicy.LocalPathReplace),
				ModulePathReplace: string(cfg.DirectivePolicy.ModulePathReplace),
				VersionReplace:    string(cfg.DirectivePolicy.VersionReplace),
				ExcludeNewer:      string(cfg.DirectivePolicy.ExcludeNewer),
				ExcludeOlder:      string(cfg.DirectivePolicy.ExcludeOlder),
				Default:           string(cfg.DirectivePolicy.Default),
			},
			GoDebugPolicy: configGoDebugResult{
				Red:   string(cfg.GoDebugPolicy.Red),
				Amber: string(cfg.GoDebugPolicy.Amber),
				Green: string(cfg.GoDebugPolicy.Green),
			},
			VendorPolicy: configVendorResult{
				OnDrift:         string(cfg.VendorPolicy.OnDrift),
				OnInconsistency: string(cfg.VendorPolicy.OnInconsistency),
				VendorOnly:      cfg.VendorPolicy.VendorOnly,
			},
			FIPSPolicy: configFIPSResult{
				Required:    cfg.FIPSPolicy.Required,
				OnDeviation: string(cfg.FIPSPolicy.OnDeviation),
			},
			FetchPolicy: configFetchResult{
				AllowedVCSHosts: cfg.FetchPolicy.AllowedVCSHosts,
				Enforcing:       cfg.FetchPolicy.AllowedVCSHosts != nil,
			},
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("encoding config: %w", err)
		}
		return nil
	}

	data, err := os.ReadFile(filepath.Join(root, "config.yaml")) // #nosec G304 -- operator-supplied store-root path
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	if _, err := fmt.Fprint(stdout, string(data)); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

type storeInfoResult struct {
	StoreRoot string   `json:"store_root"`
	DBPath    string   `json:"db_path"`
	Applied   int      `json:"applied"`
	Expected  int      `json:"expected"`
	Unknown   []string `json:"unknown,omitempty"`
	Status    string   `json:"status"`
}

func newStoreInfoCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Report the store schema version and migration status",
		Example: `  kanonarion store info --store-root ~/kanonarion/.mirror
  kanonarion store info --store-root ~/kanonarion/.mirror --json`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStoreInfo(storeRoot, jsonOut, stdout, stderr)
		},
	}

	return cmd
}

// storeSchemaState is what the store's schema_migrations table says about this
// binary: how many migrations are applied, how many this binary knows, and which
// applied ones it does not recognise.
//
// It is one determination with two consumers — the reporting `store info` prints
// and the gate that refuses to operate — because the question they ask is
// identical and a second copy of the comparison could drift into disagreeing
// with the command an operator uses to diagnose it.
type storeSchemaState struct {
	applied  int
	expected int
	unknown  []string
}

// isNewer reports whether the store carries migrations this binary does not know,
// which means it was built by a later build of kanonarion. It is not the same
// question as "applied != expected": a store with FEWER migrations than this
// binary knows is simply one this binary is about to bring up to date.
func (s storeSchemaState) isNewer() bool { return len(s.unknown) > 0 }

func (s storeSchemaState) status() string {
	switch {
	case s.isNewer():
		return "newer"
	case s.applied == s.expected:
		return "ok"
	default:
		return fmt.Sprintf("pending (%d of %d migrations applied)", s.applied, s.expected)
	}
}

// readStoreSchemaState asks the store what it holds and pairs the answer with what
// this binary expects. The comparison itself lives in sqlitestore, beside migrate,
// because the public driver surface opens the store to write to it too and must
// reach the same verdict this does.
//
// The handle must have been opened WITHOUT migrations, or the comparison would be
// against a table this call had just written to.
//
// It takes no context. It runs on the path that opens the store — before any
// command's context exists — and reads one bounded local table, so a cancellation
// hook here would buy nothing and cost every NewContainer caller a parameter.
func readStoreSchemaState(dbHandle sqlitestore.DB) (storeSchemaState, error) {
	state, err := sqlitestore.ReadMigrationState(dbHandle, allMigrations())
	if err != nil {
		return storeSchemaState{}, fmt.Errorf("reading store schema state: %w", err)
	}
	return storeSchemaState{
		applied:  state.Applied,
		expected: len(allMigrations()),
		unknown:  state.Unknown,
	}, nil
}

// newerStoreError is the refusal an older binary owes a newer store, in the shape
// the config and policy schema gates already use: what is newer than what, and
// the remedy.
//
// It is a precondition failure, not a corrupt store — the store is intact and a
// current binary reads it fine — so it carries ExitConfig rather than
// ExitIntegrity. Nothing about the recorded evidence is in doubt; this binary is
// simply not the one that can operate on it.
func newerStoreError(dbPath string, state storeSchemaState) error {
	return &exitError{code: ExitConfig, msg: fmt.Sprintf(
		"store schema at %s is newer than supported: %d migration(s) applied that this binary does not know (%s); upgrade kanonarion. "+
			"Run `kanonarion store info` to inspect the store without writing to it",
		dbPath, len(state.unknown), strings.Join(state.unknown, ", "))}
}

func runStoreInfo(storeRoot string, jsonOut bool, stdout, _ io.Writer) error {
	absStore, err := filepath.Abs(storeRoot)
	if err != nil {
		return fmt.Errorf("resolving store root: %w", err)
	}
	dbPath := filepath.Join(absStore, "mirror.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("store not found at %s: run a kanonarion command to initialise it", dbPath)
	}

	// Open with no migrations — only initialises the infrastructure tables
	// (schema_migrations, _store_meta) without applying any domain migrations.
	// This keeps store info read-only with respect to domain schema changes, and
	// is what lets it still answer for a store this binary refuses to operate on:
	// the command an operator reaches for to diagnose the refusal must not be
	// subject to it.
	dbHandle, err := sqlitestore.Open(dbPath, nil)
	if err != nil {
		return fmt.Errorf("opening store at %s: %w", dbPath, err)
	}
	defer func() { _ = dbHandle.Close() }()

	state, err := readStoreSchemaState(dbHandle)
	if err != nil {
		return err
	}
	unknown := state.unknown
	appliedCount := state.applied
	expected := state.expected
	status := state.status()

	result := storeInfoResult{
		StoreRoot: absStore,
		DBPath:    dbPath,
		Applied:   appliedCount,
		Expected:  expected,
		Unknown:   unknown,
		Status:    status,
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return fmt.Errorf("encoding store info: %w", err)
		}
		return nil
	}

	if _, err := fmt.Fprintf(stdout, "store schema: v%d  binary expects: v%d  status: %s\n",
		appliedCount, expected, status); err != nil {
		return fmt.Errorf("writing store info: %w", err)
	}
	if len(unknown) > 0 {
		if _, err := fmt.Fprintf(stdout, "unknown migrations (store is from a newer binary — upgrade kanonarion):\n"); err != nil {
			return fmt.Errorf("writing store info: %w", err)
		}
		for _, u := range unknown {
			if _, err := fmt.Fprintf(stdout, "  %s\n", u); err != nil {
				return fmt.Errorf("writing store info: %w", err)
			}
		}
	}
	return nil
}
