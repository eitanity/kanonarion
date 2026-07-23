package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
	cmd.AddCommand(newStoreConfigCmd(stdout, stderr))
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

func newStoreConfigCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and manage the store configuration",
	}
	cmd.AddCommand(newStoreConfigShowCmd(stdout, stderr))
	return cmd
}

type configShowResult struct {
	Version          string             `json:"version"`
	Preferences      configPrefsResult  `json:"preferences"`
	LicensePolicy    configPolicyResult `json:"license_policy"`
	LicenseOverrides map[string]string  `json:"license_overrides"`
	Callgraph        configCGResult     `json:"callgraph"`

	// Unified supply-chain governance blocks (schema v2). Surfaced
	// in the effective-config view so the schema bump and the resolved
	// posture are observable by agentic consumers; rules are wired by the
	// directive and godebug policy blocks below.
	DirectivePolicy configDirectiveResult `json:"directive_policy"`
	GoDebugPolicy   configGoDebugResult   `json:"godebug_policy"`
	VendorPolicy    configVendorResult    `json:"vendor_policy"`
	FIPSPolicy      configFIPSResult      `json:"fips_policy"`
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

func newStoreConfigShowCmd(stdout, stderr io.Writer) *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStoreInfo(cmd.Context(), storeRoot, jsonOut, stdout, stderr)
		},
	}

	return cmd
}

func runStoreInfo(ctx context.Context, storeRoot string, jsonOut bool, stdout, _ io.Writer) error {
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
	// This keeps store info read-only with respect to domain schema changes.
	dbHandle, err := sqlitestore.Open(dbPath, nil)
	if err != nil {
		return fmt.Errorf("opening store at %s: %w", dbPath, err)
	}
	defer func() { _ = dbHandle.Close() }()

	rows, err := dbHandle.DB().QueryContext(ctx,
		`SELECT module, version FROM schema_migrations ORDER BY module, version`)
	if err != nil {
		return fmt.Errorf("querying schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type mv struct {
		module  string
		version int
	}
	var applied []mv
	for rows.Next() {
		var r mv
		if err := rows.Scan(&r.module, &r.version); err != nil {
			return fmt.Errorf("scanning schema_migrations: %w", err)
		}
		applied = append(applied, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading schema_migrations: %w", err)
	}

	known := make(map[string]struct{}, len(allMigrations()))
	for _, m := range allMigrations() {
		known[migrationKey(m.Module, m.Version)] = struct{}{}
	}

	var unknown []string
	for _, a := range applied {
		if _, ok := known[migrationKey(a.module, a.version)]; !ok {
			unknown = append(unknown, migrationKey(a.module, a.version))
		}
	}
	sort.Strings(unknown)

	expected := len(allMigrations())
	appliedCount := len(applied)

	var status string
	switch {
	case len(unknown) > 0:
		status = "newer"
	case appliedCount == expected:
		status = "ok"
	default:
		status = fmt.Sprintf("pending (%d of %d migrations applied)", appliedCount, expected)
	}

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

func migrationKey(module string, version int) string {
	return fmt.Sprintf("%s@v%d", module, version)
}
