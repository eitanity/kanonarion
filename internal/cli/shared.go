package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	configstore "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	"github.com/eitanity/kanonarion/internal/config/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	walkadapterpolicy "github.com/eitanity/kanonarion/internal/walk/adapters/policy/localfile"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// parseModuleArg splits "module[@version]" into path and version without
// validating the version. version is "" when no @ is present, "latest" when
// the caller passes @latest, or an unvalidated semver string otherwise.
// Callers must either validate the version or resolve it before use.
func parseModuleArg(arg string) (path, version string, err error) {
	if arg == "" {
		return "", "", fmt.Errorf("module path must not be empty")
	}
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		return arg, "", nil
	}
	if at == 0 {
		return "", "", fmt.Errorf("module path must not be empty")
	}
	return arg[:at], arg[at+1:], nil
}

func parseCoordinate(arg string) (fetchdomain.ModuleCoordinate, error) {
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		return fetchdomain.ModuleCoordinate{}, fmt.Errorf("expected module@version, got %q", arg)
	}
	path := arg[:at]
	version := arg[at+1:]
	coord, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		return fetchdomain.ModuleCoordinate{}, fmt.Errorf("invalid module coordinate: %w", err)
	}
	return coord, nil
}

// buildLogger constructs the logger for a command. The log format is taken
// from the single global --json flag, never a per-call argument, so every
// subsystem in one invocation emits exactly one format on stderr.
func buildLogger(level string, stderr io.Writer) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if jsonOut {
		return slog.New(slog.NewJSONHandler(stderr, opts))
	}
	return slog.New(slog.NewTextHandler(stderr, opts))
}

// loadPolicy resolves and loads the effective DepthPolicy for an invocation.
//
// Resolution order:
// 1. policyPath if non-empty — load from that explicit path.
// 2. Search for.kanonarion/policy.yaml from the current directory upward.
// 3. Fall back to DefaultDepthPolicy, logging at info level.
func loadPolicy(ctx context.Context, policyPath string, logger *slog.Logger) (walkdomain.DepthPolicy, string, error) {
	if policyPath == "" {
		policyPath = findPolicyFile()
	}
	if policyPath != "" {
		store := walkadapterpolicy.New(policyPath)
		result, err := store.LoadPolicy(ctx)
		if err != nil {
			if errors.Is(err, walkadapterpolicy.ErrPolicyNotFound) {
				// explicit path that doesn't exist is a user error
				return walkdomain.DepthPolicy{}, "", fmt.Errorf("policy file not found: %s", policyPath)
			}
			return walkdomain.DepthPolicy{}, "", fmt.Errorf("loading policy from %s: %w", policyPath, err)
		}
		logger.InfoContext(ctx, "policy.loaded",
			slog.String("source", result.Source),
			slog.String("version", result.Policy.Version),
			slog.String("hash", result.ContentHash),
		)
		return result.Policy, result.ContentHash, nil
	}

	logger.InfoContext(ctx, "policy.defaults", slog.String("reason", "no policy file found"))
	return walkdomain.DefaultDepthPolicy(), "", nil
}

// findPolicyFile searches from the current working directory upward for
// .kanonarion/policy.yaml, returning the first path found or empty string.
func findPolicyFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	const name = ".kanonarion/policy.yaml"
	for {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}


// readPackageModules runs "go list -deps" over pattern and returns the module
// coordinates ("path@version") of every non-standard-library package reachable
// from that pattern. This gives the exact set of modules linked into the binary
// produced by that package — dev, test, and tool-only dependencies that are in
// go.mod but not imported by the binary are excluded.
//
// Requires the go toolchain to be on PATH. Returns an error with a --walk-id
// hint if go is not found.
func readPackageModules(pattern string) ([]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-f", // #nosec G204 -- pattern is a Go package path from a developer CLI flag
		"{{if not .Standard}}{{.Module.Path}}@{{.Module.Version}}{{end}}", pattern)
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("go toolchain not found on PATH: use --walk-id to scope without requiring go")
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("go list %s: %s", pattern, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("go list %s: %w", pattern, err)
	}
	seen := make(map[string]bool)
	var coords []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Skip blank lines and the local module (no version suffix after @).
		if line == "" || strings.HasSuffix(line, "@") || seen[line] {
			continue
		}
		seen[line] = true
		coords = append(coords, line)
	}
	sort.Strings(coords)
	return coords, nil
}

// depScope selects which dependency set a go.mod-walking command operates on.
// Every such command exposes the same three scopes, so a question like "is there
// vulnerable code in my project?" resolves to the same module set regardless of
// which command asks it.
type depScope string

const (
	// scopeCode is the default: the modules the project's own code builds against,
	// including test code (`go list -deps -test ./...`). It equals the modules
	// linked into the binary plus test-only dependencies — the fast, high-value
	// triage set for "is there vulnerable code / what licences / whose copyright
	// in my project".
	scopeCode depScope = "code"
	// scopeTool is the tooling supply chain: the import closure of the go.mod
	// `tool` directives (Go 1.24+) — linters, generators, `go tool` binaries.
	scopeTool depScope = "tool"
	// scopeComplete is build + tooling: the full Go build list (`go list -m all`).
	scopeComplete depScope = "complete"
)

// scopeFromFlags maps the shared --tool/--project booleans to a depScope. The
// two are mutually exclusive; with neither set the scope is code (the default).
func scopeFromFlags(tool, project bool) (depScope, error) {
	if tool && project {
		return "", fmt.Errorf("--tool and --project are mutually exclusive")
	}
	switch {
	case tool:
		return scopeTool, nil
	case project:
		return scopeComplete, nil
	default:
		return scopeCode, nil
	}
}

// goListModuleFmt is the `go list -f` template emitting "path@version" for a
// non-standard package's module, and nothing for standard-library packages or
// the main module (whose Version is empty).
const goListModuleFmt = `{{if .Module}}{{if and (not .Standard) .Module.Version}}{{.Module.Path}}@{{.Module.Version}}{{end}}{{end}}`

// resolveScopeModules returns the "path@version" module coordinates for scope,
// resolved by the Go toolchain in the directory containing gomodPath. The main
// module and local-replace targets (which carry no version) are excluded.
// Requires `go` on PATH; the error names the absence so callers can hint.
//
// This is the single definition of each scope, shared by every go.mod-walking
// command so they answer the same question with the same set.
func resolveScopeModules(gomodPath string, scope depScope) ([]string, error) {
	dir := filepath.Dir(gomodPath)
	switch scope {
	case scopeComplete:
		return goListBuildList(dir)
	case scopeTool:
		toolPkgs, err := readGoModToolPackages(gomodPath)
		if err != nil {
			return nil, err
		}
		if len(toolPkgs) == 0 {
			return nil, nil
		}
		return goListDeps(dir, toolPkgs, false)
	case scopeCode:
		return goListDeps(dir, []string{"./..."}, true)
	default:
		return nil, fmt.Errorf("unknown dependency scope %q", scope)
	}
}

// goListDeps runs `go list -deps [-test] -f <module> <patterns>` in dir and
// returns the de-duplicated, sorted module coordinates of every non-standard,
// non-main package reachable from the patterns. withTest includes test imports.
func goListDeps(dir string, patterns []string, withTest bool) ([]string, error) {
	args := []string{"list", "-deps"}
	if withTest {
		args = append(args, "-test")
	}
	args = append(args, "-f", goListModuleFmt)
	args = append(args, patterns...)
	return runGoListCoords(dir, args)
}

// goListBuildList runs `go list -m all` in dir and returns the de-duplicated,
// sorted coordinates of every module in the build list except the main module
// and local-replace targets (no version).
func goListBuildList(dir string) ([]string, error) {
	return runGoListCoords(dir, []string{
		"list", "-m", "-mod=readonly",
		"-f", `{{if and (not .Main) .Version}}{{.Path}}@{{.Version}}{{end}}`,
		"all",
	})
}

// runGoListCoords executes `go <args>` in dir and parses its line-oriented
// "path@version" output into a sorted, de-duplicated slice. Blank lines (emitted
// by the templates for skipped packages) are dropped.
func runGoListCoords(dir string, args []string) ([]string, error) {
	cmd := exec.Command("go", args...) // #nosec G204 -- args are ./..., go.mod tool directive package paths, or the fixed `list -m all`
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("go toolchain not found on PATH: required to resolve the dependency scope")
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("go %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	seen := make(map[string]bool)
	var coords []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, "@") || seen[line] {
			continue
		}
		seen[line] = true
		coords = append(coords, line)
	}
	sort.Strings(coords)
	return coords, nil
}

// coordsToPaths strips the @version suffix from "path@version" coordinates,
// returning a non-nil slice of module paths. Non-nil matters for graph scoping:
// an empty (but non-nil) keep-set filters to the main anchor only, whereas nil
// means "no restriction" (the complete scope).
func coordsToPaths(coords []string) []string {
	paths := make([]string, 0, len(coords))
	for _, c := range coords {
		if i := strings.LastIndex(c, "@"); i >= 0 {
			paths = append(paths, c[:i])
		} else {
			paths = append(paths, c)
		}
	}
	return paths
}

// readGoModToolPackages parses a go.mod file and returns the package paths listed
// in its `tool` directives (Go 1.24+), in declaration order.
func readGoModToolPackages(gomodPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod %q: %w", gomodPath, err)
	}
	f, err := modfile.Parse(gomodPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod %q: %w", gomodPath, err)
	}
	pkgs := make([]string, 0, len(f.Tool))
	for _, t := range f.Tool {
		pkgs = append(pkgs, t.Path)
	}
	return pkgs, nil
}

// readGoModModules parses a go.mod file and returns all required module
// coordinates as "path@version" strings. Indirect dependencies are included.
func readGoModModules(gomodPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod %q: %w", gomodPath, err)
	}
	f, err := modfile.Parse(gomodPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod %q: %w", gomodPath, err)
	}
	coords := make([]string, 0, len(f.Require))
	for _, req := range f.Require {
		coords = append(coords, req.Mod.Path+"@"+req.Mod.Version)
	}
	return coords, nil
}

// readGoModulePath parses a go.mod file and returns its declared module
// path (the `module` directive). Used by the local-analysis command to
// derive the working tree's module path.
func readGoModulePath(gomodPath string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return "", fmt.Errorf("reading go.mod %q: %w", gomodPath, err)
	}
	f, err := modfile.Parse(gomodPath, data, nil)
	if err != nil {
		return "", fmt.Errorf("parsing go.mod %q: %w", gomodPath, err)
	}
	if f.Module == nil || f.Module.Mod.Path == "" {
		return "", fmt.Errorf("go.mod %q has no module path", gomodPath)
	}
	return f.Module.Mod.Path, nil
}

// readGoModToolModules parses a go.mod file and returns the module coordinates
// for all tool directive entries (Go 1.24+) as "modulePath@version" strings.
// A tool path like "golang.org/x/tools/cmd/stringer" is resolved to its parent
// module ("golang.org/x/tools") via longest-prefix match against require entries.
// In Go workspace setups, if a tool's module is not found in the local go.mod,
// the function walks upward to find a go.work file and merges require entries
// from each use-listed module's go.mod (go.mod entries take precedence).
func readGoModToolModules(gomodPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(gomodPath))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod %q: %w", gomodPath, err)
	}
	f, err := modfile.Parse(gomodPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod %q: %w", gomodPath, err)
	}
	if len(f.Tool) == 0 {
		return nil, nil
	}
	reqVersions := make(map[string]string, len(f.Require))
	for _, req := range f.Require {
		reqVersions[req.Mod.Path] = req.Mod.Version
	}

	// Quick check: if any tool path is unresolved, try workspace fallback.
	needsWorkspace := false
	for _, t := range f.Tool {
		if _, ver := resolveToolModule(t.Path, reqVersions); ver == "" {
			needsWorkspace = true
			break
		}
	}
	var goworkPath string
	if needsWorkspace {
		if p, found := findGoWork(filepath.Dir(filepath.Clean(gomodPath))); found {
			goworkPath = p
			if merr := mergeWorkspaceRequires(goworkPath, reqVersions); merr != nil {
				return nil, merr
			}
		}
	}

	seen := make(map[string]bool)
	coords := make([]string, 0, len(f.Tool))
	for _, t := range f.Tool {
		modPath, ver := resolveToolModule(t.Path, reqVersions)
		if ver == "" {
			if goworkPath != "" {
				return nil, fmt.Errorf("tool %q in %s has no matching require directive (go.work %s also checked)", t.Path, gomodPath, goworkPath)
			}
			return nil, fmt.Errorf("tool %q in %s has no matching require directive", t.Path, gomodPath)
		}
		coord := modPath + "@" + ver
		if !seen[coord] {
			seen[coord] = true
			coords = append(coords, coord)
		}
	}
	return coords, nil
}

// findGoWork walks upward from dir looking for a go.work file, stopping at the
// filesystem root. Returns the path and true if found.
func findGoWork(dir string) (string, bool) {
	for {
		candidate := filepath.Join(dir, "go.work")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// mergeWorkspaceRequires parses a go.work file, reads the go.mod of each
// use-listed module, and merges their require entries into reqVersions.
// Existing keys are not overwritten (go.mod takes precedence).
func mergeWorkspaceRequires(goworkPath string, reqVersions map[string]string) error {
	data, err := os.ReadFile(filepath.Clean(goworkPath))
	if err != nil {
		return fmt.Errorf("reading go.work %q: %w", goworkPath, err)
	}
	wf, err := modfile.ParseWork(goworkPath, data, nil)
	if err != nil {
		return fmt.Errorf("parsing go.work %q: %w", goworkPath, err)
	}
	workDir := filepath.Dir(goworkPath)
	for _, use := range wf.Use {
		modPath := filepath.Join(workDir, use.Path, "go.mod")
		mdata, merr := os.ReadFile(filepath.Clean(modPath))
		if merr != nil {
			continue // best-effort: skip unreadable modules
		}
		mf, merr := modfile.Parse(modPath, mdata, nil)
		if merr != nil {
			continue
		}
		for _, req := range mf.Require {
			if _, exists := reqVersions[req.Mod.Path]; !exists {
				reqVersions[req.Mod.Path] = req.Mod.Version
			}
		}
	}
	return nil
}

// resolveToolModule finds the module path and version for a tool path by
// longest-prefix match against the require map. For example,
// "golang.org/x/tools/cmd/stringer" matches module "golang.org/x/tools".
func resolveToolModule(toolPath string, reqVersions map[string]string) (modPath, version string) {
	if ver, ok := reqVersions[toolPath]; ok {
		return toolPath, ver
	}
	best := ""
	bestVer := ""
	for mp, ver := range reqVersions {
		if strings.HasPrefix(toolPath, mp+"/") && len(mp) > len(best) {
			best = mp
			bestVer = ver
		}
	}
	return best, bestVer
}

// storeRoot is the effective store directory for the current invocation.
// Bound to --store-root on the root command; the env-var override
// (KANONARION_STORE) is applied in root's PersistentPreRunE.
var storeRoot string

// logLevel is the effective log verbosity for the current invocation.
// Bound to --log-level on the root command.
var logLevel string

// jsonOut controls whether commands emit output as JSON.
// Bound to --json on the root command as a persistent flag.
var jsonOut bool

// activeConfig holds the resolved configuration for the current invocation.
// Loaded in PersistentPreRunE after store-root is resolved.
// Flag values override the corresponding config fields (flag > config > default).
var activeConfig domain.Config

// loadStoreConfig loads and returns the parsed Config from
// <storeRoot>/config.yaml. It never creates or modifies that file: an absent
// file resolves to DefaultConfig, and any key the user has not explicitly
// written resolves to its live built-in default at parse time. This keeps
// read-only commands side-effect-free and ensures built-in default changes
// propagate to existing stores rather than being frozen to disk on first
// touch. The config file is materialised only by `config set`. Falls back to
// DefaultConfig on any load error.
func loadStoreConfig(root string) domain.Config {
	configPath := filepath.Join(root, "config.yaml")
	store := configstore.New(configPath)
	cfg, err := store.LoadConfig(context.Background())
	if err != nil {
		return domain.DefaultConfig()
	}
	return cfg
}

// defaultStoreRoot returns the default store root path (~/.kanonarion).
// Falls back to ".kanonarion" if the home directory cannot be determined.
//
// Test isolation: in-process Run calls from package cli unit
// tests that omit --store-root must never reach the developer's real
// ~/.kanonarion. That is enforced by TestMain (main_test.go) pointing
// KANONARION_STORE at a throwaway temp dir for the whole test binary, so
// this function is left environment-pure and is not test-aware. The
// testscript suite lives in a separate package and runs the CLI as
// subprocesses with HOME set to its sandbox, so it is unaffected.
func defaultStoreRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".kanonarion"
	}
	return filepath.Join(home, ".kanonarion")
}

// resolveGoModPath returns the effective go.mod path to use for a command.
// If explicit is non-empty it is returned as-is. Otherwise./go.mod is
// stat-checked; if present that path is returned. If neither is available an
// error is returned so callers can give a clear message without silently
// falling through.
func resolveGoModPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	const defaultPath = "./go.mod"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}
	return "", fmt.Errorf("no --gomod specified and ./go.mod not found in current directory")
}

// projectModulePathFromGoMod reads goModPath and returns the declared module
// path. Used by commands that infer a project identifier when the
// caller did not pass one explicitly.
func projectModulePathFromGoMod(goModPath string) (string, error) {
	data, err := os.ReadFile(goModPath) // #nosec G304 — go.mod paths are caller-supplied via --gomod or the cwd default
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", goModPath, err)
	}
	mod := modfile.ModulePath(data)
	if mod == "" {
		return "", fmt.Errorf("no module directive in %s", goModPath)
	}
	return mod, nil
}

// exitError carries a specific exit code through cobra's error return.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// ExitCodeFromError reports the exit code carried by err's chain, if any.
// Used by main to translate categorised errors (e.g. ExitNotFound) into
// distinct process exit codes rather than the catch-all ExitConfig.
func ExitCodeFromError(err error) (int, bool) {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code, true
	}
	return 0, false
}
