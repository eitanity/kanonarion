package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	configstore "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	"github.com/eitanity/kanonarion/internal/config/domain"
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licenceports "github.com/eitanity/kanonarion/internal/license/ports"
	stdlibports "github.com/eitanity/kanonarion/internal/stdlib/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkadapterpolicy "github.com/eitanity/kanonarion/internal/walk/adapters/policy/localfile"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
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

func parseCoordinate(arg string) (coordinate.ModuleCoordinate, error) {
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("expected module@version, got %q", arg)
	}
	path := arg[:at]
	version := arg[at+1:]
	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		return coordinate.ModuleCoordinate{}, fmt.Errorf("invalid module coordinate: %w", err)
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
		return applyConfigVCSHosts(ctx, result.Policy, logger), result.ContentHash, nil
	}

	logger.InfoContext(ctx, "policy.defaults", slog.String("reason", "no policy file found"))
	return applyConfigVCSHosts(ctx, walkdomain.DefaultDepthPolicy(), logger), "", nil
}

// applyConfigVCSHosts overlays the store config's fetch_policy.allowed_vcs_hosts
// onto the resolved depth policy when the policy file did not set it.
//
// The depth policy file wins where both speak. It is the narrower, per-project
// artefact, and it is the one whose content hash is recorded on the walk — an
// operator who wrote allowed_vcs_hosts into it has said something specific
// about this project, and a machine-level default must not quietly override it.
// Where the policy file is silent, the config supplies the operator's standing
// answer instead of leaving the built-in advisory set to apply by default.
//
// Setting it here rather than at each use site means the value flows into the
// same StageDepth every command already reads, so `walk`, `fetch`, `audit` and
// `inspect` cannot drift apart on which forges they will contact.
func applyConfigVCSHosts(ctx context.Context, p walkdomain.DepthPolicy, logger *slog.Logger) walkdomain.DepthPolicy {
	hosts := activeConfig.FetchPolicy.AllowedVCSHosts
	if len(hosts) == 0 {
		return p
	}
	fetch := p.FetchStage()
	if fetch.AllowedVCSHosts != nil {
		logger.InfoContext(ctx, "policy.vcs_hosts.policy_file_wins",
			slog.Int("config_hosts", len(hosts)))
		return p
	}
	// Copy before writing: DepthPolicy carries a map, and callers hold the
	// default policy value in package state.
	stages := make(map[string]walkdomain.StageDepth, len(p.Stages)+1)
	for k, v := range p.Stages {
		stages[k] = v
	}
	fetch.AllowedVCSHosts = &hosts
	stages["fetch"] = fetch
	p.Stages = stages
	logger.InfoContext(ctx, "policy.vcs_hosts.from_config", slog.Int("hosts", len(hosts)))
	return p
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
	for line := range strings.SplitSeq(string(out), "\n") {
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
//
// It returns the test axis it applied alongside the set, so a caller cannot
// state one axis and resolve another: the disclosure and the resolution come out
// of the same call. The two -deps scopes default differently on that axis, and
// correctly so — see testScopeFor, which is the only place the axis is decided.
func resolveScopeModules(gomodPath string, scope depScope, excludeTests bool) ([]string, scopeResolution, error) {
	res := newScopeResolution(scope, excludeTests)
	args, err := scopeGoListArgs(gomodPath, scope, res.Tests)
	if err != nil {
		return nil, res, err
	}
	if args == nil {
		// The tool scope with no tool directives: an empty set, resolved without
		// asking the toolchain a question about no packages.
		return nil, res, nil
	}
	coords, err := runGoListCoords(filepath.Dir(gomodPath), args)
	return coords, res, err
}

// scopeGoListArgs is the `go list` invocation a scope and a test axis resolve to,
// or nil args for a tool scope with no tool directives to close over.
//
// It is separated from running it because this IS the scope: which invocation a
// scope produces is the whole of what distinguishes the three, and it is the half
// the two -deps scopes silently disagreed on — code passed -test and tool did
// not, so --tool moved the closure and the test axis at once. Separated, that
// decision can be exercised without a toolchain, a module cache or a network.
func scopeGoListArgs(gomodPath string, scope depScope, ts testScope) ([]string, error) {
	switch scope {
	case scopeComplete:
		return []string{
			"list", "-m", "-mod=readonly",
			"-f", `{{if and (not .Main) .Version}}{{.Path}}@{{.Version}}{{end}}`,
			"all",
		}, nil
	case scopeTool:
		toolPkgs, err := readGoModToolPackages(gomodPath)
		if err != nil {
			return nil, err
		}
		if len(toolPkgs) == 0 {
			return nil, nil
		}
		return goListDepsArgs(toolPkgs, ts), nil
	case scopeCode:
		return goListDepsArgs([]string{"./..."}, ts), nil
	default:
		return nil, fmt.Errorf("unknown dependency scope %q", scope)
	}
}

// goListDepsArgs builds `go list -deps [-test] -f <module> <patterns>`. The -test
// flag comes from the axis and from nothing else, so the decision lives in
// testScopeFor rather than being spelled again at each resolution.
func goListDepsArgs(patterns []string, ts testScope) []string {
	args := []string{"list", "-deps"}
	if ts.withTests() {
		args = append(args, "-test")
	}
	args = append(args, "-f", goListModuleFmt)
	return append(args, patterns...)
}

// runGoList executes `go <args>` in dir and returns its raw stdout. The absence
// of the toolchain is named rather than reported as a generic exec failure, and
// a non-zero exit carries the toolchain's own stderr, which says more about a
// broken module graph than any message this could invent.
func runGoList(dir string, args []string) ([]byte, error) {
	cmd := exec.Command("go", args...) // #nosec G204 -- args are ./..., a Go package pattern from a developer CLI flag, go.mod tool directive package paths, or the fixed `list -m all`
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
	return out, nil
}

// runGoListCoords executes `go <args>` in dir and parses its line-oriented
// "path@version" output into a sorted, de-duplicated slice. Blank lines (emitted
// by the templates for skipped packages) are dropped.
func runGoListCoords(dir string, args []string) ([]string, error) {
	out, err := runGoList(dir, args)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var coords []string
	for line := range strings.SplitSeq(string(out), "\n") {
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
	// Map order cannot reach the answer: two distinct keys of the same length
	// cannot both be a prefix of one path, so the longest match is unique and
	// `len > len(best)` never ties.
	for mp, ver := range reqVersions {
		if strings.HasPrefix(toolPath, mp+"/") && len(mp) > len(best) {
			best = mp
			bestVer = ver
		}
	}
	return best, bestVer
}

// resetInvocationState puts the process-wide state a command DERIVES back to
// what a fresh invocation starts from. newRootCmd calls it, so it runs once
// per Run.
//
// The flag-BOUND variables (storeRoot, logLevel, jsonOut,
// allowVerificationDowngrade) are absent because they need no help:
// StringVar/BoolVar assign the flag's default at registration, and newRootCmd
// registers every flag on every invocation. The ones below are written by a
// resolve* helper or by PersistentPreRunE, and a helper that is not called
// leaves the previous command's value in place. Three call sites reach
// resolveModcacheMode; sixty-odd reach NewContainer, which reads modcacheMode.
//
// cliClock is deliberately absent for the opposite reason: it is the test seam
// SetClockForTest pins BEFORE the invocation runs, and resetting it here would
// unpin every golden.
func resetInvocationState() {
	modcacheMode, modcacheDir, goSumPath = false, "", ""
	projectGoSumPath = ""
	// The built-in defaults, which is what a store with no config file loads —
	// never the previous store's policy.
	activeConfig, activeConfigErr = domain.DefaultConfig(), nil
	// The safe default, so an invocation that never reaches PersistentPreRunE
	// cannot inherit the last one's permission to create a store.
	storeIntent = StoreIntentRead
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

// activeConfigErr holds the rejection when the store has a config file that
// could not be loaded. It is nil in the two ordinary cases — no file, or a file
// that loaded — so it is never a stand-in for "these are the built-in
// defaults". A store with no config file loads DefaultConfig with no error and
// runs the full built-in policy, exactly as before.
//
// It is set alongside activeConfig so a command exempted from the refusal (see
// annotationUsableWithRejectedConfig) can state the rejection instead of
// pretending the file is in force.
var activeConfigErr error

// annotationUsableWithRejectedConfig marks a command that must keep running
// when the store's config file has been rejected, because that command is part
// of seeing or repairing the file. Every other command refuses, so the tool
// never produces evidence under a policy the operator did not write.
//
// It is a cobra annotation rather than a name list in the root command so the
// exemption is declared where the command is defined, next to the reason it
// qualifies, and a new config-repair command carries it without editing a
// second file.
//
// A command qualifies on one test: with the file rejected, would refusing it
// leave the operator unable to see the problem or fix it? `--help` and
// `--version` need no annotation — cobra answers both before any PersistentPreRunE
// runs, so they were never gated in the first place.
const annotationUsableWithRejectedConfig = "kanonarion/usable-with-rejected-config"

// usableWithRejectedConfig reports whether cmd carries the exemption.
func usableWithRejectedConfig(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd.Annotations[annotationUsableWithRejectedConfig]
	return ok
}

// annotationStoreIntent is what a command says about the store root: whether
// running it may bring that directory into existence.
//
// It is declared per command, next to the command, for the same reason the
// rejected-config exemption is: the decision belongs where a reader of the
// command can see it, and adding a command must not mean editing a list in a
// second file.
//
// The default — no annotation, or one this build does not recognise — is
// StoreIntentRead, which refuses. A command added without a decision then
// fails safe instead of silently minting a store under whatever path the
// caller typed.
const annotationStoreIntent = "kanonarion/store-intent"

// The values annotationStoreIntent takes. A command declares exactly one.
const (
	// StoreIntentRead answers from records some other run wrote. It must not
	// create the store root: a root created by a read answers "nothing
	// recorded here", which is true of the empty store it just made and false
	// about the store the caller meant.
	//
	// A command that writes but cannot be the first command against a store —
	// `store clean` has nothing to clean, and every extract needs a walk —
	// declares read as well. What the value governs is creation, not writing.
	StoreIntentRead = "read"
	// StoreIntentCreate writes records, so it creates the root when it is
	// absent. A first fetch, walk, extract or inspect on a clean machine must
	// not need a preparatory step.
	StoreIntentCreate = "create"
	// StoreIntentNone touches no store at all, so neither answer applies:
	// refusing it for a store root it never opens would be a refusal with no
	// subject. Only the commands that genuinely open nothing qualify.
	StoreIntentNone = "none"
)

// storeIntentOf returns the intent cmd declared, or StoreIntentRead when it
// declared nothing or declared a value this build does not know.
func storeIntentOf(cmd *cobra.Command) string {
	if cmd == nil {
		return StoreIntentRead
	}
	switch v := cmd.Annotations[annotationStoreIntent]; v {
	case StoreIntentCreate, StoreIntentNone:
		return v
	default:
		return StoreIntentRead
	}
}

// storeIntent is the intent the command running in this invocation declared,
// resolved in root's PersistentPreRunE once and read by every store-opening
// seam below it. It lives alongside storeRoot and activeConfig because it is
// the same kind of fact: one property of this invocation, resolved from the
// command line before any command body runs.
//
// It is derived from the annotation rather than passed at each NewContainer
// call so there is one declaration per command and no second place for it to
// disagree with itself.
var storeIntent = StoreIntentRead

// storeOpenIntent maps this invocation's declared intent onto what the sqlite
// layer is allowed to do about a missing directory.
func storeOpenIntent() sqlitestore.Intent {
	if storeIntent == StoreIntentCreate {
		return sqlitestore.IntentCreate
	}
	return sqlitestore.IntentRead
}

// missingStoreError is a read aimed at a store root that is not there. It names
// the path it looked at — the whole failure mode is a path the caller did not
// mean — and the command that would create a store there.
type missingStoreError struct {
	root string
}

func (e *missingStoreError) Error() string {
	return fmt.Sprintf("no store at %s\n"+
		"  this command reads recorded evidence; it does not create a store, so nothing was written there\n"+
		"  to create one and record the module set: kanonarion inspect --store-root %s",
		e.root, e.root)
}

// requireStoreRoot refuses an invocation whose store root does not exist, for
// every command that did not declare it creates one.
//
// It runs before anything opens the store, so the refusal costs no directory:
// the defect it closes is a read that answers from a store it made a
// millisecond earlier, and a check that fires after the open would still leave
// the directory behind.
func requireStoreRoot(root string) error {
	if storeIntent == StoreIntentCreate || storeIntent == StoreIntentNone {
		return nil
	}
	info, err := os.Stat(root)
	if err == nil {
		if !info.IsDir() {
			return &exitError{code: ExitConfig, msg: fmt.Sprintf("store root %s is not a directory", root)}
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf("checking store root %s: %v", root, err)}
	}
	return &exitError{code: ExitConfig, msg: (&missingStoreError{root: root}).Error()}
}

// rejectedConfigError is a config file that exists but cannot be turned into a
// configuration. It names the file, the loader's own rejection, and the repair
// path, because the operator's next action is to edit one line of that file.
type rejectedConfigError struct {
	path  string
	cause error
}

func (e *rejectedConfigError) Error() string {
	return fmt.Sprintf("config file %s was rejected: %v\n"+
		"  nothing in that file is in force; the built-in defaults would apply instead\n"+
		"  fix the named value, then re-run. To see the file and this rejection: kanonarion config show\n"+
		"  To rewrite one key: kanonarion config set <key> <value>",
		e.path, e.cause)
}

func (e *rejectedConfigError) Unwrap() error { return e.cause }

// configRejectionReason returns the loader's own rejection sentence for this
// invocation, or "" when the config file loaded (or there is none). It is the
// cause alone, without the repair advice the refusal message carries, because
// its callers are views that surround it with their own framing.
func configRejectionReason() string {
	if activeConfigErr == nil {
		return ""
	}
	if rej, ok := errors.AsType[*rejectedConfigError](activeConfigErr); ok {
		return rej.cause.Error()
	}
	return activeConfigErr.Error()
}

// modcacheMode, modcacheDir, and goSumPath carry --from-modcache state across
// the audit/sbom orchestration. They are process-wide because a single audit
// or sbom invocation builds several Containers (walk, extract, vuln-scan), each
// through NewContainer, and every one must wire the same module-cache adapters.
// modcacheMode is false by default, leaving the network+blobstore path
// byte-for-byte unchanged.
var (
	modcacheMode bool
	modcacheDir  string
	goSumPath    string
)

// projectGoSumPath is the walk root's go.sum path for the NORMAL (network)
// fetch path. When set and the file exists, NewContainer layers a local go.sum
// verifier onto the fetch use case as an always-on, offline complement to the
// network checksum database. Empty leaves the network path's
// verification unchanged. It is process-wide for the same reason modcacheMode
// is: a single audit/sbom invocation builds several Containers, each of which
// must wire the same verifier. Distinct from --from-modcache (goSumPath), where
// go.sum is the sole anchor.
var projectGoSumPath string

// resolveProjectGoSum records the walk root's go.sum path for the normal fetch
// path, derived from the resolved gomodPath. A missing go.sum leaves the path
// empty: on the normal path go.sum is an optional complement, so its absence
// simply means the cross-check never fires (unlike --from-modcache, where a
// missing go.sum is a hard error). It is a no-op in --from-modcache mode, which
// threads go.sum via resolveModcacheMode/goSumPath instead. Idempotent.
//
// Every path here ASSIGNS, including the two that select no file. Leaving the
// variable alone would let a project whose go.sum is absent verify against the
// go.sum of whatever project the previous invocation resolved.
func resolveProjectGoSum(gomodPath string) {
	if modcacheMode {
		projectGoSumPath = ""
		return
	}
	goSum := filepath.Join(filepath.Dir(gomodPath), "go.sum")
	if _, err := os.Stat(goSum); err != nil {
		projectGoSumPath = ""
		return
	}
	projectGoSumPath = goSum
}

// allowVerificationDowngrade carries --allow-verification-downgrade across the
// audit/sbom/walk orchestration, process-wide for the same reason modcacheMode
// is: one invocation builds several Containers and every fetch use case they
// wire must agree. False by default, which is what keeps a weaker
// re-measurement from displacing a stronger stored record.
var allowVerificationDowngrade bool

// registerAllowVerificationDowngradeFlag adds --allow-verification-downgrade to
// cmd, binding it to the process-wide state the containers read. It is
// deliberately a separate flag from --force: forcing means "re-measure now", and
// overloading it with "and accept a weaker anchor" is the conflation that let a
// --from-modcache run demote records a network run had anchored to the
// transparency log.
func registerAllowVerificationDowngradeFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&allowVerificationDowngrade, "allow-verification-downgrade", false,
		"permit a re-measurement to REPLACE A STRONGER VERIFICATION ANCHOR WITH A WEAKER ONE (e.g. let a --from-modcache record verified only against local go.sum overwrite one verified against the checksum-database transparency log); without this, the stronger record is kept and the run logs a warning")
}

// modcacheFlagSentinel is the NoOptDefVal for --from-modcache: it distinguishes
// "flag passed with no value" (use `go env GOMODCACHE`) from "flag absent"
// (empty string, mode off) and from an explicit directory value.
//
// pflag prints NoOptDefVal into help output verbatim, so the value has to be
// ordinary text. It also uses a NUL of its own to mark where a flag's usage
// column starts, so a NUL here both broke every text pipeline over help output
// and split the rendered line in the wrong place. The text is what a bare
// --from-modcache actually runs, which is why `--from-modcache dir[="go env
// GOMODCACHE"]` reads as documentation rather than as an internal token.
//
// A directory can be named anything, this string included, so resolveModcacheMode
// refuses rather than guesses when one exists under this exact name.
const modcacheFlagSentinel = "go env GOMODCACHE"

// registerFromModcacheFlag adds --from-modcache[=dir] to cmd, binding it to
// target. Passed bare it resolves the cache dir from `go env GOMODCACHE`; passed
// a value it names the directory. Absent, the flag leaves target empty.
func registerFromModcacheFlag(cmd *cobra.Command, target *string) {
	cmd.Flags().StringVar(target, "from-modcache", "",
		"source modules from an existing Go module cache instead of the network: verify against local go.sum and bypass the blob store (optional `dir`; defaults to the go env GOMODCACHE path)")
	cmd.Flags().Lookup("from-modcache").NoOptDefVal = modcacheFlagSentinel
}

// resolveModcacheMode configures the process-wide --from-modcache state from a
// flag value. flagVal is "" when the flag was absent (mode stays off), the
// sentinel when passed bare (dir resolves from `go env GOMODCACHE`), or an
// explicit cache directory. gomodPath locates the sibling go.sum used for
// hash verification. It is idempotent and safe to call once per invocation.
func resolveModcacheMode(flagVal, gomodPath string) error {
	if flagVal == "" {
		// Flag absent — the network + blob-store path, and it is CLEARED rather
		// than left alone. These are process-wide, and one process runs one
		// command in production, so the difference never showed there; in a test
		// binary that runs several commands it meant a later invocation silently
		// inherited --from-modcache from an earlier one and reported module
		// bytes it had not been asked to read. "Mode stays off" is what the
		// caller is entitled to assume, so make it true.
		modcacheMode, modcacheDir, goSumPath = false, "", ""
		return nil
	}
	dir := flagVal
	if dir == modcacheFlagSentinel {
		// The bare flag and an explicit --from-modcache="go env GOMODCACHE"
		// reach here as the same string. They differ only when a directory of
		// that literal name exists, and then the run stops rather than picking
		// one reading: no path becomes unreachable, since the same directory
		// can be named as "./go env GOMODCACHE" or absolutely.
		if info, serr := os.Stat(modcacheFlagSentinel); serr == nil && info.IsDir() {
			return fmt.Errorf("--from-modcache: %q names both this flag's bare default and a directory here; "+
				"pass %q or an absolute path to mean the directory",
				modcacheFlagSentinel, "."+string(os.PathSeparator)+modcacheFlagSentinel)
		}
		resolved, err := goEnvGOMODCACHE()
		if err != nil {
			return fmt.Errorf("--from-modcache: %w", err)
		}
		dir = resolved
	}
	if dir == "" {
		return fmt.Errorf("--from-modcache: could not determine module cache directory")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("--from-modcache: module cache %q is not an accessible directory", dir)
	}
	goSum := filepath.Join(filepath.Dir(gomodPath), "go.sum")
	if _, err := os.Stat(goSum); err != nil {
		return fmt.Errorf("--from-modcache: go.sum not found at %s (required for hash verification): %w", goSum, err)
	}
	modcacheMode = true
	modcacheDir = dir
	goSumPath = goSum
	return nil
}

// modcacheWalkGate turns a partial walk caused by module-cache/go.sum failures
// into a hard, non-zero exit. In --from-modcache mode the fetch pipeline fails a
// module whose h1 does not match go.sum, or which is absent from go.sum or the
// cache; the walker records that as a fetch_failed (or parse_failed) node rather
// than aborting. This gate collects those nodes and returns an ExitIntegrity
// error naming them, so `audit`/`sbom --package` exit non-zero on any
// verification failure. It is a no-op when mode is off or the walk is clean.
func modcacheWalkGate(rec walkdomain.WalkRecord, local coordinate.ModuleCoordinate) error {
	if !modcacheMode {
		return nil
	}
	var failed []string
	for _, node := range rec.Graph.Nodes {
		if node.Coordinate == local {
			continue
		}
		switch node.ResolutionSource {
		case walkdomain.ResolutionFetchFailed, walkdomain.ResolutionParseFailed:
			msg := node.Coordinate.String()
			if node.ErrorDetail != "" {
				msg += ": " + node.ErrorDetail
			}
			failed = append(failed, msg)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return &exitError{code: ExitIntegrity, msg: fmt.Sprintf(
		"--from-modcache: %d module(s) failed go.sum verification or could not be sourced from the module cache:\n  %s",
		len(failed), strings.Join(failed, "\n  "))}
}

// goSumWalkGate turns a go.sum tamper detected on the NORMAL (network) walk
// path into a hard, non-zero exit. When a project go.sum is present,
// the fetch pipeline fails a module whose fetched h1 disagrees with its go.sum
// entry; the walker records that as a fetch_failed node (with the tamper detail)
// rather than aborting. This gate scans for such nodes and returns an
// ExitIntegrity error naming them, so `audit`/`sbom --package` exit non-zero on
// a go.sum mismatch. Unlike modcacheWalkGate it fires ONLY on go.sum-mismatch
// failures, never on ordinary network fetch failures, which stay tolerated as a
// partial walk. It is a no-op in --from-modcache mode (modcacheWalkGate covers
// that path) and when the walk is clean.
func goSumWalkGate(rec walkdomain.WalkRecord, local coordinate.ModuleCoordinate) error {
	if modcacheMode {
		return nil
	}
	var failed []string
	for _, node := range rec.Graph.Nodes {
		if node.Coordinate == local {
			continue
		}
		if node.ResolutionSource != walkdomain.ResolutionFetchFailed {
			continue
		}
		// Only go.sum tamper failures are hard; match the shared sentinel so an
		// ordinary network fetch failure does not fail the command.
		if !strings.Contains(node.ErrorDetail, fetchapp.ErrGoSumVerification.Error()) {
			continue
		}
		msg := node.Coordinate.String()
		if node.ErrorDetail != "" {
			msg += ": " + node.ErrorDetail
		}
		failed = append(failed, msg)
	}
	if len(failed) == 0 {
		return nil
	}
	return &exitError{code: ExitIntegrity, msg: fmt.Sprintf(
		"%d module(s) failed local go.sum verification (tamper-evidence):\n  %s",
		len(failed), strings.Join(failed, "\n  "))}
}

// goEnvGOMODCACHE returns the effective module cache directory reported by
// `go env GOMODCACHE`.
func goEnvGOMODCACHE() (string, error) {
	cmd := exec.Command("go", "env", "GOMODCACHE") // #nosec G204 -- fixed, argument-free go invocation
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", fmt.Errorf("go toolchain not found on PATH: required to resolve GOMODCACHE")
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("go env GOMODCACHE: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("go env GOMODCACHE: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// loadStoreConfig loads and returns the parsed Config from
// <storeRoot>/config.yaml. It never creates or modifies that file: an absent
// file resolves to DefaultConfig, and any key the user has not explicitly
// written resolves to its live built-in default at parse time. This keeps
// read-only commands side-effect-free and ensures built-in default changes
// propagate to existing stores rather than being frozen to disk on first
// touch. The config file is materialised only by `config set`.
//
// A file that exists and cannot be loaded is returned as a rejection, not
// absorbed. The configuration that would be in force in that case — the
// built-in defaults — is returned alongside it, so a command entitled to carry
// on can report what is actually in force rather than what the file says. An
// absent file is not a rejection: the store adapter resolves it to
// DefaultConfig with no error, and that path is unchanged.
func loadStoreConfig(root string) (domain.Config, error) {
	configPath := filepath.Join(root, "config.yaml")
	store := configstore.New(configPath)
	cfg, err := store.LoadConfig(context.Background())
	if err != nil {
		return domain.DefaultConfig(), &rejectedConfigError{path: configPath, cause: err}
	}
	return cfg, nil
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

// writeArtefactFile writes a generated document to path and reports the path on
// notify, which is the whole of the --output contract two artefact generators
// (sbom, notice) share.
//
// It is one function rather than one per command because the semantics are the
// thing that must not drift: same permissions, same "wrote it, here is where"
// acknowledgement, same wrapped error naming the path that failed. notify is a
// parameter rather than a fixed stream because the two commands put it in
// different places on purpose — sbom's acknowledgement joins its ID/hash block
// on stdout, while notice keeps stdout clear of anything that is not the
// document and reports on stderr alongside its scope and review lines.
func writeArtefactFile(kind, path string, content []byte, notify io.Writer) error {
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("writing %s to %q: %w", kind, path, err)
	}
	if _, err := fmt.Fprintf(notify, "%s written to %s\n", kind, path); err != nil {
		return fmt.Errorf("writing %s acknowledgement: %w", kind, err)
	}
	return nil
}

// exitError carries a specific exit code through cobra's error return.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// proxyAdapterError renders a failure to build the module proxy for a command
// that was about to use it.
//
// An environment refusal — GOPROXY=off, or a GOPROXY naming a fetch route this
// build has not got — is passed through as the operator-facing sentence it
// already is, carrying ExitConfig explicitly rather than arriving there by the
// catch-all: the run never reached an answer because the environment said it
// must not, which is a precondition, and a script must be able to read that off
// the exit code. It is not prefixed with "creating proxy adapter", because
// nothing about the adapter is what the operator has to act on. A malformed
// proxy URL keeps the wiring prefix; that one IS about the adapter.
func proxyAdapterError(err error) error {
	if proxyadapter.IsRefusal(err) {
		return &exitError{code: ExitConfig, msg: err.Error()}
	}
	return fmt.Errorf("creating proxy adapter: %w", err)
}

// ExitCodeFromError reports the exit code carried by err's chain, if any.
// Used by main to translate categorised errors (e.g. ExitNotFound) into
// distinct process exit codes rather than the catch-all ExitConfig.
func ExitCodeFromError(err error) (int, bool) {
	if ee, ok := errors.AsType[*exitError](err); ok {
		return ee.code, true
	}
	return 0, false
}

// evidenceInDoubt is every sentinel meaning the recorded evidence cannot be
// trusted: a stored record whose content hash does not verify, or two records
// for one coordinate that disagree. The table gives both to ExitIntegrity and
// does not qualify either by which domain raised it.
//
// Only the walk sentinel was mapped, so the other twelve reached ExitConfig by
// the fallback — which says the invocation itself was wrong, and routes a
// store-integrity problem to whoever fixes broken command lines. A sentinel
// added to a ports package must be added here; the contract test reads the
// ports packages and fails if one is missing.
var evidenceInDoubt = []error{
	walkports.ErrWalkIntegrity,
	cgports.ErrCallGraphIntegrity, cgports.ErrCallGraphConflict,
	ifaceports.ErrInterfaceIntegrity, ifaceports.ErrInterfaceConflict,
	licenceports.ErrLicenceIntegrity, licenceports.ErrLicenceConflict,
	exampleports.ErrExampleIntegrity, exampleports.ErrExampleConflict,
	extractports.ErrExtractionRunIntegrity,
	vulnports.ErrVulnIntegrity, vulnports.ErrSnapshotIntegrity,
	stdlibports.ErrFactsIntegrity, stdlibports.ErrFactsConflict,
}

// ExitCodeForError maps a Run error onto the process exit code. It honours an
// explicit exit-code carrier on the chain first (so categories like ExitNotFound
// survive), then the evidence-in-doubt sentinels, and otherwise falls back to
// ExitConfig. Shared by every main package so the binary's exit semantics are
// defined once here rather than duplicated per entry point.
//
// A store-schema refusal — this binary meeting a store a newer one wrote — lands
// on ExitConfig, and does so by both routes: the CLI's own gate carries
// ExitConfig explicitly on the chain, and composition.ErrStoreSchemaNewer from
// the shared driver surface reaches the same code through the fallback. That is
// the intended classification, not an accident of the default: the store is
// intact and a current binary reads it fine, so it is a precondition failure and
// must not be reported as ExitIntegrity, which says the recorded evidence is in
// doubt.
func ExitCodeForError(err error) int {
	if err == nil {
		return ExitOK
	}
	if code, ok := ExitCodeFromError(err); ok {
		return code
	}
	for _, sentinel := range evidenceInDoubt {
		if errors.Is(err, sentinel) {
			return ExitIntegrity
		}
	}
	// A divergence — two records for one coordinate disagreeing on a hash they
	// both carry — is an integrity failure, not a configuration error. A
	// consuming command fails closed on it, matching modcacheWalkGate and
	// goSumWalkGate; a store-inspection command reports it and exits 0 (see
	// reportDivergence), so the tool used to diagnose the problem is not the one
	// that refuses to run.
	if _, ok := errors.AsType[*fetchdomain.Divergence](err); ok {
		return ExitIntegrity
	}
	return ExitConfig
}

// divergenceMessage renders err as an operator-facing divergence report,
// reporting whether it was a divergence at all.
//
// It is what a store-inspection command calls instead of failing: an operator
// diagnosing a contradictory store must be able to run the commands that
// describe it, so inspection reports the divergence and exits 0. Consuming
// commands take the other branch and fail closed via ExitCodeForError.
func divergenceMessage(err error) (string, bool) {
	var divergence *fetchdomain.Divergence
	if !errors.As(err, &divergence) {
		return "", false
	}
	return divergence.Error() +
		" — two measurements describe different artefacts; recover with --force," +
		" which appends an authoritative measurement and erases nothing", true
}

// unreadableRunEntry is one stored scan run a survey listed but could not
// verify: the row's identity and why it could not be read, kept apart so text
// and JSON output can each present them their own way.
type unreadableRunEntry struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// unreadableRunReport turns a scan-run listing error into one operator-facing
// entry per row the store could not verify, reporting whether it was that kind
// of failure at all.
//
// It is divergenceMessage's counterpart for the scan-run listings, and it is
// there for the same reason: a survey command reports what it could not read
// and exits 0, while a consuming command takes the other branch and fails
// closed. Any other error is not this one and is returned as not-handled, so a
// database that fell over still aborts the listing.
func unreadableRunReport(err error) ([]unreadableRunEntry, bool) {
	var unreadable *vulnports.UnreadableRuns
	if !errors.As(err, &unreadable) {
		return nil, false
	}
	entries := make([]unreadableRunEntry, 0, len(unreadable.Runs))
	for _, r := range unreadable.Runs {
		id := r.ID
		if id == "" {
			id = "(unidentified run)"
		}
		entries = append(entries, unreadableRunEntry{ID: id, Reason: unreadableRunReason(r)})
	}
	return entries, true
}

// scanRunStatusUnreadable is the status a survey reports for a row it listed
// but could not verify. It is deliberately not one of the domain's scan
// statuses: the run's status is exactly what is not known about it.
const scanRunStatusUnreadable = "unreadable"

// writeUnreadableRun reports a single run an inspection command was asked for
// and could not verify, and returns nil: naming what is wrong with the row is
// the answer to "show me this run", not a failure to answer.
//
// It reports the id the CALLER asked for. The stored bytes may not name
// themselves, and echoing an empty id back at someone who just typed one would
// lose the only identity in the exchange.
func writeUnreadableRun(stdout io.Writer, runID string, entries []unreadableRunEntry, asJSON bool) error {
	reason := "could not be verified"
	if len(entries) > 0 {
		reason = entries[0].Reason
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		}{ID: runID, Status: scanRunStatusUnreadable, Reason: reason}); err != nil {
			return fmt.Errorf("encoding unreadable scan run: %w", err)
		}
		return nil
	}
	_, _ = fmt.Fprintf(stdout, "ID:          %s\n", runID)
	_, _ = fmt.Fprintf(stdout, "Status:      %s\n", scanRunStatusUnreadable)
	_, _ = fmt.Fprintf(stdout, "Reason:      %s\n", reason)
	return nil
}

// writeUnreadableRuns prints one line per row the store could not verify, in
// the listing itself. Silence here would be the one answer that is not honest:
// an omitted row and a row reported as unreadable say different things about
// the store, and only the second is true of it.
func writeUnreadableRuns(stdout io.Writer, entries []unreadableRunEntry) {
	for _, e := range entries {
		_, _ = fmt.Fprintf(stdout, "%-26s  status=%-12s  %s\n", e.ID, scanRunStatusUnreadable, e.Reason)
	}
}

// unreadableRunReason says why a row could not be verified, in words a reader
// can act on.
//
// The two cases are not interchangeable and must not be reported alike. A
// record whose stored bytes still hash to the seal they carry has not been
// altered; this build simply cannot reproduce it, because it was sealed by an
// earlier canonical shape — the remedy is a re-scan. Where that cannot be
// established the wording stays neutral: an unverified record is reported as
// unverified, and nothing is insinuated about how it got that way.
func unreadableRunReason(r vulnports.UnreadableRun) string {
	if errors.Is(r.Reason, recordseal.ErrGenerationDrift) {
		return "sealed by an earlier record generation; re-scan to reseal"
	}
	return "could not be verified: " + r.Reason.Error()
}
