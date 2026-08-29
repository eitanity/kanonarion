package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	configyaml "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
	walkadapterpolicy "github.com/eitanity/kanonarion/internal/walk/adapters/policy/localfile"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newPolicyCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and validate depth-policy and governance policy files",
	}
	cmd.AddCommand(
		newPolicyValidateCmd(stdout),
		newPolicyShowCmd(stdout, stderr),
	)
	return cmd
}

// ---- policy validate ----

func newPolicyValidateCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:         "validate <path>",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentNone},
		Short:       "Validate a depth-policy or governance policy YAML file against its schema",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runPolicyValidate(cmd.Context(), args[0], jsonOut, stdout)
		},
	}
}

func runPolicyValidate(ctx context.Context, path string, asJSON bool, stdout io.Writer) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &exitError{code: ExitConfig, msg: fmt.Sprintf("policy file not found: %s", path)}
		}
		return fmt.Errorf("stat policy path: %w", err)
	}
	if info.IsDir() {
		return runPolicyValidateDir(ctx, path, asJSON, stdout)
	}
	return runPolicyValidateFile(path, asJSON, stdout)
}

// governanceMarkers are the top-level keys that identify a config-schema
// governance file as opposed to a depth-policy file. `policy
// validate` routes to the matching schema so the two coherent schemas stay
// independently validated rather than one leniently accepting the other.
var governanceMarkers = []string{
	"license_policy", "directive_policy", "godebug_policy",
	"vendor_policy", "fips_policy", "preferences", "license_overrides",
	"copyright_declarations",
}

// policyValidation is one file's outcome. Results are collected before
// anything is written so --json can emit exactly one array across a whole
// directory; the error is kept as a value, not a string, because the caller
// still returns it and the exit code is read off it.
type policyValidation struct {
	path   string
	schema string
	err    error
}

// policyValidationJSON is one row of the --json array. The schema is empty
// only when the file could not be read, so no schema was ever chosen.
type policyValidationJSON struct {
	File   string `json:"file"`
	Schema string `json:"schema"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

func writePolicyValidateJSON(w io.Writer, results []policyValidation) error {
	out := make([]policyValidationJSON, 0, len(results))
	for _, r := range results {
		row := policyValidationJSON{File: r.path, Schema: r.schema, Passed: r.err == nil}
		if r.err != nil {
			row.Error = r.err.Error()
		}
		out = append(out, row)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding policy validation JSON: %w", err)
	}
	return nil
}

func validatePolicyFile(path string) policyValidation {
	res := policyValidation{path: path}
	data, err := os.ReadFile(path) /* #nosec G304 -- operator-supplied path is intentional */
	if err != nil {
		res.err = fmt.Errorf("reading policy file: %w", err)
		return res
	}

	res.schema = "depth-policy"
	var validateErr error
	if isGovernanceSchema(data) {
		res.schema = "governance"
		_, validateErr = configyaml.Parse(data)
	} else {
		_, validateErr = walkadapterpolicy.Parse(data)
	}
	if validateErr != nil {
		res.err = fmt.Errorf("invalid policy (%s schema): %w", res.schema, validateErr)
	}
	return res
}

func runPolicyValidateFile(path string, asJSON bool, stdout io.Writer) error {
	res := validatePolicyFile(path)
	if asJSON {
		// The result is rendered before the verdict is returned: --json
		// changes how the outcome is written, never what the outcome is, and
		// a CI check reads the exit code either way.
		if err := writePolicyValidateJSON(stdout, []policyValidation{res}); err != nil {
			return err
		}
		return res.err
	}
	if res.err != nil {
		return res.err
	}
	if _, pErr := fmt.Fprintf(stdout, "ok: %s (%s schema)\n", res.path, res.schema); pErr != nil {
		return fmt.Errorf("writing output: %w", pErr)
	}
	return nil
}

// isGovernanceSchema reports whether the YAML document has any top-level key
// that identifies it as a config-schema governance file.
func isGovernanceSchema(data []byte) bool {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false
	}
	for _, m := range governanceMarkers {
		if _, ok := doc[m]; ok {
			return true
		}
	}
	return false
}

func runPolicyValidateDir(_ context.Context, dir string, asJSON bool, stdout io.Writer) error {
	patterns := []string{"*.yaml", "*.yml", "*.json"}
	var files []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return fmt.Errorf("globbing %s: %w", pat, err)
		}
		files = append(files, matches...)
	}
	results := make([]policyValidation, 0, len(files))
	var firstErr error
	for _, f := range files {
		res := validatePolicyFile(f)
		results = append(results, res)
		if res.err != nil && firstErr == nil {
			firstErr = res.err
		}
	}
	if asJSON {
		// A directory with no policy files is an empty array. Prose here
		// would be a second document to a parser that asked for one.
		if err := writePolicyValidateJSON(stdout, results); err != nil {
			return err
		}
		return firstErr
	}
	if len(files) == 0 {
		_, _ = fmt.Fprintf(stdout, "no policy files found in %s\n", dir)
		return nil
	}
	for _, res := range results {
		if res.err != nil {
			_, _ = fmt.Fprintf(stdout, "FAIL: %s: %v\n", res.path, res.err)
			continue
		}
		if _, pErr := fmt.Fprintf(stdout, "ok: %s (%s schema)\n", res.path, res.schema); pErr != nil {
			return fmt.Errorf("writing output: %w", pErr)
		}
	}
	return firstErr
}

// ---- policy show ----

func newPolicyShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var policyPath string

	cmd := &cobra.Command{
		Use:         "show",
		Annotations: map[string]string{annotationStoreIntent: StoreIntentNone},
		Short:       "Print the effective depth policy for the current invocation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyShow(cmd.Context(), policyPath, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "explicit policy file path (default: auto-discover)")
	return cmd
}

func runPolicyShow(ctx context.Context, policyPath string, stdout, stderr io.Writer) error {
	logger := buildLogger(logLevel, stderr)
	policy, hash, err := loadPolicy(ctx, policyPath, logger)
	if err != nil {
		return err
	}
	return writePolicyJSON(stdout, policy, hash)
}

func writePolicyJSON(w io.Writer, policy walkdomain.DepthPolicy, hash string) error {
	// The effective VCS forge allowlist is reported explicitly, resolved rather
	// than as authored: a policy that omits allowed_vcs_hosts still verifies
	// against the built-in set, and an operator syncing an egress allowlist
	// (e.g. harden-runner) needs the set that will actually be contacted, not
	// the absence of a field.
	vcsHosts, err := policy.FetchStage().VCSHostAllowlist()
	if err != nil {
		return fmt.Errorf("resolving fetch-stage VCS host allowlist: %w", err)
	}
	out := struct {
		Version           string                           `json:"version"`
		PolicyHash        string                           `json:"policy_hash,omitempty"`
		StageDepths       map[string]walkdomain.StageDepth `json:"stage_depths"`
		EffectiveVCSHosts []string                         `json:"effective_vcs_hosts"`
	}{
		Version:           policy.Version,
		PolicyHash:        hash,
		StageDepths:       policy.Stages,
		EffectiveVCSHosts: vcsHosts.Hosts(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding policy JSON: %w", err)
	}
	return nil
}
