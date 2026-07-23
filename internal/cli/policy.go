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
		newPolicyValidateCmd(stdout, stderr),
		newPolicyShowCmd(stdout, stderr),
	)
	return cmd
}

// ---- policy validate ----

func newPolicyValidateCmd(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "validate <path>",
		Short: "Validate a depth-policy or governance policy YAML file against its schema",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runPolicyValidate(cmd.Context(), args[0], stdout)
		},
	}
}

func runPolicyValidate(ctx context.Context, path string, stdout io.Writer) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &exitError{code: ExitConfig, msg: fmt.Sprintf("policy file not found: %s", path)}
		}
		return fmt.Errorf("stat policy path: %w", err)
	}
	if info.IsDir() {
		return runPolicyValidateDir(ctx, path, stdout)
	}
	return runPolicyValidateFile(path, stdout)
}

// governanceMarkers are the top-level keys that identify a config-schema
// governance file as opposed to a depth-policy file. `policy
// validate` routes to the matching schema so the two coherent schemas stay
// independently validated rather than one leniently accepting the other.
var governanceMarkers = []string{
	"license_policy", "directive_policy", "godebug_policy",
	"vendor_policy", "fips_policy", "preferences", "license_overrides",
}

func runPolicyValidateFile(path string, stdout io.Writer) error {
	data, err := os.ReadFile(path) /* #nosec G304 -- operator-supplied path is intentional */
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	schema := "depth-policy"
	var validateErr error
	if isGovernanceSchema(data) {
		schema = "governance"
		_, validateErr = configyaml.Parse(data)
	} else {
		_, validateErr = walkadapterpolicy.Parse(data)
	}
	if validateErr != nil {
		return fmt.Errorf("invalid policy (%s schema): %w", schema, validateErr)
	}
	if _, pErr := fmt.Fprintf(stdout, "ok: %s (%s schema)\n", path, schema); pErr != nil {
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

func runPolicyValidateDir(_ context.Context, dir string, stdout io.Writer) error {
	patterns := []string{"*.yaml", "*.yml", "*.json"}
	var files []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return fmt.Errorf("globbing %s: %w", pat, err)
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		_, _ = fmt.Fprintf(stdout, "no policy files found in %s\n", dir)
		return nil
	}
	var firstErr error
	for _, f := range files {
		if err := runPolicyValidateFile(f, stdout); err != nil {
			_, _ = fmt.Fprintf(stdout, "FAIL: %s: %v\n", f, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ---- policy show ----

func newPolicyShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var policyPath string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the effective depth policy for the current invocation",
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
	out := struct {
		Version     string                           `json:"version"`
		PolicyHash  string                           `json:"policy_hash,omitempty"`
		StageDepths map[string]walkdomain.StageDepth `json:"stage_depths"`
	}{
		Version:     policy.Version,
		PolicyHash:  hash,
		StageDepths: policy.Stages,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding policy JSON: %w", err)
	}
	return nil
}
