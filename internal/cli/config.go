package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/config"
	"github.com/eitanity/kanonarion/internal/config/domain"
)

func newConfigCmd(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Read and write configuration values (git config style)",
	}
	cmd.AddCommand(
		newConfigInitCmd(stdout),
		newConfigShowCmd(stdout, stderr),
		newConfigGetCmd(stdout),
		newConfigSetCmd(stdout),
	)
	return cmd
}

// ---- config init ----

func newConfigInitCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write a commented config template to the store",
		Long: "Create <store-root>/config.yaml from the commented default " +
			"template so the available settings are easy to discover and edit. " +
			"Every key is commented out, so the file changes nothing until you " +
			"uncomment a value; keys you leave commented keep their live " +
			"built-in default and continue to track default changes across " +
			"upgrades. An existing file is preserved (only missing sections are " +
			"appended).",
		Example: `  kanonarion config init
  kanonarion config init --store-root /tmp/store`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runConfigInit(storeRoot, stdout)
		},
	}
}

func runConfigInit(root string, stdout io.Writer) error {
	configPath := filepath.Join(root, "config.yaml")
	_, statErr := os.Stat(configPath)
	existed := statErr == nil

	if err := config.EnsureConfig(configPath); err != nil {
		return fmt.Errorf("writing config template: %w", err)
	}

	msg := "wrote commented config template to %s\n"
	if existed {
		msg = "config already present at %s (any missing sections appended)\n"
	}
	if _, err := fmt.Fprintf(stdout, msg, configPath); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// ---- config show ----

func newConfigShowCmd(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the full effective configuration",
		Example: `  kanonarion config show
  kanonarion config show --json`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runStoreConfigShow(storeRoot, jsonOut, stdout)
		},
	}
}

// ---- config get ----

func newConfigGetCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Print the value for a configuration key",
		Example: `  kanonarion config get preferences.json
  kanonarion config get preferences.log_level
  kanonarion config get license_policy.categories.permissive
  kanonarion config get callgraph.exclude`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runConfigGet(activeConfig, args[0], stdout)
		},
	}
}

func runConfigGet(cfg domain.Config, key string, stdout io.Writer) error {
	val, err := configGetValue(cfg, key)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintln(stdout, val); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func configGetValue(cfg domain.Config, key string) (string, error) {
	switch {
	case key == "version":
		return cfg.Version, nil
	case key == "preferences.json":
		return strconv.FormatBool(cfg.Preferences.JSON), nil
	case key == "preferences.log_level":
		return cfg.Preferences.LogLevel, nil
	case key == "preferences.progress":
		return strconv.FormatBool(cfg.Preferences.Progress), nil
	case key == "license_policy.categories":
		return marshalConfigYAML(cfg.LicensePolicy.Categories)
	case strings.HasPrefix(key, "license_policy.categories."):
		name := strings.TrimPrefix(key, "license_policy.categories.")
		cat, ok := cfg.LicensePolicy.Categories[name]
		if !ok {
			return "", &exitError{code: ExitConfig, msg: fmt.Sprintf("unknown category %q", name)}
		}
		return marshalConfigYAML(cat)
	case key == "license_policy.rules":
		return marshalConfigYAML(cfg.LicensePolicy.Rules)
	case key == "license_overrides":
		return marshalConfigYAML(cfg.LicenseOverrides)
	case strings.HasPrefix(key, "license_overrides."):
		module := strings.TrimPrefix(key, "license_overrides.")
		val, ok := cfg.LicenseOverrides[module]
		if !ok {
			return "", &exitError{code: ExitConfig, msg: fmt.Sprintf("no license override for %q", module)}
		}
		return val, nil
	case key == "callgraph.exclude":
		return marshalConfigYAML(cfg.Callgraph.Exclude)
	default:
		return "", &exitError{code: ExitConfig, msg: fmt.Sprintf("unknown config key %q", key)}
	}
}

func marshalConfigYAML(v interface{}) (string, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshaling config value: %w", err)
	}
	return strings.TrimRight(string(data), "\n"), nil
}

// ---- config set ----

func newConfigSetCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Write a value to the configuration file",
		Example: `  kanonarion config set preferences.json true
  kanonarion config set preferences.log_level debug
  kanonarion config set license_policy.categories.permissive '[MIT, Apache-2.0, ISC]'
  kanonarion config set license_overrides.golang.org/x/mod MIT
  kanonarion config set callgraph.exclude '[]'`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return runConfigSet(storeRoot, args[0], args[1], stdout)
		},
	}
}

func runConfigSet(root, key, value string, stdout io.Writer) error {
	yamlPath, err := configSetPath(key)
	if err != nil {
		return err
	}

	configPath := filepath.Join(root, "config.yaml")
	if err := config.EnsureConfig(configPath); err != nil {
		return fmt.Errorf("ensuring config file: %w", err)
	}

	data, err := os.ReadFile(configPath) // #nosec G304 -- operator-supplied store-root path
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing config YAML: %w", err)
	}

	valueNode, err := parseConfigValue(key, value)
	if err != nil {
		return err
	}

	if err := setYAMLNode(&doc, yamlPath, valueNode); err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("finalising config: %w", err)
	}
	if err := os.WriteFile(configPath, buf.Bytes(), 0o600); err != nil { // #nosec G304 G703 -- operator-supplied path
		return fmt.Errorf("writing config %s: %w", configPath, err)
	}

	if _, err = fmt.Fprintf(stdout, "set %s\n", key); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// configSetPath returns the YAML key path for a settable config key.
func configSetPath(key string) ([]string, error) {
	switch {
	case key == "preferences.json":
		return []string{"preferences", "json"}, nil
	case key == "preferences.log_level":
		return []string{"preferences", "log_level"}, nil
	case key == "preferences.progress":
		return []string{"preferences", "progress"}, nil
	case strings.HasPrefix(key, "license_policy.categories."):
		name := strings.TrimPrefix(key, "license_policy.categories.")
		if name == "" {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("unknown config key %q", key)}
		}
		return []string{"license_policy", "categories", name}, nil
	case strings.HasPrefix(key, "license_overrides."):
		module := strings.TrimPrefix(key, "license_overrides.")
		if module == "" {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("unknown config key %q", key)}
		}
		return []string{"license_overrides", module}, nil
	case key == "callgraph.exclude":
		return []string{"callgraph", "exclude"}, nil
	default:
		return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("unknown config key %q", key)}
	}
}

// parseConfigValue parses a string value for the given key into a yaml.Node,
// validating that the node kind matches what the key expects.
func parseConfigValue(key, value string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(value), &doc); err != nil {
		return nil, fmt.Errorf("invalid value %q: %w", value, err)
	}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("empty value")
	}
	node := doc.Content[0]

	switch {
	case key == "preferences.json":
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("preferences.json requires a boolean (true/false), got %q", value)}
		}
	case key == "preferences.progress":
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("preferences.progress requires a boolean (true/false), got %q", value)}
		}
	case key == "preferences.log_level":
		if node.Kind != yaml.ScalarNode {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("preferences.log_level requires a string, got %q", value)}
		}
		switch node.Value {
		case "debug", "info", "warn", "error":
		default:
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("preferences.log_level must be one of: debug, info, warn, error; got %q", value)}
		}
	case strings.HasPrefix(key, "license_policy.categories."),
		key == "callgraph.exclude":
		if node.Kind != yaml.SequenceNode {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("%s requires a YAML sequence (e.g. '[MIT, Apache-2.0]'), got %q", key, value)}
		}
	case strings.HasPrefix(key, "license_overrides."):
		if node.Kind != yaml.ScalarNode {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("license_overrides.<module> requires a string (SPDX expression), got %q", value)}
		}
	}

	return node, nil
}

// setYAMLNode navigates the document to yamlPath and replaces that node with valueNode.
// Intermediate mapping keys are created if absent.
func setYAMLNode(doc *yaml.Node, yamlPath []string, valueNode *yaml.Node) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("invalid YAML document")
	}
	setInMapping(doc.Content[0], yamlPath, valueNode)
	return nil
}

func setInMapping(node *yaml.Node, path []string, valueNode *yaml.Node) {
	if node.Kind != yaml.MappingNode || len(path) == 0 {
		return
	}
	key := path[0]
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			if len(path) == 1 {
				node.Content[i+1] = valueNode
				return
			}
			// If the value is null/scalar (e.g. an empty section like "overrides:"),
			// upgrade it to a mapping so we can navigate deeper.
			if node.Content[i+1].Kind != yaml.MappingNode {
				old := node.Content[i+1]
				node.Content[i+1] = &yaml.Node{
					Kind:        yaml.MappingNode,
					Tag:         "!!map",
					HeadComment: old.HeadComment,
				}
			}
			setInMapping(node.Content[i+1], path[1:], valueNode)
			return
		}
	}
	// Key absent: append it.
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"}
	if len(path) == 1 {
		node.Content = append(node.Content, keyNode, valueNode)
		return
	}
	childMap := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	node.Content = append(node.Content, keyNode, childMap)
	setInMapping(childMap, path[1:], valueNode)
}
