package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/config"
	"github.com/eitanity/kanonarion/internal/config/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func newConfigCmd(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "config",
		Annotations: map[string]string{annotationNetworkUse: NetworkNever},
		Short:       "Read and write configuration values (git config style)",
	}
	cmd.AddCommand(
		newConfigInitCmd(stdout),
		newConfigShowCmd(stdout),
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
		// Exempt from the rejected-config refusal: it writes the commented
		// template, which is where an operator reads the legal values for the
		// key that was rejected. It never consults the loaded configuration.
		Annotations: map[string]string{
			annotationUsableWithRejectedConfig: "creates or completes the config file",
			// Writes config.yaml into the store root, so it may make the root.
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runConfigInit(storeRoot, jsonOut, stdout)
		},
	}
}

// What `config init` did to the file it was pointed at. Creating a file,
// completing one and leaving one alone are three different events, and a
// caller that only learns the path cannot tell which of them happened.
const (
	configInitCreated   = "created"
	configInitAppended  = "sections_appended"
	configInitUnchanged = "unchanged"
)

// configInitResult states the file and what became of it. existed is kept
// beside action rather than folded into it because the two answer different
// questions: whether the operator already had a file, and whether this run
// changed it.
type configInitResult struct {
	ConfigFile string `json:"config_file"`
	Existed    bool   `json:"existed"`
	Action     string `json:"action"`
}

func runConfigInit(root string, asJSON bool, stdout io.Writer) error {
	configPath := filepath.Join(root, "config.yaml")
	// Read rather than stat: the bytes are what says whether the template
	// completed an existing file or left it exactly as it was, and they are
	// only readable before the write. A file that exists and cannot be read
	// still refuses below, in EnsureConfig, as it did before.
	before, readErr := os.ReadFile(configPath) // #nosec G304 -- operator-supplied store-root path
	existed := readErr == nil

	if err := config.EnsureConfig(configPath); err != nil {
		return fmt.Errorf("writing config template: %w", err)
	}

	if asJSON {
		action := configInitCreated
		if existed {
			after, err := os.ReadFile(configPath) // #nosec G304 -- same path
			if err != nil {
				return fmt.Errorf("reading config file: %w", err)
			}
			action = configInitUnchanged
			if !bytes.Equal(before, after) {
				action = configInitAppended
			}
		}
		return encodeJSON(stdout, configInitResult{
			ConfigFile: configPath,
			Existed:    existed,
			Action:     action,
		})
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

func newConfigShowCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the full effective configuration",
		Example: `  kanonarion config show
  kanonarion config show --json`,
		// Exempt from the rejected-config refusal: this is the command whose
		// whole job is answering "what is in force", so it is the one that must
		// keep working when the answer is "not what your file says". It states
		// the rejection in its own output.
		Annotations: map[string]string{
			annotationUsableWithRejectedConfig: "reports the file and what is actually in force",
			annotationStoreIntent:              StoreIntentRead,
			annotationNetworkUse:               NetworkNever,
		},
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
  kanonarion config get copyright_declarations
  kanonarion config get callgraph.exclude
  kanonarion config get staleness.ttl`,
		// Exempt from the rejected-config refusal: it reports a single value in
		// force, which with a rejected file is the built-in default. That is a
		// true answer, and the rejection is stated on stderr beside it, so an
		// operator can read the value the rejection left them with.
		Annotations: map[string]string{
			annotationUsableWithRejectedConfig: "reports one value in force",
			annotationStoreIntent:              StoreIntentRead,
			annotationNetworkUse:               NetworkNever,
		},
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runConfigGet(storeRoot, activeConfig, args[0], jsonOut, stdout)
		},
	}
}

// configGetResult is one configuration key as a document: the value in force
// and where it came from.
//
// source carries the same two words `config show` uses, answered by the same
// loader, because the value alone cannot say what a caller scripting this
// needs to know. A bare "false" is true of a store nobody has configured and
// of one an operator deliberately turned off, and the two are different facts.
type configGetResult struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

func runConfigGet(root string, cfg domain.Config, key string, asJSON bool, stdout io.Writer) error {
	val, err := configGetValue(cfg, key)
	if err != nil {
		return err
	}
	if !asJSON {
		if _, err = fmt.Fprintln(stdout, val); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return nil
	}
	source, err := configKeySource(root, key)
	if err != nil {
		return err
	}
	return encodeJSON(stdout, configGetResult{Key: key, Value: val, Source: source})
}

// configKeySource reports whether the value in force for key was written by the
// operator or merged in from the built-in defaults.
//
// It asks the file the way `config show` does — the typed config cannot answer
// it, because once the defaults are merged a value set to the default and a
// value never set are the same bytes — and it discards a rejected file for the
// same reason config show does: a rejected file set nothing.
func configKeySource(root, key string) (string, error) {
	_, data, _, err := readConfigFile(root)
	if err != nil {
		return "", err
	}
	raw, err := parseRawConfigDoc(data)
	if err != nil {
		return "", err
	}
	if path, ok := configKeyPath(key); ok && rawIfInForce(raw).isSet(path...) {
		return configSourceFile, nil
	}
	return configSourceDefault, nil
}

// configKeyPath maps a readable config key to its path in the raw YAML
// document, so presence in the file can be asked about it.
//
// It mirrors configGetValue rather than configSetPath: every key that can be
// READ needs a source, and several of them — version, the whole-section keys,
// the copyright declarations — are not settable.
func configKeyPath(key string) ([]string, bool) {
	switch {
	case key == "version":
		return []string{"version"}, true
	case strings.HasPrefix(key, "preferences."):
		return []string{"preferences", strings.TrimPrefix(key, "preferences.")}, true
	case key == "license_policy.categories":
		return []string{"license_policy", "categories"}, true
	case strings.HasPrefix(key, "license_policy.categories."):
		return []string{"license_policy", "categories", strings.TrimPrefix(key, "license_policy.categories.")}, true
	case key == "license_policy.rules":
		return []string{"license_policy", "rules"}, true
	case key == "license_overrides":
		return []string{"license_overrides"}, true
	case strings.HasPrefix(key, "license_overrides."):
		return []string{"license_overrides", strings.TrimPrefix(key, "license_overrides.")}, true
	case key == "copyright_declarations":
		return []string{"copyright_declarations"}, true
	case strings.HasPrefix(key, "copyright_declarations."):
		return []string{"copyright_declarations", strings.TrimPrefix(key, "copyright_declarations.")}, true
	case key == "callgraph.exclude":
		return []string{"callgraph", "exclude"}, true
	case strings.HasPrefix(key, "staleness."):
		return []string{"staleness", strings.TrimPrefix(key, "staleness.")}, true
	case key == "fetch_policy.allowed_vcs_hosts":
		return []string{"fetch_policy", "allowed_vcs_hosts"}, true
	default:
		return nil, false
	}
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
	case key == "copyright_declarations":
		return marshalConfigYAML(cfg.CopyrightDeclarations)
	case strings.HasPrefix(key, "copyright_declarations."):
		module := strings.TrimPrefix(key, "copyright_declarations.")
		d, ok := cfg.CopyrightDeclarations[module]
		if !ok {
			return "", &exitError{code: ExitConfig, msg: fmt.Sprintf("no copyright declaration for %q", module)}
		}
		return marshalConfigYAML(d)
	case key == "callgraph.exclude":
		return marshalConfigYAML(cfg.Callgraph.Exclude)
	case key == "staleness.ttl":
		return cfg.Staleness.TTL.String(), nil
	case key == "staleness.probe_concurrency":
		return strconv.Itoa(cfg.Staleness.ProbeConcurrency), nil
	case key == "fetch_policy.allowed_vcs_hosts":
		if cfg.FetchPolicy.AllowedVCSHosts == nil {
			// Absent is a distinct answer from empty, and printing "[]" would
			// report the enforcing posture for a config that has not chosen it.
			return "(unset: the built-in VCS host set applies, advisory — off-list hosts are reported, not refused)", nil
		}
		return marshalConfigYAML(cfg.FetchPolicy.AllowedVCSHosts)
	default:
		return "", &exitError{code: ExitConfig, msg: fmt.Sprintf("unknown config key %q", key)}
	}
}

func marshalConfigYAML(v any) (string, error) {
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
  kanonarion config set callgraph.exclude '[]'
  kanonarion config set staleness.ttl 6h`,
		// Exempt from the rejected-config refusal: it is the repair. It edits
		// the YAML document directly and never consults the loaded
		// configuration, so refusing it would make a rejected file unfixable by
		// the tool that wrote it.
		Annotations: map[string]string{
			annotationUsableWithRejectedConfig: "repairs the config file",
			// Writes config.yaml into the store root, so it may make the root.
			annotationStoreIntent: StoreIntentCreate,
			annotationNetworkUse:  NetworkNever,
		},
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return runConfigSet(storeRoot, args[0], args[1], jsonOut, stdout)
		},
	}
}

// configSetResult states what the write changed.
//
// previous_value is the part worth having: a caller that sets a key wants to
// know what it displaced, and the plain-text acknowledgement destroys that fact
// the moment it is written. previous_source says whether the displaced value
// was the operator's or the built-in default, in the same vocabulary
// `config get` and `config show` use, because "it was warn" and "nobody had set
// it, so it was warn" are different things to displace.
type configSetResult struct {
	Key            string `json:"key"`
	PreviousValue  string `json:"previous_value"`
	PreviousSource string `json:"previous_source"`
	Value          string `json:"value"`
	ConfigFile     string `json:"config_file"`
}

func runConfigSet(root, key, value string, asJSON bool, stdout io.Writer) error {
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

	// Read before the replacement: this is the last moment the displaced value
	// exists. Taken from the file rather than from the loaded configuration,
	// because this command edits the file and must keep working when the loaded
	// configuration was rejected.
	prevValue, prevSource := previousConfigValue(&doc, yamlPath, key)

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

	if asJSON {
		written, err := marshalConfigYAML(valueNode)
		if err != nil {
			return err
		}
		return encodeJSON(stdout, configSetResult{
			Key:            key,
			PreviousValue:  prevValue,
			PreviousSource: prevSource,
			Value:          written,
			ConfigFile:     configPath,
		})
	}

	if _, err = fmt.Fprintf(stdout, "set %s\n", key); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// previousConfigValue reports the value the write is about to displace and
// where it came from.
//
// A key the file already carries is displaced by what the file said. A key it
// does not carry is displaced by the built-in default, which is rendered from
// DefaultConfig rather than from the loaded configuration so that a rejected
// file — the case this command exists to repair — still gets a true answer. A
// key with no default behind it at all, such as a licence override that was
// never recorded, displaced nothing and reads as empty.
func previousConfigValue(doc *yaml.Node, yamlPath []string, key string) (value, source string) {
	if node, ok := lookupYAMLNode(doc, yamlPath); ok {
		if rendered, err := marshalConfigYAML(node); err == nil {
			return rendered, configSourceFile
		}
	}
	if rendered, err := configGetValue(domain.DefaultConfig(), key); err == nil {
		return rendered, configSourceDefault
	}
	return "", configSourceDefault
}

// lookupYAMLNode returns the node at yamlPath, reporting whether the document
// carries it.
func lookupYAMLNode(doc *yaml.Node, yamlPath []string) (*yaml.Node, bool) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, false
	}
	node := doc.Content[0]
	for _, seg := range yamlPath {
		if node.Kind != yaml.MappingNode {
			return nil, false
		}
		found := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == seg {
				node = node.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return node, true
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
	case key == "staleness.ttl":
		return []string{"staleness", "ttl"}, nil
	case key == "staleness.probe_concurrency":
		return []string{"staleness", "probe_concurrency"}, nil
	case key == "fetch_policy.allowed_vcs_hosts":
		return []string{"fetch_policy", "allowed_vcs_hosts"}, nil
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
	case key == "staleness.ttl":
		if node.Kind != yaml.ScalarNode {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("staleness.ttl requires a duration string (e.g. 1h, 30m, 0), got %q", value)}
		}
		if _, err := time.ParseDuration(node.Value); err != nil {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("staleness.ttl must be a duration (e.g. 1h, 30m, 0), got %q", value)}
		}
	case key == "staleness.probe_concurrency":
		// Bounded, and the bound is a correctness setting rather than a speed
		// one: past the default the proxy starts answering 200 with an empty
		// body, which is a lost answer rather than an error. 0 is a serial probe.
		if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"staleness.probe_concurrency requires a whole number (0 for a serial probe), got %q", value)}
		}
		n, err := strconv.Atoi(node.Value)
		if err != nil || n < 0 {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"staleness.probe_concurrency must not be negative (use 0 for a serial probe), got %q", value)}
		}
	case key == "fetch_policy.allowed_vcs_hosts":
		if node.Kind != yaml.SequenceNode {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf(
				"%s requires a YAML sequence of bare hostnames (e.g. '[github.com, git.example.org]'), got %q", key, value)}
		}
		// Validated on the way in, by the domain that owns the rule, so an
		// unusable list is refused while the operator is typing it rather than
		// halfway through the next walk. Setting it switches the host check
		// from advisory to enforcing, which is worth saying out loud in the
		// error when the list cannot be used.
		hosts := make([]string, 0, len(node.Content))
		for _, n := range node.Content {
			hosts = append(hosts, n.Value)
		}
		if _, err := fetchdomain.NewVCSHostAllowlist(hosts); err != nil {
			return nil, &exitError{code: ExitConfig, msg: fmt.Sprintf("%s: %v", key, err)}
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
