package yaml

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
)

// ValidateSetting refuses a value for a settable key that no load could use.
// `config set` and the loader both call it, so a value one refuses the other
// refuses with the same words. A key it has no rule for passes.
func ValidateSetting(key string, node *yaml.Node) error {
	shown := nodeText(node)
	switch {
	case key == "preferences.json", key == "preferences.progress":
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			return fmt.Errorf("%s requires a boolean (true/false), got %q", key, shown)
		}
	case key == "preferences.log_level":
		return validateLogLevel(node, shown)
	case strings.HasPrefix(key, "license_policy.categories."), key == "callgraph.exclude":
		if node.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s requires a YAML sequence (e.g. '[MIT, Apache-2.0]'), got %q", key, shown)
		}
	case key == "callgraph.toolchain":
		return validateToolchain(key, node, shown)
	case key == "staleness.ttl", key == "staleness.probe_concurrency":
		return validateStaleness(key, node, shown)
	case key == "fetch_policy.allowed_vcs_hosts":
		return validateVCSHosts(key, node, shown)
	case key == "vulndb.url":
		return validateVulnDBURL(node, shown)
	case key == "storage.backend", key == "storage.sumdb_cache":
		if node.Kind != yaml.ScalarNode || (key == "storage.backend" && node.Value == "") {
			return fmt.Errorf("%s requires a string, got %q", key, shown)
		}
	}
	return nil
}

// validateVulnDBURL accepts only an https URL with a host: the advisory set
// decides every verdict, so it is never fetched over plain HTTP.
func validateVulnDBURL(node *yaml.Node, shown string) error {
	const want = "vulndb.url requires an https:// URL with a host (the base of a mirror of https://vuln.go.dev), got %q"
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf(want, shown)
	}
	u, err := url.Parse(node.Value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf(want, shown)
	}
	return nil
}

func validateLogLevel(node *yaml.Node, shown string) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("preferences.log_level requires a string, got %q", shown)
	}
	switch node.Value {
	case "debug", "info", "warn", "error":
		return nil
	}
	return fmt.Errorf("preferences.log_level must be one of: debug, info, warn, error; got %q", shown)
}

// validateToolchain refuses a callgraph.toolchain no record could hold: the
// preference is compared with what records state, so any other form never fires.
func validateToolchain(key string, node *yaml.Node, shown string) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("%s requires a Go toolchain version in `go env GOVERSION` form (e.g. go1.26.6), got %q", key, shown)
	}
	if _, err := gotoolchain.ParseVersion(node.Value); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

func validateStaleness(key string, node *yaml.Node, shown string) error {
	if key == "staleness.ttl" {
		return validateTTL(node, shown)
	}
	return validateProbeConcurrency(node, shown)
}

func validateTTL(node *yaml.Node, shown string) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("staleness.ttl requires a duration string (e.g. 1h, 30m, 0), got %q", shown)
	}
	d, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("staleness.ttl must be a duration (e.g. 1h, 30m, 0), got %q", shown)
	}
	if d < 0 {
		return fmt.Errorf("staleness.ttl must not be negative (use 0 to disable the ledger), got %q", shown)
	}
	return nil
}

func validateProbeConcurrency(node *yaml.Node, shown string) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
		return fmt.Errorf("staleness.probe_concurrency requires a whole number (0 for a serial probe), got %q", shown)
	}
	if n, err := strconv.Atoi(node.Value); err != nil || n < 0 {
		return fmt.Errorf("staleness.probe_concurrency must not be negative (use 0 for a serial probe), got %q", shown)
	}
	return nil
}

// validateVCSHosts refuses a host list the fetch domain cannot build. Naming the
// key switches the host check to enforcing, so an unusable list is refused here.
func validateVCSHosts(key string, node *yaml.Node, shown string) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s requires a YAML sequence of bare hostnames (e.g. '[github.com, git.example.org]'), got %q", key, shown)
	}
	hosts := make([]string, 0, len(node.Content))
	for _, n := range node.Content {
		hosts = append(hosts, n.Value)
	}
	if _, err := fetchdomain.NewVCSHostAllowlist(hosts); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

// nodeText renders a value the way an operator would type it: a scalar as
// written, anything else in flow style.
func nodeText(node *yaml.Node) string {
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	flow := *node
	flow.Style |= yaml.FlowStyle
	out, err := yaml.Marshal(&flow)
	if err != nil {
		return node.Value
	}
	return strings.TrimRight(string(out), "\n")
}

// validateSettings runs ValidateSetting over every settable key the file
// carries. A key written with no value is left to the loader's default, as it
// always has been.
func validateSettings(root *yaml.Node) error {
	var first error
	check := func(key string, node *yaml.Node) {
		if first == nil && node.Tag != "!!null" {
			first = ValidateSetting(key, node)
		}
	}
	forEachEntry(root, func(section string, value *yaml.Node) {
		forEachEntry(value, func(key string, v *yaml.Node) {
			if section == "license_policy" && key == "categories" {
				forEachEntry(v, func(name string, cat *yaml.Node) {
					check("license_policy.categories."+name, cat)
				})
				return
			}
			check(section+"."+key, v)
		})
	})
	return first
}

// forEachEntry calls fn for each key of the mapping n (or the document's root
// mapping), following aliases and "<<" merges. Anything that is not a mapping
// has no entries.
func forEachEntry(n *yaml.Node, fn func(key string, value *yaml.Node)) {
	n = resolve(n)
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = resolve(n.Content[0])
	}
	if n == nil {
		return
	}
	if n.Kind == yaml.SequenceNode {
		// Only reached through a merge key, which may list several mappings.
		for _, m := range n.Content {
			forEachEntry(m, fn)
		}
		return
	}
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Tag == "!!merge" {
			forEachEntry(n.Content[i+1], fn)
			continue
		}
		fn(n.Content[i].Value, resolve(n.Content[i+1]))
	}
}

func resolve(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}
