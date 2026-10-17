// Package config provides the ConfigSpec registration mechanism used by modules
// to declare their configuration schema and built-in defaults.
//
// Registration is explicit (never via init) and happens in main.go so that
// alternate binaries can register additional specs without modifying shared code.
package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ConfigSpec declares the configuration schema for a single compiled-in module.
// Section is the top-level YAML key; Defaults is the zero-value struct whose
// fields represent that section's defaults.
type ConfigSpec struct {
	// Section is the top-level YAML key for this module (e.g. "preferences").
	Section string
	// Defaults holds the built-in default values for this section.
	// The type must be a struct with yaml tags matching the config.yaml schema.
	Defaults any
}

// Registry collects ConfigSpec values registered by compiled-in modules.
// Use NewRegistry to obtain one, then call Register for each module.
// The zero value is not valid; always construct via NewRegistry.
type Registry struct {
	specs []ConfigSpec
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a ConfigSpec to the registry.
// Duplicate section names are allowed (last registration wins during generation).
func (r *Registry) Register(spec ConfigSpec) {
	r.specs = append(r.specs, spec)
}

// Specs returns a snapshot of all registered specs in registration order.
func (r *Registry) Specs() []ConfigSpec {
	out := make([]ConfigSpec, len(r.specs))
	copy(out, r.specs)
	return out
}

// Validate refuses Defaults the generator cannot render as YAML; yaml.v3
// panics on some types rather than returning an error, so both are caught.
func (s ConfigSpec) Validate() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("section %s: defaults cannot be written as YAML: %v", s.Section, r)
		}
	}()
	if _, merr := yaml.Marshal(s.Defaults); merr != nil {
		return fmt.Errorf("section %s: defaults cannot be written as YAML: %w", s.Section, merr)
	}
	return nil
}
