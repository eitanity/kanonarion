package storage

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/eitanity/kanonarion/internal/config"
	"github.com/eitanity/kanonarion/internal/config/domain"
)

// Backend is a storage implementation a binary registers, selected by the
// storage.backend value of config.yaml.
type Backend struct {
	// Name is the value of storage.backend that selects it, e.g. "sqlite".
	Name string
	// Section is its own top-level config.yaml section, "" for none.
	Section string
	// Defaults is a struct with yaml tags; `config init` writes it commented
	// out under Section. It may implement config.Commented.
	Defaults any
	// Open opens the store a Request names. Request.Section carries the raw
	// YAML of Section.
	Open func(context.Context, Request) (*Storage, error)
}

// ErrBackendNotRegistered matches a configuration naming a backend the
// running binary did not register.
var ErrBackendNotRegistered = errors.New("storage backend is not registered")

// The registry is process-wide and filled from main, never from init, so a
// binary's backends are the ones its main names.
var registry = struct {
	sync.Mutex
	backends []Backend
	specs    *config.Registry
}{specs: config.NewRegistry()}

// Register adds b to the backends this process can open. It refuses an empty
// Name, a nil Open, a Name already registered, a Section that is already taken
// or is one of the schema's own sections, and Defaults that cannot be written
// as YAML.
func Register(b Backend) error {
	if b.Name == "" {
		return errors.New("registering storage backend: empty name")
	}
	if b.Open == nil {
		return fmt.Errorf("registering storage backend %q: nil Open", b.Name)
	}
	if b.Section != "" && config.IsKnownSection(b.Section) {
		return fmt.Errorf("registering storage backend %q: section %q is a config.yaml section of its own", b.Name, b.Section)
	}
	spec := config.ConfigSpec{Section: b.Section, Defaults: b.Defaults}
	if b.Section != "" {
		if err := spec.Validate(); err != nil {
			return fmt.Errorf("registering storage backend %q: %w", b.Name, err)
		}
	}
	registry.Lock()
	defer registry.Unlock()
	for _, have := range registry.backends {
		if have.Name == b.Name {
			return fmt.Errorf("registering storage backend %q: already registered", b.Name)
		}
		if b.Section != "" && have.Section == b.Section {
			return fmt.Errorf("registering storage backend %q: section %q belongs to backend %q", b.Name, b.Section, have.Name)
		}
	}
	registry.backends = append(registry.backends, b)
	if b.Section != "" {
		registry.specs.Register(spec)
	}
	return nil
}

// Lookup returns the registered backend called name.
func Lookup(name string) (Backend, bool) {
	registry.Lock()
	defer registry.Unlock()
	for _, b := range registry.backends {
		if b.Name == name {
			return b, true
		}
	}
	return Backend{}, false
}

// Names lists the registered backends, sorted.
func Names() []string {
	registry.Lock()
	defer registry.Unlock()
	names := make([]string, 0, len(registry.backends))
	for _, b := range registry.backends {
		names = append(names, b.Name)
	}
	slices.Sort(names)
	return names
}

// ConfigSpecs is the config.yaml section of every registered backend that has
// one, in registration order, for `config init` to write.
func ConfigSpecs() []config.ConfigSpec {
	registry.Lock()
	defer registry.Unlock()
	return registry.specs.Specs()
}

// OpenConfigured opens the backend req.Config names, with req.Section set to
// that backend's own section of the configuration. implicit is in force
// whether or not it is registered, so a library consumer that registers
// nothing, or registers only its own backend, still opens a default store.
func OpenConfigured(ctx context.Context, req Request, implicit Backend) (*Storage, error) {
	b, err := Select(req.Config, implicit)
	if err != nil {
		return nil, err
	}
	req.Section = nil
	if b.Section != "" {
		req.Section = req.Config.Sections[b.Section]
	}
	return b.Open(ctx, req)
}

// Select resolves the configured backend name against the backends in force:
// the registered ones, and implicit. It opens nothing.
func Select(cfg domain.Config, implicit Backend) (Backend, error) {
	name := cfg.Storage.Backend
	if name == "" {
		name = domain.DefaultStorageBackend
	}
	if b, ok := Lookup(name); ok {
		return b, nil
	}
	if name == implicit.Name {
		return implicit, nil
	}
	names := Names()
	if !slices.Contains(names, implicit.Name) {
		names = append(names, implicit.Name)
		slices.Sort(names)
	}
	return Backend{}, &notRegisteredError{name: name, registered: names}
}

// notRegisteredError names the backend asked for and the ones in force; it
// matches ErrBackendNotRegistered.
type notRegisteredError struct {
	name       string
	registered []string
}

func (e *notRegisteredError) Error() string {
	return fmt.Sprintf("backend %q is not registered in this binary (registered: %s)", e.name, strings.Join(e.registered, ", "))
}

func (e *notRegisteredError) Unwrap() error { return ErrBackendNotRegistered }

// resetRegistry empties the registry; tests use it through export_test.go.
func resetRegistry() {
	registry.Lock()
	defer registry.Unlock()
	registry.backends = nil
	registry.specs = config.NewRegistry()
}
