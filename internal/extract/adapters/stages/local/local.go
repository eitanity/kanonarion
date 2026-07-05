package local

// defaultStages lists all built-in extraction stage names in execution order.
var defaultStages = []string{"license", "interface", "callgraph", "example"}

// Registry is the default, local implementation of ports.StageRegistry.
type Registry struct{}

// New returns the default local Registry.
func New() Registry { return Registry{} }

// Stages returns the built-in stage names in canonical execution order.
func (Registry) Stages() []string {
	out := make([]string, len(defaultStages))
	copy(out, defaultStages)
	return out
}

// Has reports whether name is a known stage.
func (Registry) Has(name string) bool {
	for _, s := range defaultStages {
		if s == name {
			return true
		}
	}
	return false
}
