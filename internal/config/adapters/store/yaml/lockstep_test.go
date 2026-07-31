package yaml

import (
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/config"
	"gopkg.in/yaml.v3"
)

// TestWireStructIsScaffolded asserts that every top-level key the wire struct
// parses is also a section the generator writes.
//
// This is an internal test because the wire struct is the authority on the
// schema's shape and is unexported; asking it directly is the only way to make
// the check total. It exists because the two halves drifted once: fetch_policy
// was parsed and validated by the loader but absent from the generator, so no
// operator ever saw it — not on a fresh `config init`, and not on the
// upgrade-append that fills in sections a stored file predates. A section the
// generator does not know about is undiscoverable, and nothing else fails.
//
// The assertion is made against the generated document rather than against the
// section list, because appearing in the list without a defaults block would
// scaffold nothing and still pass.
func TestWireStructIsScaffolded(t *testing.T) {
	var scaffolded map[string]any
	if err := yaml.Unmarshal(config.DefaultYAML(), &scaffolded); err != nil {
		t.Fatalf("unmarshalling the generated template: %v", err)
	}

	wire := reflect.TypeOf(configYAML{})
	for i := range wire.NumField() {
		key := wire.Field(i).Tag.Get("yaml")
		if key == "" {
			t.Fatalf("field %s carries no yaml tag; the schema key cannot be checked", wire.Field(i).Name)
		}
		if _, present := scaffolded[key]; !present {
			t.Errorf("schema section %q is parsed by the loader but never scaffolded by the generator; "+
				"add it to knownSections and sectionDefaults", key)
		}
	}
}

// TestScaffoldedTemplateParsesEveryKey is the other direction: the generated
// template must not name a section the loader would reject or ignore. A block
// the wire struct does not carry is a promise `config show` cannot keep.
func TestScaffoldedTemplateParsesEveryKey(t *testing.T) {
	var scaffolded map[string]any
	if err := yaml.Unmarshal(config.DefaultYAML(), &scaffolded); err != nil {
		t.Fatalf("unmarshalling the generated template: %v", err)
	}

	wire := reflect.TypeOf(configYAML{})
	known := make(map[string]bool, wire.NumField())
	for i := range wire.NumField() {
		known[wire.Field(i).Tag.Get("yaml")] = true
	}

	for key := range scaffolded {
		if !known[key] {
			t.Errorf("generated template scaffolds %q, which the config schema does not parse", key)
		}
	}
}
