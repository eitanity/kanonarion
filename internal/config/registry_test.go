package config_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/config"
)

func TestRegistry_RegisterAndSpecs(t *testing.T) {
	r := config.NewRegistry()

	r.Register(config.ConfigSpec{Section: "preferences", Defaults: struct{ JSON bool }{JSON: false}})
	r.Register(config.ConfigSpec{Section: "callgraph", Defaults: struct{ Exclude []string }{}})

	specs := r.Specs()
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2", len(specs))
	}
	if specs[0].Section != "preferences" {
		t.Errorf("first spec section: got %q, want %q", specs[0].Section, "preferences")
	}
	if specs[1].Section != "callgraph" {
		t.Errorf("second spec section: got %q, want %q", specs[1].Section, "callgraph")
	}
}

func TestRegistry_SpecsReturnsSnapshot(t *testing.T) {
	r := config.NewRegistry()
	r.Register(config.ConfigSpec{Section: "a"})

	s1 := r.Specs()
	r.Register(config.ConfigSpec{Section: "b"})
	s2 := r.Specs()

	if len(s1) != 1 {
		t.Errorf("first snapshot: got %d specs, want 1", len(s1))
	}
	if len(s2) != 2 {
		t.Errorf("second snapshot: got %d specs, want 2", len(s2))
	}
}
