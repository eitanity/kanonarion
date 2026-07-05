package local_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/extract/adapters/stages/local"
)

func TestRegistry_Stages(t *testing.T) {
	r := local.New()
	stages := r.Stages()

	want := []string{"license", "interface", "callgraph", "example"}
	if len(stages) != len(want) {
		t.Fatalf("Stages(): got %d stages, want %d", len(stages), len(want))
	}
	for i, s := range want {
		if stages[i] != s {
			t.Errorf("Stages()[%d] = %q, want %q", i, stages[i], s)
		}
	}
}

func TestRegistry_Stages_ReturnsCopy(t *testing.T) {
	r := local.New()
	s1 := r.Stages()
	s1[0] = "mutated"
	s2 := r.Stages()
	if s2[0] != "license" {
		t.Errorf("Stages() did not return a copy: got %q after mutation", s2[0])
	}
}

func TestRegistry_Has_KnownStages(t *testing.T) {
	r := local.New()
	for _, name := range []string{"license", "interface", "callgraph", "example"} {
		if !r.Has(name) {
			t.Errorf("Has(%q) = false, want true", name)
		}
	}
}

func TestRegistry_Has_UnknownStage(t *testing.T) {
	r := local.New()
	if r.Has("unknown") {
		t.Error("Has('unknown') = true, want false")
	}
	if r.Has("") {
		t.Error("Has('') = true, want false")
	}
}
