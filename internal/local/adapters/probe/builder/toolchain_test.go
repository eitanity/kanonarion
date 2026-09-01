package builder_test

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/adapters/probe/builder"
	"github.com/eitanity/kanonarion/internal/local/localtest"
)

// TestProbe_SettlesTheToolchainOnceAndEveryChildRunsUnderIt is the defect on the
// symbol probe, and the reason the decision is a value passed down rather than a
// retry written at each spawn.
//
// One probe spawns up to five Go children — a package list, a build per main, a
// symbol-table read. Deciding per child would make the probe pay a failed first
// attempt five times, and would let two children measure the same tree under
// different toolchains, which is a worse answer than the failure it replaced.
//
// So the assertion is not merely that the escalation happened: it is that
// exactly one child ran under the installed toolchain and every child after it
// ran under the one this host has.
func TestProbe_SettlesTheToolchainOnceAndEveryChildRunsUnderIt(t *testing.T) {
	h := localtest.NewHost(t, true)

	result, err := builder.New(h.GoBinary).Probe(context.Background(), h.Tree)

	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(result.BinarySymbols) == 0 {
		t.Error("the probe read no symbols, so the children after the escalation did not really run")
	}
	h.AssertEscalated(t)

	children := h.Children(t)
	if len(children) < 3 {
		t.Fatalf("%d child environment(s) recorded; a probe of a main package runs a list, a build and a "+
			"symbol read, so the escalation was not threaded past the first", len(children))
	}
	pinned := 0
	for _, env := range children {
		if env["GOTOOLCHAIN"] == "local" {
			pinned++
		}
	}
	if pinned != 1 {
		t.Errorf("%d of %d children ran under the installed toolchain, want exactly 1: the decision is taken "+
			"once per probe and every later child runs under its answer", pinned, len(children))
	}
}

// TestProbe_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk: the probe refuses
// with the same sentence as every other surface, because there is one sentence.
func TestProbe_NamesKanonarionAsThePinnerWhenNoToolchainIsOnDisk(t *testing.T) {
	h := localtest.NewHost(t, false)

	_, err := builder.New(h.GoBinary).Probe(context.Background(), h.Tree)

	if err == nil {
		t.Fatal("Probe succeeded with no toolchain on this host that could serve the tree")
	}
	for _, want := range []string{"kanonarion pins the toolchain", "go >= 1.99.0", "golang.org/dl/go1.99.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	h.AssertNeverEscalated(t)
}

// TestProbe_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheTree is the
// control: a toolchain is on disk and must stay unused.
func TestProbe_LeavesTheInstalledToolchainAloneWhenItSatisfiesTheTree(t *testing.T) {
	h := localtest.NewHost(t, true)
	h.NeverRefuse(t)

	if _, err := builder.New(h.GoBinary).Probe(context.Background(), h.Tree); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	h.AssertNeverEscalated(t)
}
