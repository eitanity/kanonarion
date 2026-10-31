package cli

import (
	"io"
	"testing"

	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
)

// The callgraph command accepts every flag a call-graph child is started with,
// of the same kind, so the binary's child and an application's read one
// command line.
func TestCallGraphCommand_AcceptsEveryChildFlag(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	cmd, _, err := root.Find([]string{cgports.ChildCommand})
	if err != nil || cmd.Name() != cgports.ChildCommand {
		t.Fatalf("no %q command: %v", cgports.ChildCommand, err)
	}
	for _, f := range cgports.ChildFlags {
		fl := cmd.Flags().Lookup(f.Name)
		if fl == nil {
			fl = cmd.InheritedFlags().Lookup(f.Name)
		}
		if fl == nil {
			t.Errorf("callgraph has no --%s", f.Name)
			continue
		}
		if isBool := fl.Value.Type() == "bool"; isBool != f.Bool {
			t.Errorf("--%s is %s on callgraph, and the child reads it as bool=%v", f.Name, fl.Value.Type(), f.Bool)
		}
	}
}
