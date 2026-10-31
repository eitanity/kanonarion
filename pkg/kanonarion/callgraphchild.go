package kanonarion

import (
	"io"

	"code.eitanity.com/kanonarion/internal/composition/cgchild"
)

// ServeCallGraphChild runs the call-graph child and returns its exit code for
// the caller to pass to os.Exit. Extraction and reachability analyse each
// module's call graph in a separate process: they start the running
// executable again with the argv "callgraph <module>@<version>" followed by
// --narrate-progress, --store-root=<dir> and, when they apply, --force and
// --from-walk <id>, and read the graph that process writes back from the store.
// An importing application serves that argv by calling this function with it,
// the arguments after the program name, in a process that runs nothing else,
// after registering the backends its parent registered.
//
// It runs the extraction the kanonarion binary's callgraph command runs, on
// the backend the store root's config.yaml (or --config, or
// KANONARION_CONFIG) selects, and exits with the same codes. Progress and
// failures go to stderr, where the parent reads them; nothing is written to
// stdout. Any other argv is refused with a non-zero code, and so is
// --from-modcache, which only the kanonarion binary sends its own child. The
// function may end the process itself when the parent set a memory ceiling the
// analysis reaches.
//
// Stability: public entrypoint (called by consumers); unstable pre-v1. The
// argv is whatever the parent sends; pass it through unchanged.
func ServeCallGraphChild(args []string, stdout, stderr io.Writer) int {
	return cgchild.Serve(args, stdout, stderr)
}
