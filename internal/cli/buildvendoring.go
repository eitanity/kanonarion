package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// buildVendoring is what a project-scoped answer needs to say about itself
// before it says anything else: whether the project it describes compiles from
// a vendored tree.
//
// A vendored project builds from the bytes under vendor/. Every answer the
// manifest-resolving commands give — audit's rows, a walk's graph, the
// verification coverage over it — describes the modules go.mod RESOLVES, which
// is a claim about what a proxy would serve, not about what ships. The two are
// usually the same and are not required to be, and the whole of the tampering
// question lives in the gap. A reader given no notice cannot tell which of the
// two they were told about; a reader given this line can, and knows which
// command measures the other one.
//
// Detection is the presence of vendor/modules.txt beside the manifest, which is
// exactly what the toolchain keys `-mod=vendor` on. Nothing here changes a
// verdict: it states a fact that was always true and never said.
type buildVendoring struct {
	// Known is false when there is no project directory to look in — a walk of
	// a published coordinate has none, and a stored walk's recorded directory is
	// provenance that may have moved. An unknown is stated as an unknown rather
	// than answered as "not vendored", which would be a claim the run never
	// checked.
	Known bool `json:"vendoring_known"`
	// Vendored reports vendor/modules.txt beside the manifest.
	Vendored bool `json:"vendored"`
	// ModulesTxt is the path that was looked for, so a reader who disagrees can
	// go and look at the same place.
	ModulesTxt string `json:"vendor_modules_txt,omitempty"`
}

// detectBuildVendoringForGoMod answers for a project identified by its go.mod
// path. An empty path is an unknown, not a negative.
func detectBuildVendoringForGoMod(goModPath string) buildVendoring {
	if goModPath == "" {
		return buildVendoring{}
	}
	return detectBuildVendoringInDir(filepath.Dir(goModPath))
}

// detectBuildVendoringInDir answers for a project rooted at dir.
//
// A directory that cannot be read at all is reported as unknown rather than as
// not vendored: a stored walk names the tree it was taken from, and that tree
// may since have moved or gone. Degrading to "no vendor tree here" would let a
// missing checkout answer a question about the build.
func detectBuildVendoringInDir(dir string) buildVendoring {
	if dir == "" {
		return buildVendoring{}
	}
	if _, err := os.Stat(dir); err != nil {
		return buildVendoring{}
	}
	modulesTxt := filepath.Join(dir, "vendor", "modules.txt")
	if _, err := os.Stat(modulesTxt); err != nil {
		return buildVendoring{Known: true}
	}
	return buildVendoring{Known: true, Vendored: true, ModulesTxt: modulesTxt}
}

// writeBuildVendoring states the disclosure, and states nothing at all when the
// project is not vendored or the question could not be answered.
//
// Silence is the right answer for an unvendored project: the commands' existing
// wording already describes resolved modules, so there is no ambiguity to
// resolve and a line saying "not vendored" on every run would train the reader
// to skip the block that matters. It goes to the caller's report channel
// alongside the other basis lines, never to the data channel, because a
// statement about a run is not one of the run's rows.
func writeBuildVendoring(w io.Writer, v buildVendoring) error {
	if !v.Known || !v.Vendored {
		return nil
	}
	if _, err := fmt.Fprintf(w, "vendored build:\n"+
		"  %s is present beside go.mod, so this project compiles the bytes under vendor/\n"+
		"  this answer describes the modules the manifest resolves, not those bytes; "+
		"`kanonarion vendor` is what measures the vendored tree\n",
		v.ModulesTxt); err != nil {
		return fmt.Errorf("writing vendoring disclosure: %w", err)
	}
	return nil
}
