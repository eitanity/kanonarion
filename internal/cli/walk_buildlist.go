package cli

import (
	"fmt"
	"io"
	"strings"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// buildListUnavailablePartialMsg is what exit 1 says when a walk's module set is
// the manifest's require directives rather than the resolved build. It names the
// gap rather than the mechanism: nothing in the walk failed, and the module set
// is still not the one that compiles.
const buildListUnavailablePartialMsg = "walk partial: the build list was unavailable, " +
	"so this walk covers the go.mod require directives rather than the modules that compile"

// writeBuildListUnavailable states that a walk's module set came from the go.mod
// require directives because the Go toolchain could not compute the build list,
// and prints nothing at all for a walk whose build list resolved.
//
// The reason is the toolchain's own, quoted from the record rather than
// paraphrased, because it is the half a reader acts on: a missing go.sum entry
// names the module to download, and no wording of ours could.
func writeBuildListUnavailable(w io.Writer, g walkdomain.Graph) error {
	if g.BuildListUnavailable == "" {
		return nil
	}
	if _, err := fmt.Fprintf(w,
		"build list unavailable:\n"+
			"  the Go toolchain could not compute this project's build list, so this walk covers "+
			"the go.mod require directives, not the modules that compile\n"+
			"  the toolchain's reason:\n%s",
		indentedToolchainReason(g.BuildListUnavailable)); err != nil {
		return fmt.Errorf("writing build-list disclosure: %w", err)
	}
	return nil
}

// indentedToolchainReason renders the toolchain's multi-line error one line per
// line, indented under the heading that introduces it, so a go command's own
// two-line "to add it:" remedy stays readable as the pair it is.
func indentedToolchainReason(reason string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(reason), "\n") {
		b.WriteString("    ")
		b.WriteString(strings.TrimRight(line, " \t"))
		b.WriteString("\n")
	}
	return b.String()
}
