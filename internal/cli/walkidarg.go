package cli

import (
	"fmt"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"
)

// looksLikeWalkID reports whether an argument has a walk id's shape. Walk ids
// are ULIDs, so the shape is decidable without a store read — which is what lets
// a command refuse a walk id in a coordinate's slot by saying so, instead of
// parsing it as a module path.
func looksLikeWalkID(arg string) bool {
	_, err := ulid.ParseStrict(arg)
	return err == nil
}

// moduleVersionRequired is the refusal for a module argument that named no
// version.
//
// A walk id is refused as one, by shape, rather than read as a module path:
// parsed as a path it produced "use <id>@<version> or <id>@latest", advice whose
// second failure was the reader following it.
func moduleVersionRequired(cmdName, path string) error {
	if looksLikeWalkID(path) {
		return &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"%q is a walk id, and %s takes a module coordinate. To read that walk:\n  kanonarion walk-show %s",
			path, cmdName, path)}
	}
	return fmt.Errorf("version required: use %s@<version> or %s@latest", path, path)
}

// oneWalkID takes the walk a command is about from either its positional slot
// or --walk-id.
//
// Both spellings exist because the sibling commands disagree: vuln-by-id,
// reachability and vuln-show take the flag while others take the positional, and
// a caller reaching for the wrong one spends a round trip on a grammar rather
// than on the question. Naming both twice is refused rather than resolved by
// precedence, since the two values may differ and nothing here can say which one
// was meant.
func oneWalkID(cmd *cobra.Command, args []string, flagID string) (string, error) {
	switch {
	case len(args) > 1:
		return "", usageErr(cmd)
	case len(args) == 1 && flagID != "":
		return "", &exitError{code: ExitConfig, msg: fmt.Sprintf(
			"two walks named: %q positionally and %q on --walk-id; give one",
			args[0], flagID)}
	case len(args) == 1:
		return args[0], nil
	case flagID != "":
		return flagID, nil
	}
	return "", usageErr(cmd)
}
