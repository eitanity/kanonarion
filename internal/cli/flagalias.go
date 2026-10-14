package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// deprecatedAlias is the old spelling of a renamed string flag. It stays
// accepted, hidden, for one release so scripts keep working, and warns on stderr
// so stdout (and --json) is unchanged.
type deprecatedAlias struct {
	oldName string
	newName string
	value   string
}

// registerDeprecatedAlias registers oldName on cmd as a hidden spelling of the
// already-registered flag newName.
func registerDeprecatedAlias(cmd *cobra.Command, oldName, newName string) *deprecatedAlias {
	a := &deprecatedAlias{oldName: oldName, newName: newName}
	cmd.Flags().StringVar(&a.value, oldName, "", "deprecated spelling of --"+newName)
	hideFlag(cmd, oldName)
	return a
}

// resolve returns the value the command acts on: current (the new flag's) unless
// the old spelling was typed. Both typed together is refused rather than one
// silently winning, because one of the two lines the caller wrote would do
// nothing.
func (a *deprecatedAlias) resolve(cmd *cobra.Command, current string, stderr io.Writer) (string, error) {
	if !cmd.Flags().Changed(a.oldName) {
		return current, nil
	}
	if cmd.Flags().Changed(a.newName) {
		return "", &exitError{
			code: ExitConfig,
			msg: fmt.Sprintf("--%s is the deprecated spelling of --%s on %s and both were given; pass --%s only",
				a.oldName, a.newName, cmd.Name(), a.newName),
		}
	}
	if _, err := fmt.Fprintf(stderr, "warning: --%s is deprecated on %s and will be removed; use --%s\n",
		a.oldName, cmd.Name(), a.newName); err != nil {
		return "", fmt.Errorf("writing deprecation warning: %w", err)
	}
	return a.value, nil
}
