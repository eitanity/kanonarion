package cli

import (
	"io"
	"regexp"
	"testing"

	"github.com/spf13/cobra"
)

// ticketIDPattern matches internal tracker references that must never
// appear in user-facing help text.
var ticketIDPattern = regexp.MustCompile(`KN-[0-9]+`)

// TestHelpFieldsCarryNoTicketIDs walks the entire cobra command tree and
// asserts that no user-facing help field (Use/Short/Long/Example) leaks an
// internal ticket identifier. Source comments are intentionally not
// inspected — only the strings cobra renders in --help output.
func TestHelpFieldsCarryNoTicketIDs(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)

	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		fields := map[string]string{
			"Use":     cmd.Use,
			"Short":   cmd.Short,
			"Long":    cmd.Long,
			"Example": cmd.Example,
		}
		for name, value := range fields {
			if match := ticketIDPattern.FindString(value); match != "" {
				t.Errorf("command %q field %s leaks ticket ID %q: %q",
					cmd.CommandPath(), name, match, value)
			}
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
}
