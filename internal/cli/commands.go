package cli

import (
	"io"
	"sort"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

// RegisteredCommand describes one command in the CLI's command tree.
type RegisteredCommand struct {
	// Path is the command as a caller types it after "kanonarion": ["store",
	// "info"] for `kanonarion store info`. Its last element is the name.
	Path []string
	// Aliases are the spellings accepted in place of Path's last element —
	// "licence" for "license".
	Aliases []string
	// Runnable reports whether the path executes on its own. A grouping
	// command such as "store" does not, so naming it alone is a broken
	// instruction rather than a command.
	Runnable bool
	// Children names the subcommands registered under this path.
	Children []string
	// Flags are the long flag names accepted here, without their dashes,
	// including the persistent flags inherited from parent commands: a caller
	// can write --json on any command, and --help on all of them.
	Flags []string
}

// RegisteredCommands returns every command the CLI registers, parents before
// children, so a caller can ask what exists rather than keeping a list.
//
// The default help and completion commands are installed first. Cobra adds
// them during Execute, so a tree assembled without executing is two commands
// short of what a caller can actually type. Hidden commands are left out: the
// completion protocol's `__complete` is not a command anyone runs.
func RegisteredCommands() []RegisteredCommand {
	root := newRootCmd(io.Discard, io.Discard)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	var out []RegisteredCommand
	var walk func(path []string, c *cobra.Command)
	walk = func(path []string, c *cobra.Command) {
		var children []string
		for _, sub := range c.Commands() {
			if sub.Hidden {
				continue
			}
			children = append(children, sub.Name())
		}
		sort.Strings(children)
		if len(path) > 0 {
			out = append(out, RegisteredCommand{
				Path:     path,
				Aliases:  append([]string(nil), c.Aliases...),
				Runnable: c.Runnable(),
				Children: children,
				Flags:    longFlags(c),
			})
		}
		for _, sub := range c.Commands() {
			if sub.Hidden {
				continue
			}
			walk(append(append([]string(nil), path...), sub.Name()), sub)
		}
	}
	walk(nil, root)
	return out
}

// longFlags returns every long flag name accepted on c, its own and the
// persistent ones it inherits, without the leading dashes and in order.
//
// The default help flag is installed first: cobra adds it when the command
// runs, so a command read straight off the tree does not carry the --help
// every caller can type.
func longFlags(c *cobra.Command) []string {
	c.InitDefaultHelpFlag()
	seen := map[string]bool{}
	// LocalFlags and InheritedFlags each merge the parents' persistent flags
	// into the command before answering, which is what makes --json visible
	// here rather than only after a parse.
	for _, set := range []*flag.FlagSet{c.LocalFlags(), c.InheritedFlags()} {
		set.VisitAll(func(f *flag.Flag) { seen[f.Name] = true })
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
