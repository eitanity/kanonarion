package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/tools/go/packages"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/gotoolchain"
)

// The rule this guard holds the whole tree to is in docs/cli/conventions.md:
// "Every remedy printed is an invocation this CLI's own parser accepts."
//
// It has been broken nine times, and every previous check looked for a known-bad
// SPELLING — a literal "<dir>", a "--module" count, a named filename. A spelling
// only ever catches the site that was reported, which is why this one derives
// its subject from the source and its verdict from the CLI's own command tree:
// nothing here names a file, and the set of commands that require a coordinate
// is read off the cobra Use lines, so it drains as the tree moves.

// The values a runtime operand stands in for while a printed line is judged.
// They are shapes, not examples: the guard asks whether a slot holds a
// coordinate, not which module it names.
const (
	standInCoordinate = "example.com/mod@v1.0.0"
	standInPath       = "example.com/mod"
	standInVersion    = "v1.0.0"
	standInWalkID     = "01M0VG1267S1XDJGDFZTVRPM84"
	// standInOpaque marks a value the source does not describe. It is a byte no
	// printed line can contain, so a slot carrying one is visibly unproven rather
	// than quietly plausible.
	standInOpaque = "\x00"
)

// coordinateTypeName is the value object every proven coordinate has, or is
// derived from.
const coordinateTypeName = "code.eitanity.com/kanonarion/internal/coordinate.ModuleCoordinate"

// -- what the guard reads ----------------------------------------------------

// printedMessage is one string-valued expression from the shipped source,
// rendered as the text it prints, together with the function it is built in.
type printedMessage struct {
	file string
	line int
	text string
	// scope is what the enclosing function holds. It decides whether a
	// placeholder is a gap the reader must fill or a value that was in hand and
	// thrown away — the distinction between the two `<version>` sites in
	// provenance_basis.go, one of which is correct.
	scope scopeFacts
}

// scopeFacts says which kinds of value the function building a message could
// have substituted. It is read from the enclosing function's parameters,
// receiver and named results — those are the values the message is
// unambiguously built from, and widening it to every identifier in the body
// would call a value "in hand" that is computed after the message is built —
// and from one level inside a struct among them, because a builder handed a
// struct holds what the struct holds.
//
// The three facts stay separate all the way to the verdict. Disjoining them at
// the point of judgement is what made the obvious version of the struct reach
// unusable: it read a path out of a struct, called it "a value", and then
// reported a <version> placeholder printed by a builder that has no version.
type scopeFacts struct {
	hasCoordinate bool
	hasPath       bool
	hasVersion    bool
}

func (s *scopeFacts) observe(o scopeFacts) {
	s.hasCoordinate = s.hasCoordinate || o.hasCoordinate
	s.hasPath = s.hasPath || o.hasPath
	s.hasVersion = s.hasVersion || o.hasVersion
}

// slotFact is the one fact that would fill a given placeholder. A coordinate
// fills a path slot and a version slot; neither of them alone fills the other,
// and neither alone fills a whole-coordinate slot.
type slotFact int

const (
	fillNothing slotFact = iota
	fillPath
	fillVersion
	fillCoordinate
)

func (f slotFact) String() string {
	switch f {
	case fillPath:
		return "the module path"
	case fillVersion:
		return "the version"
	case fillCoordinate:
		return "the coordinate"
	case fillNothing:
		return "nothing the guard can name"
	}
	return "nothing the guard can name"
}

func (s scopeFacts) holds(f slotFact) bool {
	switch f {
	case fillCoordinate:
		return s.hasCoordinate
	case fillVersion:
		return s.hasVersion || s.hasCoordinate
	case fillPath:
		return s.hasPath || s.hasCoordinate
	case fillNothing:
		return false
	}
	return false
}

// placeholdersIn returns the <…> slots written into one argument, lowercased.
func placeholdersIn(arg string) []string {
	var out []string
	for i := 0; i < len(arg); i++ {
		if arg[i] != '<' {
			continue
		}
		j := strings.IndexByte(arg[i:], '>')
		if j < 0 {
			break
		}
		out = append(out, strings.ToLower(arg[i+1:i+j]))
		i += j
	}
	return out
}

// placeholderWants says which fact would have filled a placeholder, read off
// the word the author wrote inside the angle brackets. A slot the guard cannot
// place wants nothing and is never reported: a guard that failed on a correct
// message would be suppressed, and a hole is the cheaper failure.
func placeholderWants(name string) slotFact {
	wantsVersion := strings.Contains(name, "version")
	wantsPath := strings.Contains(name, "mod") || strings.Contains(name, "path") ||
		strings.Contains(name, "dir")
	switch {
	case strings.Contains(name, "coord") || (wantsPath && wantsVersion):
		return fillCoordinate
	case wantsVersion:
		return fillVersion
	case wantsPath:
		return fillPath
	}
	return fillNothing
}

var (
	repoPackagesOnce sync.Once
	repoPackages     []*packages.Package
	repoPackagesErr  error
)

// loadRepoPackages type-checks the whole module once per test binary. Types are
// needed rather than syntax alone because the question a slot poses — "is this
// a coordinate or a bare path" — is answered by coordinate.ModuleCoordinate,
// and a guard that answered it from identifier spelling would be another
// known-bad-spelling check.
func loadRepoPackages(t *testing.T) []*packages.Package {
	t.Helper()
	repoPackagesOnce.Do(func() {
		cfg := &packages.Config{
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
				packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
			Dir: filepath.Join("..", ".."),
		}
		repoPackages, repoPackagesErr = packages.Load(cfg, "./...")
	})
	if repoPackagesErr != nil {
		t.Fatalf("loading the module for the remedy guard: %v", repoPackagesErr)
	}
	return repoPackages
}

// -- the guard ---------------------------------------------------------------

// TestEveryPrintedInvocationIsAcceptedByTheParser is the class, not a site: it
// finds every command line the shipped source can print, renders the runtime
// values it is built from as the shapes the source proves them to be, and
// pushes the result through the CLI's own parser.
func TestEveryPrintedInvocationIsAcceptedByTheParser(t *testing.T) {
	slots := coordinateSlots(t)
	messages := allPrintedMessages(t)
	checked := 0
	for _, m := range messages {
		for _, inv := range invocationsIn(m.text) {
			for _, conjunct := range strings.Split(inv.line, " && ") {
				line, cmdName, positionals, ok := readInvocation(t, strings.TrimSpace(conjunct))
				if !ok {
					// Prose that happens to name the binary — "kanonarion records are
					// Go-only". A subcommand this tree does not have is not an
					// invocation to judge.
					continue
				}
				checked++
				for _, v := range invocationViolations(t, slots, line, cmdName, positionals, inv.presented, m.scope) {
					t.Errorf("%s:%d prints %q\n  %s\n  (rendered from: %q)",
						m.file, m.line, line, v, m.text)
				}
			}
		}
	}
	// A guard that reached nothing passes by finding nothing. The floor is well
	// under the population so ordinary churn does not trip it.
	if checked < 200 {
		t.Fatalf("judged only %d printed invocations across %d messages; the guard is not reaching the source",
			checked, len(messages))
	}
	t.Logf("judged %d printed invocations across %d messages", checked, len(messages))
}

// invocationViolations is the whole verdict for one rendered command line, and
// is pure so the control below can plant lines the tree does not contain.
//
// presented says whether the line was printed as a line — starting the message
// or its own line within it — rather than named inside a sentence. A line owes
// the whole parse. A mention owes the arguments the command requires and the
// coordinate shape of those it prints: "run 'kanonarion license' first" sends
// the reader to a command that refuses the empty argument list.
func invocationViolations(t *testing.T, slots map[string]coordinateSlotSpec, line, cmdName string,
	positionals []string, presented bool, scope scopeFacts,
) []string {
	t.Helper()
	var out []string
	if presented {
		if err := parseInvocation(t, strings.ReplaceAll(line, standInOpaque, "x")); err != nil {
			out = append(out, "the CLI's own parser rejects it: "+err.Error())
		}
	} else if err := mentionArity(line, cmdName, positionals); err != nil {
		out = append(out, "names the command without the arguments it requires: "+err.Error())
	}
	// A command that counts its arguments in RunE passes cobra's validation with
	// none, so a line or mention short of them parses and still does not run.
	if want := runEArity(t)[slots[cmdName].use]; len(positionals) < want && !slices.Contains(splitInvocation(line), "--help") {
		out = append(out, fmt.Sprintf("names %d argument(s) where %q refuses fewer than %d", len(positionals), slots[cmdName].use, want))
	}
	spec, known := slots[cmdName]
	if !known {
		return out
	}
	for i, required := range spec.coordinateAt {
		if !required || i >= len(positionals) {
			continue
		}
		if v := coordinateSlotViolation(positionals[i], scope); v != "" {
			out = append(out, fmt.Sprintf("positional %d %s (%q takes a module coordinate there)",
				i+1, v, spec.use))
		}
	}
	return out
}

var (
	runEArityOnce  sync.Once
	runEArityByUse map[string]int
)

// runEArity reads, per Use line, the fewest positionals a command's RunE accepts
// before it does anything else: a top-level `if len(args) … N { return
// usageErr(cmd) }`. It is read off the source because cobra never sees it.
func runEArity(t *testing.T) map[string]int {
	t.Helper()
	runEArityOnce.Do(func() {
		runEArityByUse = map[string]int{}
		for _, p := range loadRepoPackages(t) {
			if !strings.HasSuffix(p.PkgPath, "/internal/cli") {
				continue
			}
			for _, f := range p.Syntax {
				ast.Inspect(f, func(n ast.Node) bool {
					if lit, ok := n.(*ast.CompositeLit); ok {
						if use, fewest, found := commandArity(lit); found {
							runEArityByUse[use] = fewest
						}
					}
					return true
				})
			}
		}
	})
	return runEArityByUse
}

// commandArity returns a cobra.Command literal's Use line and the fewest
// positionals its RunE accepts, when its RunE opens on a count refusal.
func commandArity(lit *ast.CompositeLit) (string, int, bool) {
	use, run := commandParts(lit)
	if use == "" || run == nil || run.Body == nil {
		return "", 0, false
	}
	for _, stmt := range run.Body.List {
		ifs, ok := stmt.(*ast.IfStmt)
		if !ok || !returnsUsageErr(ifs.Body) {
			// A count checked only after another way out is not one every
			// invocation owes.
			if returns(stmt) {
				break
			}
			continue
		}
		if fewest, counted := countRefused(ifs.Cond); counted {
			return use, fewest, true
		}
	}
	return "", 0, false
}

// commandParts reads the Use line and the RunE literal out of a command literal.
func commandParts(lit *ast.CompositeLit) (use string, run *ast.FuncLit) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, isIdent := kv.Key.(*ast.Ident)
		if !isIdent {
			continue
		}
		switch key.Name {
		case "Use":
			if b, isLit := kv.Value.(*ast.BasicLit); isLit {
				use = literalValue(b)
			}
		case "RunE":
			if fn, isFn := kv.Value.(*ast.FuncLit); isFn {
				run = fn
			}
		}
	}
	return use, run
}

// countRefused reads `len(args) != N`, `len(args) < N` or `len(args) == 0` as
// the fewest positionals the guarded refusal lets through.
func countRefused(cond ast.Expr) (int, bool) {
	cmp, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return 0, false
	}
	call, isCall := cmp.X.(*ast.CallExpr)
	n, isInt := cmp.Y.(*ast.BasicLit)
	if !isCall || !isInt || n.Kind != token.INT {
		return 0, false
	}
	if fn, isIdent := call.Fun.(*ast.Ident); !isIdent || fn.Name != "len" {
		return 0, false
	}
	v, err := strconv.Atoi(n.Value)
	if err != nil {
		return 0, false
	}
	switch {
	case cmp.Op == token.NEQ || cmp.Op == token.LSS:
		return v, true
	case cmp.Op == token.EQL && v == 0:
		return 1, true
	}
	return 0, false
}

// returns reports whether stmt holds a return statement.
func returns(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
		}
		return !found
	})
	return found
}

// returnsUsageErr reports whether a block returns usageErr(...).
func returnsUsageErr(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		if call, isCall := ret.Results[0].(*ast.CallExpr); isCall {
			if fn, isIdent := call.Fun.(*ast.Ident); isIdent && fn.Name == "usageErr" {
				return true
			}
		}
	}
	return false
}

// mentionArity holds a command named inside a sentence to the positional count
// it requires, without the parse a presented line gets: a mention's flags are
// judged by TestEveryPrintedFlagIsOneTheCommandDefines.
func mentionArity(line, cmdName string, positionals []string) error {
	// Asking for help is the one invocation cobra answers before it counts.
	if slices.Contains(splitInvocation(line), "--help") {
		return nil
	}
	root := newRootCmd(io.Discard, io.Discard)
	cmd, _, err := root.Find(strings.Fields(cmdName))
	if err != nil {
		return fmt.Errorf("resolving %q: %w", cmdName, err)
	}
	return cmd.ValidateArgs(positionals) //nolint:wrapcheck // cobra's own sentence is the verdict
}

// TestEveryPrintedFlagIsOneTheCommandDefines holds every long flag the shipped
// source prints to a command that accepts it. A flag inside a line is judged
// against the command the line invokes, whether the line is presented or
// mentioned. A flag in the prose around it is judged by where the string is
// built: outside internal/cli no code knows which command is running, so prose
// there may name only a flag every command defines; a remedy needing any other
// belongs in a full invocation, or in the CLI.
func TestEveryPrintedFlagIsOneTheCommandDefines(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	judged, outside := 0, 0
	for _, m := range allFlagMessages(t) {
		n, faults := flagViolations(t, root, m.text, insideCLI(m.file))
		judged += n
		if !insideCLI(m.file) {
			outside++
		}
		for _, v := range faults {
			t.Errorf("%s:%d %s\n  (rendered from: %q)", m.file, m.line, v, m.text)
		}
	}
	// The floor is well under the population so ordinary churn does not trip it.
	if judged < 300 || outside < 20 {
		t.Fatalf("judged only %d printed flags, %d strings outside internal/cli; the guard is not reaching the source",
			judged, outside)
	}
	t.Logf("judged %d printed flags", judged)
}

// insideCLI reports whether a file is in the package that knows which command
// is running.
func insideCLI(file string) bool {
	return strings.Contains(filepath.ToSlash(file), "/internal/cli/")
}

// flagViolations is the flag verdict on one message, pure so the control below
// can plant text. It returns how many flags it judged and what it found.
func flagViolations(t *testing.T, root *cobra.Command, text string, cliBuilt bool) (int, []string) {
	t.Helper()
	var out []string
	judged := 0
	prose := text
	for _, inv := range invocationsIn(text) {
		prose = strings.Replace(prose, inv.line, "", 1)
		for _, conjunct := range strings.Split(inv.line, " && ") {
			conjunct = strings.TrimSpace(conjunct)
			line, cmdName, _, ok := readInvocation(t, conjunct)
			if !ok {
				prose += " " + conjunct
				continue
			}
			// What the line read stops short of is the sentence it sits in.
			prose += " " + conjunct[min(len(conjunct), len(line)):]
			cmd, _, err := root.Find(strings.Fields(cmdName))
			if err != nil {
				t.Fatalf("resolving %q: %v", cmdName, err)
			}
			for _, field := range splitInvocation(line) {
				name, isFlag := strings.CutPrefix(field, "--")
				if !isFlag || name == "" {
					continue
				}
				name, _, _ = strings.Cut(name, "=")
				// A runtime value spliced on after the flag is not part of its name.
				name, _, _ = strings.Cut(name, standInOpaque)
				judged++
				if !flagDefinedOn(root, cmd, name) {
					out = append(out, fmt.Sprintf("prints --%s in %q, a flag %q does not define", name, line, cmdName))
				}
			}
		}
	}
	if isArgumentFragment(prose) {
		return judged, out
	}
	for _, name := range flagTokensIn(prose) {
		judged++
		if !cliBuilt && root.PersistentFlags().Lookup(name) == nil {
			out = append(out, fmt.Sprintf("prints --%s outside an invocation, from a package that cannot know which command is running", name))
		}
	}
	return judged, out
}

// isArgumentFragment reports whether text is argument words and no sentence: an
// argv element handed to a subprocess, or a piece spliced into an invocation.
// Every token is a flag, a <placeholder> or a value the source does not
// describe, so there is no prose for a reader to act on.
func isArgumentFragment(text string) bool {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return true
	}
	for _, f := range fields {
		if !strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "<") && !strings.Contains(f, standInOpaque) {
			return false
		}
	}
	return true
}

// flagDefinedOn reports whether cmd accepts --name, cobra's own help flag
// included.
func flagDefinedOn(root, cmd *cobra.Command, name string) bool {
	cmd.InitDefaultHelpFlag()
	for _, set := range []*pflag.FlagSet{cmd.Flags(), cmd.InheritedFlags(), root.PersistentFlags()} {
		if set.Lookup(name) != nil {
			return true
		}
	}
	return false
}

// flagTokensIn returns the names of the long flags text prints. A dash run
// inside a word, a bare "--" and a rule of dashes are not flags.
func flagTokensIn(text string) []string {
	var out []string
	for i := 0; i+2 < len(text); i++ {
		if text[i] != '-' || text[i+1] != '-' || (i > 0 && isFlagByte(text[i-1])) {
			continue
		}
		j := i + 2
		if text[j] < 'a' || text[j] > 'z' {
			i = j
			continue
		}
		for j < len(text) && isFlagByte(text[j]) {
			j++
		}
		out = append(out, strings.TrimRight(text[i+2:j], "-"))
		i = j
	}
	return out
}

func isFlagByte(b byte) bool {
	return b == '-' || b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// readInvocation resolves a candidate line against the CLI's own command tree
// and trims the prose that carries on after it.
//
// A printed line often sits inside a sentence — "so kanonarion walk --gomod
// ./go.mod records the current resolution" — and the words after the last
// argument are not arguments. The CLI itself says where the line ends: a token
// that is a bare English word cannot be an argument this tool takes, since
// every one of them carries a "/", "@", "." or a digit, and a flag's value is
// read as a value because cobra says that flag takes one.
func readInvocation(t *testing.T, line string) (trimmed, cmdName string, positionals []string, ok bool) {
	t.Helper()
	fields := splitInvocation(line)
	if len(fields) < 2 || fields[0] != "kanonarion" {
		return "", "", nil, false
	}
	root := newRootCmd(io.Discard, io.Discard)
	cmd, rest, err := root.Find(fields[1:])
	if err != nil || cmd == root {
		return "", "", nil, false
	}
	name := strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), root.Name()))
	head := len(fields) - len(rest)

	// One pass to place every token, a second to decide where the line stops.
	// The two are separate because a bare English word is only prose once the
	// command has the arguments it declares: "config set preferences.json true"
	// ends in one.
	slots := placeInvocationTokens(root, cmd, rest, head)
	cut := len(slots)
	for i, sl := range slots {
		if !sl.prose {
			continue
		}
		taken := make([]string, 0, i)
		for _, s := range slots[:i] {
			taken = append(taken, s.text)
		}
		if cmd.ValidateArgs(taken) == nil {
			cut = i
			break
		}
	}
	end := len(fields)
	if cut < len(slots) {
		end = slots[cut].field
	}
	for _, sl := range slots[:cut] {
		positionals = append(positionals, sl.text)
	}
	return joinInvocation(fields[:end]), name, positionals, true
}

// slot is one positional token of an invocation: its text, its field index in
// the whole line, and whether it reads as prose.
type slot struct {
	text  string
	field int
	prose bool
}

// placeInvocationTokens is the positional tokens of rest, the flags and their
// values skipped.
func placeInvocationTokens(root, cmd *cobra.Command, rest []string, head int) []slot {
	var slots []slot
	for i := 0; i < len(rest); i++ {
		tok := rest[i]
		if strings.HasPrefix(tok, "-") && tok != "-" {
			if !strings.Contains(tok, "=") && flagTakesValue(root, cmd, tok) && i+1 < len(rest) {
				i++
			}
			continue
		}
		slots = append(slots, slot{text: tok, field: head + i, prose: isProseWord(tok)})
	}
	return slots
}

// joinInvocation puts a split line back together with the quoting a shell needs,
// so an argument carrying a space is still one argument when the parser reads it
// again.
func joinInvocation(fields []string) string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if strings.ContainsAny(f, " \t") {
			f = "'" + f + "'"
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

// flagTakesValue asks the command itself, so a boolean flag does not swallow
// the word after it.
func flagTakesValue(root, cmd *cobra.Command, tok string) bool {
	name := strings.TrimLeft(tok, "-")
	lookup := func(set *pflag.FlagSet) *pflag.Flag {
		if set == nil {
			return nil
		}
		if f := set.Lookup(name); f != nil {
			return f
		}
		if len(name) == 1 {
			return set.ShorthandLookup(name)
		}
		return nil
	}
	for _, set := range []*pflag.FlagSet{cmd.Flags(), cmd.InheritedFlags(), root.PersistentFlags()} {
		if f := lookup(set); f != nil {
			return f.NoOptDefVal == ""
		}
	}
	// An unknown flag is left in place so the parser reports it rather than the
	// guard quietly trimming a line that does not run.
	return false
}

// isProseWord reports whether a token is an English word rather than an
// argument. No argument this CLI takes is bare lowercase letters: coordinates
// and paths carry "/" or "@", ids and versions carry digits, symbol ids carry
// ".".
func isProseWord(tok string) bool {
	if len(tok) < 2 {
		return false
	}
	for _, r := range tok {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// coordinateSlotViolation judges one argument written into a slot the command
// declares as a module coordinate.
//
// A slot rendered wholly from literals must parse as a coordinate. A slot
// carrying a runtime value must at least show the coordinate's shape: the
// defect this closes is a builder that had the version and passed only the
// path, and the "@" is what the source proves either way.
func coordinateSlotViolation(arg string, scope scopeFacts) string {
	switch {
	case strings.ContainsAny(arg, "<>"):
		// A placeholder is a gap the reader fills. That is legitimate where there
		// is nothing to fill THAT slot from — a store holding no records at all can
		// only describe the command that makes one — and it is the defect where the
		// value was in hand and discarded. Each placeholder is matched to the fact
		// that would fill it, so "give a version and run: … @<version>", printed by
		// a builder holding a path and no version, is not reported against the path.
		for _, name := range placeholdersIn(arg) {
			if want := placeholderWants(name); scope.holds(want) {
				return fmt.Sprintf("prints the placeholder <%s> in %q while its builder holds %s",
					name, arg, want)
			}
		}
		return ""
	case strings.Contains(arg, standInOpaque):
		if strings.Contains(arg, "@") {
			return ""
		}
		return fmt.Sprintf("is %q, a runtime value the source does not prove to be a coordinate",
			strings.ReplaceAll(arg, standInOpaque, "…"))
	default:
		if _, err := coordinate.ParseModuleCoordinate(arg); err != nil {
			return fmt.Sprintf("is %q, which is not a module coordinate", arg)
		}
		return ""
	}
}

// -- the command table, derived from the CLI itself --------------------------

// coordinateSlotSpec records, for one subcommand, which of its positionals must
// be a module coordinate.
type coordinateSlotSpec struct {
	use          string
	coordinateAt []bool
}

// coordinateSlots reads every subcommand's own Use line and works out which
// positionals it declares as a required module coordinate. Deriving it is the
// point: a hand-kept list of commands is what let six command paths sit outside
// every previous sweep.
func coordinateSlots(t *testing.T) map[string]coordinateSlotSpec {
	t.Helper()
	out := map[string]coordinateSlotSpec{}
	root := newRootCmd(io.Discard, io.Discard)
	var visit func(prefix string, cmds []*cobra.Command)
	visit = func(prefix string, cmds []*cobra.Command) {
		for _, c := range cmds {
			name := strings.Fields(c.Use)[0]
			full := name
			if prefix != "" {
				full = prefix + " " + name
			}
			out[full] = coordinateSlotSpec{use: c.Use, coordinateAt: coordinateSlotsOf(c.Use)}
			visit(full, c.Commands())
		}
	}
	visit("", root.Commands())
	if len(out) < 20 {
		t.Fatalf("read only %d subcommands off the root command; the command tree is not being reached", len(out))
	}
	return out
}

// coordinateSlotsOf maps a Use line to one flag per positional saying whether
// that positional must be a module coordinate.
//
// "<module>@<version>" and "<module@version>" must be; "<module[@version]>",
// "<module>[@<version>]" and "[<module>]" take a bare path too, so a line that
// prints one is not wrong. A Use line offering alternative grammars constrains
// nothing positionally and is left alone.
func coordinateSlotsOf(use string) []bool {
	fields := strings.Fields(use)
	if len(fields) < 2 {
		return nil
	}
	rest := strings.Join(fields[1:], " ")
	if strings.ContainsAny(rest, "|(") {
		return nil
	}
	var out []bool
	for _, tok := range fields[1:] {
		out = append(out, strings.Contains(tok, "<module") &&
			strings.Contains(tok, "@") &&
			!strings.Contains(tok, "["))
	}
	return out
}

// -- reading the printed lines out of the source -----------------------------

// invocation is one command line lifted out of a message, with whether it was
// printed as a line of its own.
type invocation struct {
	line      string
	presented bool
}

// invocationsIn returns every command line a message prints. An invocation runs
// from "kanonarion " to the end of its line, or to the punctuation that closes
// it where the sentence carries on — a remedy quoted inside prose ends at its
// quote, one followed by a clause ends at the comma, and one piped into another
// command ends at the pipe.
func invocationsIn(text string) []invocation {
	var out []invocation
	for i := 0; i+len("kanonarion ") <= len(text); {
		at := strings.Index(text[i:], "kanonarion ")
		if at < 0 {
			break
		}
		at += i
		i = at + len("kanonarion ")
		if at > 0 && !isInvocationOpener(rune(text[at-1])) {
			continue
		}
		var opener byte
		if at > 0 && (text[at-1] == '\'' || text[at-1] == '`' || text[at-1] == '"') {
			opener = text[at-1]
		}
		line := invocationEndingAt(text[at:], opener)
		if line == "" {
			continue
		}
		out = append(out, invocation{line: line, presented: opener == 0 && startsALine(text, at)})
	}
	return out
}

// startsALine reports whether the invocation opens the message or opens a line
// within it. Indentation is transparent; anything else before it is prose.
func startsALine(text string, at int) bool {
	for i := at - 1; i >= 0; i-- {
		switch text[i] {
		case ' ', '\t':
		case '\n':
			return true
		default:
			return false
		}
	}
	return true
}

// isInvocationOpener reports whether a command line may start after r. It keeps
// "…kanonarion" inside a word — "for kanonarion" is prose — from being read as
// the start of one.
func isInvocationOpener(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\'', '"', '`', '(', ':', '>':
		return true
	}
	return false
}

// invocationEndingAt trims a command line off the front of text. It tracks
// quoting so a symbol ID carrying a comma stays inside the line it belongs to.
func invocationEndingAt(text string, opener byte) string {
	var quote rune
	for i, r := range text {
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"', '`':
			if byte(r) == opener {
				return strings.TrimSpace(text[:i])
			}
			quote = r
		case '\n', ')', '|', '—':
			return strings.TrimSpace(text[:i])
		case ',', ';':
			if separatorEndsLine(text, i) {
				return strings.TrimSpace(text[:i])
			}
		case '.':
			// A full stop closes the line; a lone "." is the argument that names
			// the working directory, so a dot after a space is kept.
			if fullStopEndsLine(text, i) {
				return strings.TrimSpace(text[:i])
			}
		}
	}
	return strings.TrimSpace(text)
}

// separatorEndsLine reports whether the comma or semicolon at text[i] ends the
// invocation: it is last, or followed by a space or a newline.
func separatorEndsLine(text string, i int) bool {
	return i+1 >= len(text) || text[i+1] == ' ' || text[i+1] == '\n'
}

// fullStopEndsLine reports whether the dot at text[i] is a full stop rather
// than a lone "." argument.
func fullStopEndsLine(text string, i int) bool {
	return i > 0 && text[i-1] != ' ' && (i+1 >= len(text) || text[i+1] == ' ' || text[i+1] == '\n')
}

// allPrintedMessages renders every string-valued expression in the shipped
// source that names the binary.
func allPrintedMessages(t *testing.T) []printedMessage {
	t.Helper()
	return printedMessagesWhere(t, func(text string) bool { return strings.Contains(text, "kanonarion ") })
}

// allFlagMessages renders every string-valued expression in the shipped source
// that prints a long flag, whether or not it names the binary.
func allFlagMessages(t *testing.T) []printedMessage {
	t.Helper()
	return printedMessagesWhere(t, func(text string) bool { return len(flagTokensIn(text)) > 0 })
}

func printedMessagesWhere(t *testing.T, keep func(string) bool) []printedMessage {
	t.Helper()
	var out []printedMessage
	for _, p := range loadRepoPackages(t) {
		if p.TypesInfo == nil {
			continue
		}
		for _, f := range p.Syntax {
			file := p.Fset.Position(f.Pos()).Filename
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			out = append(out, messagesInFile(p, f, file, keep)...)
		}
	}
	return out
}

func messagesInFile(p *packages.Package, f *ast.File, file string, keep func(string) bool) []printedMessage {
	var out []printedMessage
	consumed := map[ast.Node]bool{}
	fns := enclosingFunctions(f)
	record := func(pos token.Pos, text string) {
		if !keep(text) {
			return
		}
		out = append(out, printedMessage{
			file:  file,
			line:  p.Fset.Position(pos).Line,
			text:  text,
			scope: scopeOf(p, fns.at(pos), pos),
		})
	}
	// Format calls first, so their format literal is not judged again on its own
	// with its verbs unsubstituted.
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		idx, ok := formatArgIndex(call)
		if !ok || len(call.Args) <= idx {
			return true
		}
		// The format string is often written as several literals across lines, so
		// it is flattened first: judging one line of it alone leaves the verbs
		// unsubstituted and reports "%s" as a module path.
		var parts []string
		if !flattenConcat(p, call.Args[idx], consumed, fns, &parts) {
			return true
		}
		record(call.Args[idx].Pos(), renderFormat(strings.Join(parts, ""), p, call.Args[idx+1:], fns))
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BinaryExpr:
			if e.Op != token.ADD || consumed[e] {
				return true
			}
			var parts []string
			if !flattenConcat(p, e, consumed, fns, &parts) {
				return true
			}
			record(e.Pos(), strings.Join(parts, ""))
		case *ast.BasicLit:
			if e.Kind == token.STRING && !consumed[e] {
				record(e.Pos(), literalValue(e))
			}
		}
		return true
	})
	return out
}

// formatArgIndex reports which argument of a printf-family call carries the
// format string.
func formatArgIndex(call *ast.CallExpr) (int, bool) {
	var name string
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	case *ast.Ident:
		name = fn.Name
	default:
		return 0, false
	}
	switch name {
	case "Sprintf", "Errorf", "Printf", "printf", "Skipf", "Logf":
		return 0, true
	case "Fprintf":
		return 1, true
	}
	return 0, false
}

// renderFormat substitutes each verb with the shape its argument is proven to
// have, so the line the reader would be handed is what gets judged.
func renderFormat(format string, p *packages.Package, args []ast.Expr, fns funcIndex) string {
	var b strings.Builder
	next := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			b.WriteByte(format[i])
			continue
		}
		j := i + 1
		for j < len(format) && strings.ContainsRune("-+# 0123456789.*[]", rune(format[j])) {
			j++
		}
		if j >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		verb := format[j]
		i = j
		if verb == '%' {
			b.WriteByte('%')
			continue
		}
		var arg ast.Expr
		if next < len(args) {
			arg = args[next]
		}
		next++
		text := standInFor(p, arg, fns, 0)
		if verb == 'q' {
			text = strconv.Quote(text)
		}
		b.WriteString(text)
	}
	return b.String()
}

// flattenConcat renders a "+" chain as the one line it prints as. It reports
// false for a chain holding no string literal, which is arithmetic.
func flattenConcat(p *packages.Package, n ast.Expr, consumed map[ast.Node]bool, fns funcIndex, parts *[]string) bool {
	consumed[n] = true
	switch e := n.(type) {
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			*parts = append(*parts, standInOpaque)
			return false
		}
		left := flattenConcat(p, e.X, consumed, fns, parts)
		right := flattenConcat(p, e.Y, consumed, fns, parts)
		return left || right
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			*parts = append(*parts, standInOpaque)
			return false
		}
		*parts = append(*parts, literalValue(e))
		return true
	default:
		*parts = append(*parts, standInFor(p, e, fns, 0))
		return false
	}
}

// -- proving what a runtime value is -----------------------------------------

// standInFor renders one runtime operand as the shape the source proves it to
// have. Anything it cannot prove renders as standInOpaque: a guard that guessed
// would be wrong in the direction that matters, since the defect is a value
// that looks like a coordinate and is not.
func standInFor(p *packages.Package, e ast.Expr, fns funcIndex, depth int) string {
	if e == nil || depth > 6 {
		return standInOpaque
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			return literalValue(x)
		}
		return standInOpaque
	case *ast.ParenExpr:
		return standInFor(p, x.X, fns, depth+1)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return standInOpaque
		}
		return standInFor(p, x.X, fns, depth+1) + standInFor(p, x.Y, fns, depth+1)
	case *ast.CallExpr:
		return standInForCall(p, x, fns, depth)
	case *ast.SelectorExpr:
		if isCoordinateType(p, x) {
			return standInCoordinate
		}
		return standInForName(x.Sel.Name)
	case *ast.Ident:
		if isCoordinateType(p, x) {
			return standInCoordinate
		}
		if rhs, ok := fns.assignmentOf(p, x); ok {
			return standInFor(p, rhs, fns, depth+1)
		}
		return standInForName(x.Name)
	}
	if isCoordinateType(p, e) {
		return standInCoordinate
	}
	return standInOpaque
}

func standInForCall(p *packages.Package, call *ast.CallExpr, fns funcIndex, depth int) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return standInOpaque
	}
	if isCoordinateType(p, sel.X) {
		switch sel.Sel.Name {
		case "String":
			return standInCoordinate
		case "Path":
			return standInPath
		case "Version", "GitTagVersion":
			return standInVersion
		}
	}
	if isCoordinateType(p, call) {
		return standInCoordinate
	}
	_ = depth
	return standInOpaque
}

// standInForName is the last resort, and it only ever narrows: a name it does
// not recognise stays opaque, so the slot is reported as unproven rather than
// waved through.
func standInForName(name string) string {
	switch {
	case name == "walkID" || name == "WalkID" || strings.HasSuffix(name, "WalkID"):
		return standInWalkID
	case name == "path" || name == "modulePath" || strings.HasSuffix(name, "ModulePath"):
		return standInPath
	case name == "version" || name == "moduleVersion" || strings.HasSuffix(name, "ModuleVersion"):
		return standInVersion
	case namesCoordinate(name):
		// The codebase carries a coordinate as text under these names — "coord :=
		// c.ModulePath + \"@\" + c.ModuleVersion". Reading them is the guard's one
		// concession to spelling, and it only ever narrows: a slot it cannot place
		// is reported, never waved through.
		return standInCoordinate
	}
	return standInOpaque
}

// namesCoordinate reports whether name is one the codebase carries a
// coordinate as text under.
func namesCoordinate(name string) bool {
	return name == "coord" || name == "coordinate" || name == "mod" || name == "module" ||
		strings.HasSuffix(name, "Coord") || strings.HasSuffix(name, "Coordinate")
}

func isCoordinateType(p *packages.Package, e ast.Expr) bool {
	tv, ok := p.TypesInfo.Types[e]
	if !ok || tv.Type == nil {
		return false
	}
	return isCoordinateGoType(tv.Type)
}

func isCoordinateGoType(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path()+"."+obj.Name() == coordinateTypeName
}

// nameFacts reads what a parameter or field name says it holds. It is
// standInForName's vocabulary, split into the separate facts the verdict keeps
// apart: a name that says "path" establishes a path and NOT a version.
func nameFacts(name string) scopeFacts {
	switch standInForName(name) {
	case standInCoordinate:
		return scopeFacts{hasCoordinate: true}
	case standInVersion:
		return scopeFacts{hasVersion: true}
	case standInPath:
		return scopeFacts{hasPath: true}
	}
	return scopeFacts{}
}

// typeFacts reads what a parameter's TYPE says it holds, one level deep.
//
// One level, not a closure: a builder handed a struct holds what that struct's
// own fields hold — the native rollup carries the coordinate it names in a
// field, and reading only the parameter list called its placeholder legitimate —
// while chasing further would call a value "in hand" that the builder would have
// to go and fetch.
func typeFacts(p *packages.Package, e ast.Expr) scopeFacts {
	tv, ok := p.TypesInfo.Types[e]
	if !ok || tv.Type == nil {
		return scopeFacts{}
	}
	if isCoordinateGoType(tv.Type) {
		return scopeFacts{hasCoordinate: true}
	}
	t := tv.Type
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = ptr.Elem()
	}
	st, isStruct := t.Underlying().(*types.Struct)
	if !isStruct {
		return scopeFacts{}
	}
	var s scopeFacts
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		// A pointer-typed field is optional by construction — a filter's *Target is
		// nil whenever the operator named none — so the struct declaring it is not
		// the builder holding a value. Reporting it would fail the zero-result
		// notices, which name the filter when there was one and print the form when
		// there was not.
		if _, optional := f.Type().(*types.Pointer); optional {
			continue
		}
		if isCoordinateGoType(f.Type()) {
			s.hasCoordinate = true
		}
		s.observe(nameFacts(f.Name()))
	}
	return s
}

// -- the enclosing function --------------------------------------------------

// funcIndex maps a position to the function declaration containing it, and
// resolves a local to the expression it was assigned once.
type funcIndex struct {
	decls []*ast.FuncDecl
	lits  []*ast.FuncLit
}

func enclosingFunctions(f *ast.File) funcIndex {
	var idx funcIndex
	ast.Inspect(f, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			idx.decls = append(idx.decls, fn)
		case *ast.FuncLit:
			idx.lits = append(idx.lits, fn)
		}
		return true
	})
	return idx
}

func (i funcIndex) at(pos token.Pos) *ast.FuncDecl {
	for _, fn := range i.decls {
		if fn.Pos() <= pos && pos <= fn.End() {
			return fn
		}
	}
	return nil
}

// assignmentOf returns the single expression a local was assigned, when there
// is exactly one. A local written twice describes two lines, so it is left
// unproven rather than judged on whichever assignment came first.
func (i funcIndex) assignmentOf(p *packages.Package, id *ast.Ident) (ast.Expr, bool) {
	obj := p.TypesInfo.Uses[id]
	if obj == nil {
		return nil, false
	}
	var found ast.Expr
	count := 0
	bodies := make([]ast.Node, 0, len(i.decls)+len(i.lits))
	for _, fn := range i.decls {
		bodies = append(bodies, fn)
	}
	for _, fn := range i.lits {
		bodies = append(bodies, fn)
	}
	for _, body := range bodies {
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for k, lhs := range as.Lhs {
				lid, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if p.TypesInfo.Defs[lid] == obj || p.TypesInfo.Uses[lid] == obj {
					count++
					found = as.Rhs[k]
				}
			}
			return true
		})
	}
	if count != 1 {
		return nil, false
	}
	return found, true
}

// scopeOf reads what the function building a message was handed.
//
// Parameters, receiver and named results only: a value computed later in the
// body is not something the message "had". And a value the function has already
// established as absent is not in hand either — resolveLicenceBasis carries a
// version parameter and prints two <version> placeholders, one above the check
// that the version is set and one below it, and only the first is a value
// thrown away.
func scopeOf(p *packages.Package, fn *ast.FuncDecl, pos token.Pos) scopeFacts {
	var s scopeFacts
	if fn == nil || fn.Type == nil {
		return s
	}
	// reach says whether to look inside a struct here. It is true for what the
	// function was HANDED and false for what it returns: a result is the value
	// being built, and reading a coordinate out of the struct this function is on
	// its way to constructing would report every builder that has not filled it in
	// yet — resolveLicenceBasis returns a licenceBasis carrying a coord field, and
	// its "give a version" line is correct precisely because it has neither.
	consider := func(fields *ast.FieldList, reach bool) {
		if fields == nil {
			return
		}
		for _, f := range fields.List {
			if reach {
				s.observe(typeFacts(p, f.Type))
			} else if isCoordinateType(p, f.Type) {
				s.hasCoordinate = true
			}
			for _, n := range f.Names {
				if emptiedBefore(fn, n.Name, pos) {
					continue
				}
				s.observe(nameFacts(n.Name))
			}
		}
	}
	consider(fn.Recv, true)
	consider(fn.Type.Params, true)
	consider(fn.Type.Results, false)
	return s
}

// emptiedBefore reports whether control flow has already dealt with the case
// where name holds a usable value, by the time pos is reached: the function
// guarded on it being set and that branch returned, so everything after it runs
// without a value to substitute.
//
// The return may sit anywhere inside the guarded branch, not only at its end.
// unresolvedSymbolMessage guards on the local module path, returns from inside
// that branch when the symbol belongs to it, and reaches its own placeholder
// only having established that the path it holds is not the one the reader
// needs — the same fact as an empty one, reached a statement deeper.
func emptiedBefore(fn *ast.FuncDecl, name string, pos token.Pos) bool {
	emptied := false
	ast.Inspect(fn, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok || stmt.Else != nil || stmt.End() >= pos {
			return true
		}
		cmp, ok := stmt.Cond.(*ast.BinaryExpr)
		if !ok || cmp.Op != token.NEQ {
			return true
		}
		id, ok := cmp.X.(*ast.Ident)
		if !ok || id.Name != name {
			return true
		}
		lit, ok := cmp.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || literalValue(lit) != "" {
			return true
		}
		ast.Inspect(stmt.Body, func(inner ast.Node) bool {
			if _, isReturn := inner.(*ast.ReturnStmt); isReturn {
				emptied = true
			}
			return true
		})
		return true
	})
	return emptied
}

func literalValue(lit *ast.BasicLit) string {
	if v, err := strconv.Unquote(lit.Value); err == nil {
		return v
	}
	return strings.Trim(lit.Value, "`\"")
}

// -- controls ----------------------------------------------------------------

// TestRemedyGuardCatchesAPlantedInvocation plants each shape the guard exists to
// catch and requires the verdict to report it, and plants the shapes it must not
// report. Without it the guard above could pass by detecting nothing at all.
func TestRemedyGuardCatchesAPlantedInvocation(t *testing.T) {
	slots := coordinateSlots(t)
	for _, tc := range []struct {
		name      string
		text      string
		scope     scopeFacts
		wantFault bool
	}{
		{"the bare path this closes", "list them:\n  kanonarion callgraph-show example.com/mod", scopeFacts{}, true},
		{"the coordinate that fixes it", "list them:\n  kanonarion callgraph-show example.com/mod@v1.0.0", scopeFacts{}, false},
		{"a version placeholder whose value was in hand", "reported by: kanonarion license example.com/mod@<version>", scopeFacts{hasVersion: true}, true},
		{"the same placeholder with nothing to fill it from", "make one:\n  kanonarion license example.com/mod@<version>", scopeFacts{}, false},
		{"a whole-coordinate placeholder with nothing to fill it from", "make one:\n  kanonarion callgraph <module>@<version>", scopeFacts{}, false},
		// Each placeholder is judged against the fact that would fill IT. These
		// four are the reason: the version site in provenance_basis.go is printed
		// by a builder holding a path, and disjoining the facts reported it.
		{"a version placeholder in a builder holding only a path", "make one:\n  kanonarion license example.com/mod@<version>", scopeFacts{hasPath: true}, false},
		{"a module placeholder in a builder holding only a path", "make one:\n  kanonarion license <module>@<version>", scopeFacts{hasPath: true}, true},
		{"a module placeholder in a builder holding only a version", "make one:\n  kanonarion license <module>@v1.0.0", scopeFacts{hasVersion: true}, false},
		{"both placeholders in a builder holding the whole coordinate", "examine one:\n  kanonarion native <module>@<version>", scopeFacts{hasCoordinate: true}, true},
		{"a version placeholder in a builder holding the whole coordinate", "make one:\n  kanonarion license example.com/mod@<version>", scopeFacts{hasCoordinate: true}, true},
		{"a runtime value the source does not describe", "run:\n  kanonarion license " + standInOpaque, scopeFacts{}, true},
		{"a runtime value carrying the coordinate's shape", "run:\n  kanonarion license " + standInOpaque + "@" + standInOpaque, scopeFacts{}, false},
		{"a coordinate in a walk id's slot", "re-scan it:\n  kanonarion vuln-scan example.com/mod@v1.0.0", scopeFacts{}, true},
		{"a walk id in its own slot", "re-scan it:\n  kanonarion vuln-scan " + standInWalkID, scopeFacts{}, false},
		{"a line missing the argument it needs", "re-scan it:\n  kanonarion vuln-scan-rescan", scopeFacts{}, true},
		{"a command named in a sentence without the argument it requires", "answers come from 'kanonarion vuln-show', which states the frame", scopeFacts{}, true},
		{"a mention with the argument it requires", "answers come from 'kanonarion vuln-show example.com/mod@v1.0.0', which states the frame", scopeFacts{}, false},
		{"a mention asking for help", "a different budget: see 'kanonarion extract --help'.", scopeFacts{}, false},
		{"the licence remedy this closes", "no license record: run 'kanonarion license' first", scopeFacts{}, true},
		{"prose carrying on after a line", "so kanonarion walk --gomod ./go.mod records the current resolution", scopeFacts{}, false},
		{"an argument that is an English word in its own right", "  kanonarion config set preferences.json true", scopeFacts{}, false},
		{"an argument carrying spaces", "  kanonarion config set license_policy.categories.permissive '[MIT, Apache-2.0, ISC]'", scopeFacts{}, false},
		{"a line piped into another tool", "  kanonarion verification-coverage " + standInWalkID + " --json | jq -e '.collapsed | not'", scopeFacts{}, false},
		{"the directory argument", "  kanonarion reachability --local .", scopeFacts{}, false},
		{"prose that only happens to name the binary", "unsupported ecosystem: kanonarion records are Go-only", scopeFacts{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var faults []string
			for _, inv := range invocationsIn(tc.text) {
				for _, conjunct := range strings.Split(inv.line, " && ") {
					line, cmdName, positionals, ok := readInvocation(t, strings.TrimSpace(conjunct))
					if !ok {
						continue
					}
					faults = append(faults, invocationViolations(t, slots, line, cmdName, positionals, inv.presented, tc.scope)...)
				}
			}
			if got := len(faults) > 0; got != tc.wantFault {
				t.Errorf("reported %v for %q, want %v (%v)", got, tc.text, tc.wantFault, faults)
			}
		})
	}
}

// TestRemedyGuardCatchesAPlantedFlag is the flag check's control: each shape it
// exists to catch is reported, and each it must leave alone is not.
func TestRemedyGuardCatchesAPlantedFlag(t *testing.T) {
	root := newRootCmd(io.Discard, io.Discard)
	for _, tc := range []struct {
		name      string
		text      string
		cliBuilt  bool
		wantFault bool
	}{
		{"a flag the invoked command does not define", "re-scan it:\n  kanonarion vuln-scan " + standInWalkID + " --snapshot-source x", true, true},
		{"the command that defines it", "re-scan it:\n  kanonarion vuln-scan-rescan " + standInWalkID + " --snapshot-source x --snapshot-version y", true, false},
		{"a mention carrying a flag its command does not define", "run 'kanonarion vuln-scan --snapshot-version y' instead", true, true},
		{"prose naming a flag, built where no command is known", "drop --fresh so the stored generation is used (kanonarion vuln-snapshot-list shows what is held)", false, true},
		{"the same prose built in the CLI", "drop --fresh so the stored generation is used (kanonarion vuln-snapshot-list shows what is held)", true, false},
		{"prose naming a flag every command defines", "list them with kanonarion walk-list, adding --json for a document", false, false},
		{"prose naming no command, built where no command is known", "proxy URL uses plain HTTP; pass --insecure to allow", false, true},
		{"an argv element handed to a subprocess", "--depth=1", false, false},
		{"a piece spliced into an invocation", " --tinygo <target>", false, false},
		{"a quoted line nested in another", "kanonarion callgraph example.com/mod@v1.0.0 (or 'kanonarion extract " + standInWalkID + " --stages callgraph' over the project walk)", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, faults := flagViolations(t, root, tc.text, tc.cliBuilt)
			if got := len(faults) > 0; got != tc.wantFault {
				t.Errorf("reported %v for %q, want %v (%v)", got, tc.text, tc.wantFault, faults)
			}
		})
	}
}

// TestRunEArity_IsReadOffTheSource pins what the RunE count derivation makes of
// commands the CLI ships: one that refuses on its first statement, one that
// takes two, and one whose count applies only after a --gomod form returned.
func TestRunEArity_IsReadOffTheSource(t *testing.T) {
	arity := runEArity(t)
	if len(arity) < 15 {
		t.Fatalf("read a RunE count off only %d commands; the derivation is not reaching the source", len(arity))
	}
	slots := coordinateSlots(t)
	for _, tc := range []struct {
		cmd  string
		want int
	}{{"license", 1}, {"walk-diff", 2}, {"fetch", 0}} {
		if got := arity[slots[tc.cmd].use]; got != tc.want {
			t.Errorf("%q: RunE refuses fewer than %d positionals, want %d", tc.cmd, got, tc.want)
		}
	}
}

// TestCoordinateSlots_AreReadOffTheCommandsThemselves pins what the derivation
// makes of the grammars the CLI ships. It names commands rather than files, so
// it fails the moment one is renamed or its positional grammar changes — the
// point being that the guard's subject moves with the tree instead of being
// re-listed by hand.
func TestCoordinateSlots_AreReadOffTheCommandsThemselves(t *testing.T) {
	slots := coordinateSlots(t)
	for _, tc := range []struct {
		cmd  string
		want []bool
	}{
		{"callgraph-show", []bool{true}},
		{"callgraph", []bool{true}},
		{"license", []bool{true}},
		{"walk", []bool{true}},
		{"usage", []bool{true}},
		{"examples-show", []bool{true, false}},
		{"interface-diff", []bool{true, true}},
		// A bare path runs these, so a line printing one is not wrong.
		{"provenance", []bool{false}},
		{"fetch", []bool{false}},
		{"callgraph-list", []bool{false}},
		{"latest", []bool{false}},
		// Their positional is a walk or a run, never a coordinate.
		{"verification-coverage", []bool{false}},
		{"vuln-scan", []bool{false}},
		{"walk-show", []bool{false}},
	} {
		spec, ok := slots[tc.cmd]
		if !ok {
			t.Errorf("%q is no longer a subcommand of this CLI", tc.cmd)
			continue
		}
		if len(spec.coordinateAt) != len(tc.want) {
			t.Errorf("%q declares %d positionals (%q), want %d", tc.cmd, len(spec.coordinateAt), spec.use, len(tc.want))
			continue
		}
		for i := range tc.want {
			if spec.coordinateAt[i] != tc.want[i] {
				t.Errorf("%q positional %d: coordinate=%v, want %v (%q)", tc.cmd, i+1, spec.coordinateAt[i], tc.want[i], spec.use)
			}
		}
	}
}

// The stand-ins are the guard's own vocabulary; if they stopped being the shapes
// they claim, every verdict above would be measuring something else.
func TestRemedyGuardStandInsAreTheShapesTheyClaim(t *testing.T) {
	if _, err := coordinate.ParseModuleCoordinate(standInCoordinate); err != nil {
		t.Errorf("the coordinate stand-in %q is not a coordinate: %v", standInCoordinate, err)
	}
	if _, err := coordinate.ParseModuleCoordinate(standInPath); err == nil {
		t.Errorf("the bare-path stand-in %q parses as a coordinate", standInPath)
	}
	if isProseWord(standInPath) || isProseWord(standInWalkID) || isProseWord(standInCoordinate) {
		t.Error("a stand-in reads as an English word, so the prose trim would cut a real argument")
	}
}

// The guard is not confined to one file: a defect written into a package no list
// names has to be reachable, which is the half every previous sweep missed.
func TestRemedyGuardReadsTheWholeTree(t *testing.T) {
	files := map[string]bool{}
	for _, m := range allPrintedMessages(t) {
		if len(invocationsIn(m.text)) > 0 {
			files[m.file] = true
		}
	}
	if len(files) < 30 {
		t.Fatalf("printed invocations were found in only %d files; the scan is not reaching the tree", len(files))
	}
	outside := 0
	for f := range files {
		if !strings.Contains(filepath.ToSlash(f), "/internal/cli/") {
			outside++
		}
	}
	if outside < 5 {
		t.Fatalf("only %d of %d files carrying a printed invocation sit outside internal/cli; the scan is too narrow",
			outside, len(files))
	}
}

// TestRemedyGuardReachesAValueHeldInAStructParameter is the control for the
// reach itself. The planted table above is handed its scopeFacts, so it proves
// the verdict and nothing about the derivation; this plants source instead and
// requires scopeOf to read the facts out of it.
//
// Three builders print the same line. One is handed a struct carrying a
// coordinate, one a struct carrying only a path, one neither — and the verdict
// on an identical message differs in all three, which is the whole claim.
func TestRemedyGuardReachesAValueHeldInAStructParameter(t *testing.T) {
	const src = `package planted

import "code.eitanity.com/kanonarion/internal/coordinate"

type rollup struct {
	notExamined  int
	anExaminable coordinate.ModuleCoordinate
}

type pathOnly struct {
	modulePath string
}

type optional struct {
	target *coordinate.ModuleCoordinate
}

func fromRollup(r *rollup) string   { return "examine one:\n  kanonarion native <module>@<version>" }
func fromPath(p pathOnly) string    { return "examine one:\n  kanonarion native <module>@<version>" }
func fromOptional(o optional) string { return "examine one:\n  kanonarion native <module>@<version>" }
func fromNothing(n int) string      { return "examine one:\n  kanonarion native <module>@<version>" }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the planted source: %v", err)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Defs:  map[*ast.Ident]types.Object{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: repoImporter(t)}
	if _, err = conf.Check("planted", fset, []*ast.File{file}, info); err != nil {
		t.Fatalf("type-checking the planted source: %v", err)
	}
	pkg := &packages.Package{Fset: fset, TypesInfo: info, Syntax: []*ast.File{file}}
	fns := enclosingFunctions(file)

	slots := coordinateSlots(t)
	for _, tc := range []struct {
		fn        string
		want      scopeFacts
		wantFault bool
	}{
		{"fromRollup", scopeFacts{hasCoordinate: true}, true},
		{"fromPath", scopeFacts{hasPath: true}, true},
		// A pointer field is optional by construction, so the struct declaring it
		// is not a builder holding a value.
		{"fromOptional", scopeFacts{}, false},
		{"fromNothing", scopeFacts{}, false},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			decl := namedFuncDecl(t, file, tc.fn)
			lit := returnedLiteral(t, decl)
			got := scopeOf(pkg, fns.at(lit.Pos()), lit.Pos())
			if got != tc.want {
				t.Fatalf("scopeOf(%s) = %+v, want %+v", tc.fn, got, tc.want)
			}
			var faults []string
			for _, inv := range invocationsIn(literalValue(lit)) {
				line, cmdName, positionals, ok := readInvocation(t, inv.line)
				if !ok {
					t.Fatalf("the planted line was not read as an invocation: %q", inv.line)
				}
				faults = append(faults, invocationViolations(t, slots, line, cmdName, positionals, inv.presented, got)...)
			}
			if reported := len(faults) > 0; reported != tc.wantFault {
				t.Errorf("reported %v, want %v (%v)", reported, tc.wantFault, faults)
			}
		})
	}
}

// repoImporter resolves the planted source's one import from the packages this
// test binary has already type-checked, so the coordinate value object in the
// fixture is the same named type the guard recognises.
func repoImporter(t *testing.T) types.Importer {
	t.Helper()
	found := map[string]*types.Package{}
	seen := map[string]bool{}
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if p == nil || seen[p.PkgPath] {
			return
		}
		seen[p.PkgPath] = true
		if p.Types != nil {
			found[p.PkgPath] = p.Types
		}
		for _, imp := range p.Imports {
			visit(imp)
		}
	}
	for _, p := range loadRepoPackages(t) {
		visit(p)
	}
	if _, ok := found[strings.TrimSuffix(coordinateTypeName, ".ModuleCoordinate")]; !ok {
		t.Fatal("the coordinate package is not among the type-checked packages; the fixture cannot be built")
	}
	return importerFunc(func(path string) (*types.Package, error) {
		if p, ok := found[path]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("the planted fixture may not import %q", path)
	})
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

func namedFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("the planted source has no function %q", name)
	return nil
}

func returnedLiteral(t *testing.T, fn *ast.FuncDecl) *ast.BasicLit {
	t.Helper()
	var lit *ast.BasicLit
	ast.Inspect(fn, func(n ast.Node) bool {
		if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING && lit == nil {
			lit = l
		}
		return true
	})
	if lit == nil {
		t.Fatalf("%s returns no string literal", fn.Name.Name)
	}
	return lit
}

// TestTheLegitimateVersionPlaceholderStaysLegitimate pins the site the guard
// must NOT report, because a guard that fails on a correct message gets
// suppressed and then catches nothing at all.
//
// The message is resolveLicenceBasis's miss with no version named. Its builder
// holds a path and has already returned for every case where a version was in
// hand, so "give a version and run: … @<version>" is an instruction the reader
// can act on, not a value thrown away. It is found by its own words rather than
// by file and line, so it stays pinned when the file moves.
func TestTheLegitimateVersionPlaceholderStaysLegitimate(t *testing.T) {
	const words = "give a version and run"
	slots := coordinateSlots(t)
	found := 0
	for _, m := range allPrintedMessages(t) {
		if !strings.Contains(m.text, words) {
			continue
		}
		found++
		if !m.scope.hasPath {
			t.Errorf("%s:%d: the builder holds no path, so the guard is reading the wrong scope", m.file, m.line)
		}
		if m.scope.hasVersion || m.scope.hasCoordinate {
			t.Errorf("%s:%d: the builder is read as holding a version (%+v); it returned for that case already",
				m.file, m.line, m.scope)
		}
		for _, inv := range invocationsIn(m.text) {
			for _, conjunct := range strings.Split(inv.line, " && ") {
				line, cmdName, positionals, ok := readInvocation(t, strings.TrimSpace(conjunct))
				if !ok {
					continue
				}
				for _, v := range invocationViolations(t, slots, line, cmdName, positionals, inv.presented, m.scope) {
					t.Errorf("%s:%d reports a correct message: %s", m.file, m.line, v)
				}
			}
		}
	}
	if found == 0 {
		t.Fatalf("no shipped message contains %q; the pin is measuring nothing", words)
	}
}

// TestRemedyGuardJudgesTheTinyGoRemedies holds the two TinyGo lines — the
// missing-package remedy and the frame notice — to the guard's verdict. Both
// are built at run time from the invocation, which the source scan above
// renders as opaque, so each is rendered here for every command that prints it.
func TestRemedyGuardJudgesTheTinyGoRemedies(t *testing.T) {
	t.Cleanup(func() { invokedCmd, invokedArgs = nil, nil })
	slots := coordinateSlots(t)
	local, err := coordinate.NewLocalCoordinate("example.com/blinky")
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := coordinate.NewModuleCoordinate("example.com/drivers", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	texts := []string{
		gotoolchain.TinyGoPackageRemedy([]string{"machine"}, cgdomain.TinyGoReanalysisInstruction(local, "/work/tree")),
		gotoolchain.TinyGoPackageRemedy([]string{"machine"}, cgdomain.TinyGoReanalysisInstruction(fetched, "")),
	}
	for _, args := range [][]string{
		{"local", "."}, {"walk", "--gomod", "./go.mod", "--no-progress"}, {"audit", "--gomod", "./go.mod"},
		{"inspect", "--gomod", "./go.mod"}, {"sbom", "--package", "./cmd/x", "--format", "spdx"},
	} {
		cmd, rest, ferr := newRootCmd(io.Discard, io.Discard).Find(args)
		if ferr != nil {
			t.Fatal(ferr)
		}
		if perr := cmd.ParseFlags(rest); perr != nil {
			t.Fatal(perr)
		}
		invokedCmd, invokedArgs = cmd, cmd.Flags().Args()
		texts = append(texts,
			gotoolchain.TinyGoPackageRemedy([]string{"machine"}, tinyGoRerun()),
			(&frameExcludesJSON{Files: []string{"v_tinygo.go"}, Command: tinyGoRerun()}).statement())
	}
	judged := 0
	for _, text := range texts {
		for _, inv := range invocationsIn(text) {
			for _, conjunct := range strings.Split(inv.line, " && ") {
				line, cmdName, positionals, ok := readInvocation(t, strings.TrimSpace(conjunct))
				if !ok {
					t.Errorf("%q is not read as an invocation of this CLI", conjunct)
					continue
				}
				judged++
				for _, v := range invocationViolations(t, slots, line, cmdName, positionals, true, scopeFacts{}) {
					t.Errorf("%q: %s", line, v)
				}
			}
		}
	}
	if judged != 14 {
		t.Errorf("judged %d TinyGo invocations, want 14", judged)
	}
}
