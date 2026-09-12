package cli

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/tools/go/packages"

	"github.com/eitanity/kanonarion/internal/coordinate"
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
const coordinateTypeName = "github.com/eitanity/kanonarion/internal/coordinate.ModuleCoordinate"

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
// receiver and named results only: those are the values the message is
// unambiguously built from, and widening it to every identifier in the body
// would call a value "in hand" that is computed after the message is built.
type scopeFacts struct {
	hasCoordinate bool
	hasVersion    bool
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
// or its own line within it — rather than named inside a sentence. A line is
// something a reader copies, so it owes the whole contract; a sentence that
// names a command is an instruction about it, and holding "answers come from
// 'kanonarion vuln-show'" to an argument count would report English as a
// defect. What a mention still owes is the argument it DOES print: naming a
// bare path where the command takes a coordinate misdirects either way.
func invocationViolations(t *testing.T, slots map[string]coordinateSlotSpec, line, cmdName string,
	positionals []string, presented bool, scope scopeFacts,
) []string {
	t.Helper()
	var out []string
	if presented {
		if err := parseInvocation(t, strings.ReplaceAll(line, standInOpaque, "x")); err != nil {
			out = append(out, "the CLI's own parser rejects it: "+err.Error())
		}
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
	type slot struct {
		text  string
		field int
		prose bool
	}
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
		// is nothing to fill it from — a store holding no records at all can only
		// describe the command that makes one — and it is the defect where the
		// value was in hand and discarded.
		if scope.hasCoordinate || scope.hasVersion {
			return fmt.Sprintf("prints the placeholder %q while its builder holds the value", arg)
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
			if i+1 >= len(text) || text[i+1] == ' ' || text[i+1] == '\n' {
				return strings.TrimSpace(text[:i])
			}
		case '.':
			// A full stop closes the line; a lone "." is the argument that names
			// the working directory, so a dot after a space is kept.
			if i > 0 && text[i-1] != ' ' && (i+1 >= len(text) || text[i+1] == ' ' || text[i+1] == '\n') {
				return strings.TrimSpace(text[:i])
			}
		}
	}
	return strings.TrimSpace(text)
}

// allPrintedMessages renders every string-valued expression in the shipped
// source that names the binary.
func allPrintedMessages(t *testing.T) []printedMessage {
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
			out = append(out, messagesInFile(p, f, file)...)
		}
	}
	return out
}

func messagesInFile(p *packages.Package, f *ast.File, file string) []printedMessage {
	var out []printedMessage
	consumed := map[ast.Node]bool{}
	fns := enclosingFunctions(f)
	record := func(pos token.Pos, text string) {
		if !strings.Contains(text, "kanonarion ") {
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
	case name == "coord" || name == "coordinate" || name == "mod" || name == "module" ||
		strings.HasSuffix(name, "Coord") || strings.HasSuffix(name, "Coordinate"):
		// The codebase carries a coordinate as text under these names — "coord :=
		// c.ModulePath + \"@\" + c.ModuleVersion". Reading them is the guard's one
		// concession to spelling, and it only ever narrows: a slot it cannot place
		// is reported, never waved through.
		return standInCoordinate
	}
	return standInOpaque
}

func isCoordinateType(p *packages.Package, e ast.Expr) bool {
	tv, ok := p.TypesInfo.Types[e]
	if !ok || tv.Type == nil {
		return false
	}
	named, ok := tv.Type.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path()+"."+obj.Name() == coordinateTypeName
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
	consider := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, f := range fields.List {
			if isCoordinateType(p, f.Type) {
				s.hasCoordinate = true
			}
			for _, n := range f.Names {
				if emptiedBefore(fn, n.Name, pos) {
					continue
				}
				switch standInForName(n.Name) {
				case standInVersion:
					s.hasVersion = true
				case standInCoordinate:
					s.hasCoordinate = true
				}
			}
		}
	}
	consider(fn.Recv)
	consider(fn.Type.Params)
	consider(fn.Type.Results)
	return s
}

// emptiedBefore reports whether control flow has established that name is the
// empty string by the time pos is reached: the function guarded on it being set
// and that guard returned, so everything after it runs without the value.
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
		if body := stmt.Body; body != nil && len(body.List) > 0 {
			if _, isReturn := body.List[len(body.List)-1].(*ast.ReturnStmt); isReturn {
				emptied = true
			}
		}
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
		{"a runtime value the source does not describe", "run:\n  kanonarion license " + standInOpaque, scopeFacts{}, true},
		{"a runtime value carrying the coordinate's shape", "run:\n  kanonarion license " + standInOpaque + "@" + standInOpaque, scopeFacts{}, false},
		{"a coordinate in a walk id's slot", "re-scan it:\n  kanonarion vuln-scan example.com/mod@v1.0.0", scopeFacts{}, true},
		{"a walk id in its own slot", "re-scan it:\n  kanonarion vuln-scan " + standInWalkID, scopeFacts{}, false},
		{"a line missing the argument it needs", "re-scan it:\n  kanonarion vuln-scan-rescan", scopeFacts{}, true},
		{"the same command merely named in a sentence", "answers come from 'kanonarion vuln-show', which states the frame", scopeFacts{}, false},
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
