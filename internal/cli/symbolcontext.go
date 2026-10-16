package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	exapp "github.com/eitanity/kanonarion/internal/example/application"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"

	ifaceapp "github.com/eitanity/kanonarion/internal/iface/application"
	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// -- output types --

type symbolContextExample struct {
	Name      string `json:"name"`
	Package   string `json:"package"`
	Validates bool   `json:"validates"`
}

type symbolContextEntry struct {
	Module        string                 `json:"module"`
	Package       string                 `json:"package"`
	Name          string                 `json:"name"`
	QualifiedName string                 `json:"qualified_name"`
	Kind          string                 `json:"kind"`
	Signature     string                 `json:"signature,omitempty"`
	Doc           string                 `json:"doc,omitempty"`
	Examples      []symbolContextExample `json:"examples"`
}

// -- symbol-context command --

type symbolContextFlags struct {
	module string
	scope  buildScopeFlags
}

func newSymbolContextCmd(stdout, stderr io.Writer) *cobra.Command {
	var f symbolContextFlags

	cmd := &cobra.Command{
		Use: "symbol-context <name> | <module>@<version> <name>",
		Annotations: map[string]string{
			annotationStoreIntent: StoreIntentRead,
			annotationNetworkUse:  NetworkNever,
		},
		Short: "Assemble per-module symbol record with signature, godoc, and examples",
		Long: `Assemble a per-module symbol record (signature, godoc, examples).

The bare-name form is primary: 'symbol-context <name>' searches every stored
module and reports one entry per module version that declares the symbol. A
qualified name keeps only what it names: the import path
(github.com/google/uuid.NewString), the package name (uuid.NewString), the
receiver type (UUID.String), or package and receiver (uuid.UUID.String).

A module held only at a superseded interface pipeline is not searched: a miss
over one exits 4 and names it, and an answer names it on stderr.

Every sibling record command (interface-show, examples-list, vuln-show,
context) takes <module>@<version> positionally, so that form is accepted here
too: 'symbol-context <module>@<version> <name>' is exactly equivalent to
'symbol-context <name> --module <module>@<version>'.`,
		Example: `  kanonarion symbol-context Marshal
  kanonarion symbol-context github.com/google/uuid.NewString
  kanonarion symbol-context uuid.NewString
  kanonarion symbol-context UUID.String
  kanonarion symbol-context New --module github.com/spf13/cobra@v1.8.1
  kanonarion symbol-context github.com/spf13/cobra@v1.8.1 New
  kanonarion symbol-context Client --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			symbolName, conflict, ok := symbolContextArgs(args, &f)
			if conflict != nil {
				return conflict
			}
			if !ok {
				return usageErr(cmd)
			}
			if berr := f.scope.bind(cmd); berr != nil {
				return berr
			}
			return runSymbolContext(cmd.Context(), symbolName, f, jsonOut, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.module, "module", "", "narrow results to a specific module@version")
	registerBuildScopeFlags(cmd, &f.scope)

	return cmd
}

// symbolContextArgs resolves the accepted positional grammars to a symbol name,
// narrowing f.module in place for the two-argument form.
//
// It reports three outcomes rather than two. conflict is a specific, nameable
// disagreement the caller must see verbatim; ok=false is a shape the usage text
// already explains and is rendered as usage. Collapsing them would print a
// generic grammar dump at someone who stated the module twice and differently —
// the one case where the grammar was not the problem.
//
// Two arguments are only accepted when the first contains '@'. A Go symbol name
// cannot contain '@', so the form is unambiguous and no sibling grammar
// collides with it. A first argument WITH '@' and no second argument stays the
// bare-name form: that is a caller naming a symbol oddly, not a truncated
// coordinate, and guessing would swallow the name.
func symbolContextArgs(args []string, f *symbolContextFlags) (name string, conflict error, ok bool) {
	switch len(args) {
	case 1:
		return args[0], nil, true
	case 2:
		if !strings.Contains(args[0], "@") {
			return "", nil, false
		}
		if f.module != "" && f.module != args[0] {
			return "", fmt.Errorf(
				"module given twice and differently: %q positionally and %q via --module; pass it once",
				args[0], f.module), false
		}
		f.module = args[0]
		return args[1], nil, true
	default:
		return "", nil, false
	}
}

// runSymbolContext is the entry point for the symbol-context command.
// All log output goes to stderr so stdout is clean for piping; JSON output
// is deterministic (stable entry order, no interleaved log lines).
func runSymbolContext(ctx context.Context, symbolName string, f symbolContextFlags, jsonOut bool, stdout, stderr io.Writer) error {
	// Always log to stderr so stdout is clean for piping.
	logger := buildLogger(logLevel, stderr)
	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
	if err != nil {
		return fmt.Errorf("initialising store: %w", err)
	}
	defer releaseStore(cleanup)

	sc, err := f.scope.resolve(ctx, ctr.QueryWalks)
	if err != nil {
		return err
	}

	// Without a scope this fans out one entry — signature, godoc and examples —
	// per stored version of the owning module, which reads as several distinct
	// symbols rather than one symbol recorded several times. --module narrows
	// after the fact and only if the caller thought to pass it; a build scope
	// narrows the query itself.
	// A conflict is carried rather than returned: see runSymbolFind. The entries
	// this command CAN assemble are rendered, and the command fails afterwards.
	q := parseSymbolQuery(symbolName)
	found, err := lookupSymbolRefs(ctx, ctr, symbolName, q, f, sc)
	if err != nil {
		return err
	}
	census, conflictErr := found.census, found.conflictErr

	// Drop symbols in non-importable packages (internal/, testdata/): they
	// cannot be called by consumers, so they are misleading as call targets.
	refs := filterImportableRefs(found.refs)

	if len(refs) == 0 {
		return writeNoSymbolContext(symbolName, q, f, sc, found, jsonOut, stdout, stderr)
	}
	if nerr := census.writeNotice(stderr, census.coordinateRemedy(q)); nerr != nil {
		return nerr
	}
	if !jsonOut {
		if nerr := writeScopeNotice(stdout, sc); nerr != nil {
			return nerr
		}
	}

	entries, carried, err := buildSymbolContextEntries(ctx, ctr, refs, ifaceapp.PipelineVersion)
	if err != nil {
		return err
	}
	conflictErr = errors.Join(conflictErr, carried)

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return fmt.Errorf("encoding symbol context: %w", err)
		}
		return conflictErr
	}
	if perr := printSymbolContext(entries, stdout); perr != nil {
		return perr
	}
	return conflictErr
}

// symbolLookup is what a symbol-context lookup found: the refs the query
// names, every importable ref of the bare name (for a qualified miss), the
// modules it could not read, and a conflict carried beside the refs.
type symbolLookup struct {
	refs, all   []ifaceports.SymbolRef
	census      unreadInterfaceModules
	conflictErr error
}

// lookupSymbolRefs finds the refs the query names and the modules it could not
// read. A named module is the whole question, so modules held only at a
// superseded pipeline elsewhere do not bear on it; without one they do.
func lookupSymbolRefs(ctx context.Context, ctr *Container, symbolName string, q symbolQuery, f symbolContextFlags, sc buildScope,
) (symbolLookup, error) {
	var out symbolLookup
	refs, err := ctr.QueryInterface.FindSymbol(ctx, q.name, ifaceapp.PipelineVersion, sc.modules)
	switch {
	case errors.Is(err, ifaceports.ErrInterfaceConflict):
		out.conflictErr = err
	case err != nil:
		return out, fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}
	out.refs = q.keep(refs)
	if f.module != "" {
		out.refs, err = narrowRefsToModule(ctx, ctr, f, out.refs)
		return out, err
	}
	if q.qualifier != "" {
		// keep copied the qualified refs, so filtering in place is safe here.
		out.all = filterImportableRefs(refs)
	}
	out.census, err = readInterfaceCensus(ctx, ctr.QueryInterface, sc.modules, q)
	return out, err
}

// narrowRefsToModule keeps the refs of the module --module names. A module
// the store serves no record for is a miss, exit 4: "never extracted" and
// "extracted under superseded logic" both arrive here as an absent record, and
// only one of them is a coordinate to check.
func narrowRefsToModule(ctx context.Context, ctr *Container, f symbolContextFlags, refs []ifaceports.SymbolRef) ([]ifaceports.SymbolRef, error) {
	coord, perr := parseCoordinate(f.module)
	if perr != nil {
		return nil, fmt.Errorf("invalid --module %q: %w", f.module, perr)
	}
	if _, found, gerr := ctr.QueryInterface.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion); gerr == nil && !found {
		line := fmt.Sprintf("no interface record for %s in the store; run 'kanonarion interface %s' first", f.module, f.module)
		if pipelines, superseded := supersededInterfaceRecord(ctx, ctr.QueryInterface, coord); superseded {
			line = supersededInterfaceLine(coord, pipelines)
		}
		return nil, &exitError{code: ExitNotFound, msg: line}
	}
	var filtered []ifaceports.SymbolRef
	for _, ref := range refs {
		if ref.ModulePath == coord.Path() && ref.ModuleVersion == coord.Version() {
			filtered = append(filtered, ref)
		}
	}
	return filtered, nil
}

// writeNoSymbolContext answers a lookup that found no export. An empty store,
// or modules that could answer held only at a superseded pipeline, is exit 4
// with stdout empty: the lookup read nothing there, so "no exports" would be
// a claim it did not measure.
func writeNoSymbolContext(symbolName string, q symbolQuery, f symbolContextFlags, sc buildScope,
	found symbolLookup, jsonOut bool, stdout, stderr io.Writer,
) error {
	census, conflictErr := found.census, found.conflictErr
	if f.module == "" && conflictErr == nil {
		if census.stored == 0 {
			return emptyInterfaceStoreError(symbolName)
		}
		if len(census.modules) > 0 {
			return census.missError(symbolName, census.coordinateRemedy(q))
		}
	}
	if err := q.writeExcluded(stderr, found.all); err != nil {
		return err
	}
	if jsonOut {
		if _, err := fmt.Fprintln(stdout, "[]"); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		return conflictErr
	}
	if err := writeScopeNotice(stdout, sc); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "no exports found for symbol %q\n", symbolName); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return conflictErr
}

// filterImportableRefs drops refs whose package path has an "internal" or
// "testdata" path segment. Such packages cannot be imported by external
// consumers, so surfacing their symbols as call targets is misleading.
func filterImportableRefs(refs []ifaceports.SymbolRef) []ifaceports.SymbolRef {
	out := refs[:0]
	for _, ref := range refs {
		if isImportablePackage(ref.PackagePath) {
			out = append(out, ref)
		}
	}
	return out
}

// isImportablePackage reports whether importPath is importable by code outside
// the defining module — i.e. it contains no "internal" or "testdata" segment.
func isImportablePackage(importPath string) bool {
	for seg := range strings.SplitSeq(importPath, "/") {
		if seg == "internal" || seg == "testdata" {
			return false
		}
	}
	return true
}

// sortSymbolRefs sorts refs in place for deterministic output:
// (module_path, module_version, package_path, symbol_kind, parent_type).
// SQL guarantees (module, package) order but not kind or parent_type within a
// package group when multiple symbols share the same name.
func sortSymbolRefs(refs []ifaceports.SymbolRef) {
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.ModulePath != b.ModulePath {
			return a.ModulePath < b.ModulePath
		}
		if a.ModuleVersion != b.ModuleVersion {
			return a.ModuleVersion < b.ModuleVersion
		}
		if a.PackagePath != b.PackagePath {
			return a.PackagePath < b.PackagePath
		}
		if a.SymbolKind != b.SymbolKind {
			return a.SymbolKind < b.SymbolKind
		}
		return a.ParentType < b.ParentType
	})
}

// buildSymbolContextEntries assembles one entry per SymbolRef, loading
// InterfaceRecords once per module for godoc and fetching scoped examples.
// Refs are sorted for deterministic output before grouping.
//
// A conflict in either read is returned as carried, beside the entries, so the
// caller renders them and fails afterwards; any other read failure is err.
func buildSymbolContextEntries(ctx context.Context, ctr *Container, refs []ifaceports.SymbolRef, pipelineVersion string) (entries []symbolContextEntry, carried, err error) {
	sortSymbolRefs(refs)

	type moduleKey struct{ path, version string }

	byModule := make(map[moduleKey][]ifaceports.SymbolRef)
	var order []moduleKey
	for _, ref := range refs {
		k := moduleKey{ref.ModulePath, ref.ModuleVersion}
		if _, seen := byModule[k]; !seen {
			order = append(order, k)
		}
		byModule[k] = append(byModule[k], ref)
	}

	var conflicts []error
	entries = make([]symbolContextEntry, 0, len(refs))
	for _, mk := range order {
		coord, cErr := coordinate.NewModuleCoordinate(mk.path, mk.version)
		if cErr != nil {
			return nil, nil, fmt.Errorf("symbol reference %s@%s names no module: %w", mk.path, mk.version, cErr)
		}

		// A missing interface record means an empty doc. A record the store
		// cannot verify or compose is not missing, so it is not shown as one.
		ifaceRec, _, ierr := ctr.QueryInterface.GetInterfaceRecord(ctx, coord, pipelineVersion)
		switch {
		case errors.Is(ierr, ifaceports.ErrInterfaceConflict):
			conflicts = append(conflicts, ierr)
		case ierr != nil:
			return nil, nil, fmt.Errorf("reading the godoc for %s: %w", coord, ierr)
		}

		for _, ref := range byModule[mk] {
			qualName := ref.PackagePath + "." + ref.SymbolName
			if ref.ParentType != "" {
				qualName = ref.PackagePath + "." + ref.ParentType + "." + ref.SymbolName
			}

			doc := symbolDoc(ifaceRec, ref)

			exRefs, eerr := ctr.QueryExamples.FindBySymbolInModule(ctx, coord, ref.SymbolName, exapp.PipelineVersion)
			switch {
			case errors.Is(eerr, exampleports.ErrExampleConflict):
				conflicts = append(conflicts, eerr)
			case eerr != nil:
				return nil, nil, fmt.Errorf("reading the examples for %s: %w", qualName, eerr)
			}
			examples := make([]symbolContextExample, 0, len(exRefs))
			for _, er := range exRefs {
				examples = append(examples, symbolContextExample{
					Name:      er.ExampleName,
					Package:   er.Package,
					Validates: er.Validates,
				})
			}

			entries = append(entries, symbolContextEntry{
				Module:        mk.path + "@" + mk.version,
				Package:       ref.PackagePath,
				Name:          ref.SymbolName,
				QualifiedName: qualName,
				Kind:          ref.SymbolKind,
				Signature:     ref.Signature,
				Doc:           doc,
				Examples:      examples,
			})
		}
	}
	return entries, errors.Join(conflicts...), nil
}

// symbolDoc looks up the doc comment for ref inside the full interface record.
func symbolDoc(rec ifacedomain.InterfaceRecord, ref ifaceports.SymbolRef) string {
	for _, pkg := range rec.Packages {
		if pkg.ImportPath != ref.PackagePath {
			continue
		}
		if doc, ok := symbolDocInPackage(pkg, ref); ok {
			return doc
		}
	}
	return ""
}

// symbolDocInPackage is the doc comment of the symbol ref names in pkg; ok is
// false when pkg does not declare it.
func symbolDocInPackage(pkg ifacedomain.PackageInterface, ref ifaceports.SymbolRef) (string, bool) {
	switch ref.SymbolKind {
	case "func":
		for _, f := range pkg.Funcs {
			if f.Name == ref.SymbolName {
				return f.Doc, true
			}
		}
	case "type":
		for _, t := range pkg.Types {
			if t.Name == ref.SymbolName {
				return t.Doc, true
			}
		}
	case "method":
		if doc, ok := methodDoc(pkg, ref); ok {
			return doc, true
		}
	case "const":
		for _, c := range pkg.Consts {
			if c.Name == ref.SymbolName {
				return c.Doc, true
			}
		}
	case "var":
		for _, v := range pkg.Vars {
			if v.Name == ref.SymbolName {
				return v.Doc, true
			}
		}
	}
	return "", false
}

// methodDoc is the doc comment of the method ref names in pkg; ok is false
// when no type of pkg declares it.
func methodDoc(pkg ifacedomain.PackageInterface, ref ifaceports.SymbolRef) (string, bool) {
	for _, t := range pkg.Types {
		if t.Name != ref.ParentType {
			continue
		}
		for _, m := range t.Methods {
			if m.Name == ref.SymbolName {
				return m.Doc, true
			}
		}
	}
	return "", false
}

// printSymbolContext renders entries as human-readable text, then appends an
// approximate token count footer (byte length of the JSON representation ÷ 4).
func printSymbolContext(entries []symbolContextEntry, stdout io.Writer) error {
	for i, e := range entries {
		if i > 0 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return fmt.Errorf("writing separator: %w", err)
			}
		}
		if _, err := fmt.Fprintf(stdout, "%s  %s  (%s)\n", e.Module, e.QualifiedName, e.Kind); err != nil {
			return fmt.Errorf("writing header: %w", err)
		}
		if sig := ifacedomain.NormalizeSignature(e.Signature); sig != "" {
			if _, err := fmt.Fprintf(stdout, "  %s\n", sig); err != nil {
				return fmt.Errorf("writing signature: %w", err)
			}
		}
		if e.Doc != "" {
			if _, err := fmt.Fprintf(stdout, "\n  %s\n", e.Doc); err != nil {
				return fmt.Errorf("writing doc: %w", err)
			}
		}
		if len(e.Examples) > 0 {
			if err := printSymbolExamples(stdout, e.Examples); err != nil {
				return err
			}
		}
	}

	if len(entries) > 0 {
		raw, err := json.Marshal(entries)
		if err != nil {
			return fmt.Errorf("computing token estimate: %w", err)
		}
		byteCount := len(raw)
		if _, err := fmt.Fprintf(stdout, "\n~%d tokens (%d bytes)\n", byteCount/4, byteCount); err != nil {
			return fmt.Errorf("writing token count: %w", err)
		}
	}
	return nil
}

// printSymbolExamples lists the symbol's examples, marking those that
// validate.
func printSymbolExamples(stdout io.Writer, examples []symbolContextExample) error {
	if _, err := fmt.Fprintln(stdout, "\n  Examples:"); err != nil {
		return fmt.Errorf("writing examples header: %w", err)
	}
	for _, ex := range examples {
		validates := ""
		if ex.Validates {
			validates = " (validates)"
		}
		if _, err := fmt.Fprintf(stdout, "    %s%s\n", ex.Name, validates); err != nil {
			return fmt.Errorf("writing example: %w", err)
		}
	}
	return nil
}
