package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/spf13/cobra"

	exapp "github.com/eitanity/kanonarion/internal/example/application"

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
}

func newSymbolContextCmd(stdout, stderr io.Writer) *cobra.Command {
	var f symbolContextFlags

	cmd := &cobra.Command{
		Use:   "symbol-context <name>",
		Short: "Assemble per-module symbol record with signature, godoc, and examples",
		Example: `  kanonarion symbol-context Marshal
  kanonarion symbol-context New --module github.com/spf13/cobra@v1.8.1
  kanonarion symbol-context Client --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			return runSymbolContext(cmd.Context(), args[0], f, jsonOut, stdout, stderr)
		},
	}

	cmd.Flags().StringVar(&f.module, "module", "", "narrow results to a specific module@version")

	return cmd
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
	defer func() { _ = cleanup() }()

	refs, err := ctr.QueryInterface.FindSymbol(ctx, symbolName, ifaceapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("finding symbol %q: %w", symbolName, err)
	}

	if f.module != "" {
		coord, err := parseCoordinate(f.module)
		if err != nil {
			return fmt.Errorf("invalid --module %q: %w", f.module, err)
		}
		// Distinguish "module not in store" from "symbol not found": an
		// empty result is ambiguous unless we know the module was indexed.
		if _, found, gerr := ctr.QueryInterface.GetInterfaceRecord(ctx, coord, ifaceapp.PipelineVersion); gerr == nil && !found {
			_, _ = fmt.Fprintf(stderr, "no interface record for %s in the store; run 'kanonarion interface %s' first\n", f.module, f.module)
			if jsonOut {
				_, _ = fmt.Fprintln(stdout, "[]")
				return nil
			}
			return nil
		}
		var filtered []ifaceports.SymbolRef
		for _, ref := range refs {
			if ref.ModulePath == coord.Path && ref.ModuleVersion == coord.Version {
				filtered = append(filtered, ref)
			}
		}
		refs = filtered
	}

	// Drop symbols in non-importable packages (internal/, testdata/): they
	// cannot be called by consumers, so they are misleading as call targets.
	refs = filterImportableRefs(refs)

	if len(refs) == 0 {
		if jsonOut {
			_, _ = fmt.Fprintln(stdout, "[]")
			return nil
		}
		_, _ = fmt.Fprintf(stdout, "no exports found for symbol %q\n", symbolName)
		return nil
	}

	entries, err := buildSymbolContextEntries(ctx, ctr, refs, ifaceapp.PipelineVersion)
	if err != nil {
		return err
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			return fmt.Errorf("encoding symbol context: %w", err)
		}
		return nil
	}
	return printSymbolContext(entries, stdout)
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
	for _, seg := range strings.Split(importPath, "/") {
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
func buildSymbolContextEntries(ctx context.Context, ctr *Container, refs []ifaceports.SymbolRef, pipelineVersion string) ([]symbolContextEntry, error) {
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

	entries := make([]symbolContextEntry, 0, len(refs))
	for _, mk := range order {
		coord := coordinate.ModuleCoordinate{Path: mk.path, Version: mk.version}

		// Best-effort: missing interface record means empty doc.
		ifaceRec, _, _ := ctr.QueryInterface.GetInterfaceRecord(ctx, coord, pipelineVersion)

		for _, ref := range byModule[mk] {
			qualName := ref.PackagePath + "." + ref.SymbolName
			if ref.ParentType != "" {
				qualName = ref.PackagePath + "." + ref.ParentType + "." + ref.SymbolName
			}

			doc := symbolDoc(ifaceRec, ref)

			exRefs, _ := ctr.QueryExamples.FindBySymbolInModule(ctx, coord, ref.SymbolName, exapp.PipelineVersion)
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
	return entries, nil
}

// symbolDoc looks up the doc comment for ref inside the full interface record.
func symbolDoc(rec ifacedomain.InterfaceRecord, ref ifaceports.SymbolRef) string {
	for _, pkg := range rec.Packages {
		if pkg.ImportPath != ref.PackagePath {
			continue
		}
		switch ref.SymbolKind {
		case "func":
			for _, f := range pkg.Funcs {
				if f.Name == ref.SymbolName {
					return f.Doc
				}
			}
		case "type":
			for _, t := range pkg.Types {
				if t.Name == ref.SymbolName {
					return t.Doc
				}
			}
		case "method":
			for _, t := range pkg.Types {
				if t.Name != ref.ParentType {
					continue
				}
				for _, m := range t.Methods {
					if m.Name == ref.SymbolName {
						return m.Doc
					}
				}
			}
		case "const":
			for _, c := range pkg.Consts {
				if c.Name == ref.SymbolName {
					return c.Doc
				}
			}
		case "var":
			for _, v := range pkg.Vars {
				if v.Name == ref.SymbolName {
					return v.Doc
				}
			}
		}
	}
	return ""
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
			if _, err := fmt.Fprintln(stdout, "\n  Examples:"); err != nil {
				return fmt.Errorf("writing examples header: %w", err)
			}
			for _, ex := range e.Examples {
				validates := ""
				if ex.Validates {
					validates = " (validates)"
				}
				if _, err := fmt.Fprintf(stdout, "    %s%s\n", ex.Name, validates); err != nil {
					return fmt.Errorf("writing example: %w", err)
				}
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
