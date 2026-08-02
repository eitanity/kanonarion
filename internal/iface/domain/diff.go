package domain

import (
	"slices"
	"strings"
)

// SymbolKind names the sort of exported declaration a delta is about.
type SymbolKind string

const (
	SymbolFunc   SymbolKind = "func"
	SymbolType   SymbolKind = "type"
	SymbolMethod SymbolKind = "method"
	SymbolConst  SymbolKind = "const"
	SymbolVar    SymbolKind = "var"
)

// SymbolID identifies one exported declaration within a record. Name carries
// the receiver for a method ("Parser.Parse"), so a method is distinguishable
// from a package-level function of the same name.
type SymbolID struct {
	Package string
	Kind    SymbolKind
	Name    string
}

// String renders the identity for display: "import/path.Name (kind)".
func (s SymbolID) String() string {
	return s.Package + "." + s.Name + " (" + string(s.Kind) + ")"
}

// Symbol is one exported declaration with the text this comparison reads.
// Signature is the declaration signature for funcs, types and methods, and the
// declared type for consts and vars (empty for an untyped constant).
type Symbol struct {
	ID        SymbolID
	Signature string
	Position  SourcePosition
	// PtrReceiver is meaningful for a method only, and records which receiver
	// form the declaration used — which is what a call-graph node ID spells.
	PtrReceiver bool
}

// SignatureChange is one declaration whose signature text is not the same in
// both records.
type SignatureChange struct {
	Symbol SymbolID
	From   string
	To     string
	// PtrReceiver mirrors Symbol.PtrReceiver on the B side.
	PtrReceiver bool
}

// RegistrySide names which record a registry-shaped surface was seen in.
type RegistrySide string

const (
	RegistryInA    RegistrySide = "A"
	RegistryInB    RegistrySide = "B"
	RegistryInBoth RegistrySide = "both"
)

// RegistrySurface is an exported declaration that hands out a string-keyed table
// of functions or values — a template FuncMap, a codec registry, a plugin table.
//
// It is recorded because it is a contract this comparison CANNOT see: the keys
// are strings resolved at run time, so a key renamed or dropped changes what
// consumers get while every signature in the record stays identical. Detection
// only: the keys are not read, and no claim is made about them.
type RegistrySurface struct {
	Symbol SymbolID
	// Shape is the type text that showed the string-keyed shape.
	Shape string
	Side  RegistrySide
}

// SignatureReader answers the questions about a declaration's TEXT that this
// package must not answer for itself.
//
// The records carry formatted signature strings and no type information, so
// deciding whether two of them mean the same thing means parsing Go — which is
// infrastructure, and lives behind this port (see
// iface/adapters/spelling/goast). The comparison stays a pure function: the
// reader is deterministic, does no I/O, and the diff it produces depends on
// nothing else.
type SignatureReader interface {
	// DiffersOnlyInSpelling reports whether two signature texts differ, and
	// differ only in spellings the language treats as identical.
	DiffersOnlyInSpelling(a, b string) bool
	// RegistryShape reports whether a declared type text is a string-keyed table
	// of functions or dynamically typed values, and the shape that showed it.
	// localTypes maps the names the package declares to their declared text.
	RegistryShape(typeText string, localTypes map[string]string) (string, bool)
	// ResultRegistryShape asks the same question of a function signature's
	// results — a registry is as often handed out by a function as held in a
	// variable.
	ResultRegistryShape(signature string, localTypes map[string]string) (string, bool)
}

// unreadSignatures is what a comparison given no reader uses. It answers "no"
// to everything, which makes every textual difference a change and detects no
// registry: the conservative reading, and never a silent one — a caller that
// passes nil gets a diff that overstates the delta rather than one that
// discounts it.
type unreadSignatures struct{}

func (unreadSignatures) DiffersOnlyInSpelling(_, _ string) bool { return false }

func (unreadSignatures) RegistryShape(_ string, _ map[string]string) (string, bool) {
	return "", false
}

func (unreadSignatures) ResultRegistryShape(_ string, _ map[string]string) (string, bool) {
	return "", false
}

// InterfaceDiff is the deterministic delta between two InterfaceRecords,
// produced by DiffRecords — a pure function with no I/O.
type InterfaceDiff struct {
	RecordA InterfaceRecord
	RecordB InterfaceRecord

	// PackagesAdded and PackagesRemoved are import paths present in only one
	// record, sorted. They are reported for orientation; every declaration they
	// carry is also in Added or Removed, so they are not counted twice.
	PackagesAdded   []string
	PackagesRemoved []string

	// Added and Removed are exported declarations present in only one record.
	Added   []Symbol
	Removed []Symbol
	// Changed is declarations whose signature differs in a way the language
	// does not treat as identical.
	Changed []SignatureChange
	// Spelling is declarations whose signature text differs but whose meaning
	// does not: interface{} rewritten as any, a result that stopped being named.
	// It is reported separately and is NOT part of BreakingCount.
	Spelling []SignatureChange

	// Registries are string-keyed function/value tables either record exports.
	Registries []RegistrySurface

	// ExcludedTestdataPackages are import paths dropped from the comparison on
	// both sides because they sit under a testdata directory, named so their
	// absence is a stated exclusion rather than a silent one.
	ExcludedTestdataPackages []string
}

// BreakingCount is the number of exported declarations that changed in a way a
// consumer can be broken by: one that is gone, and one whose signature is no
// longer the same signature. Spelling differences are excluded by construction.
func (d InterfaceDiff) BreakingCount() int {
	return len(d.Removed) + len(d.Changed)
}

// HasChanges reports whether the comparison found any delta at all, spelling
// included.
func (d InterfaceDiff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0 || len(d.Spelling) > 0
}

// DiffRecords computes the deterministic delta between two InterfaceRecords. It
// is a pure function: no I/O, no clock. Every collection is sorted.
//
// Source positions are not compared. A declaration that moved down its file is
// the same declaration, and a version bump that only shifts line numbers must
// read as no change rather than as a wall of them.
func DiffRecords(a, b InterfaceRecord, reader SignatureReader) InterfaceDiff {
	if reader == nil {
		reader = unreadSignatures{}
	}
	diff := InterfaceDiff{RecordA: a, RecordB: b}

	pkgsA, exclA := comparablePackages(a)
	pkgsB, exclB := comparablePackages(b)
	diff.ExcludedTestdataPackages = mergeSorted(exclA, exclB)

	diff.PackagesAdded = missingFrom(pkgsB, pkgsA)
	diff.PackagesRemoved = missingFrom(pkgsA, pkgsB)

	symsA := collectSymbols(pkgsA)
	symsB := collectSymbols(pkgsB)

	for _, id := range sortedIDs(symsB) {
		if _, ok := symsA[id]; !ok {
			diff.Added = append(diff.Added, symsB[id])
		}
	}
	for _, id := range sortedIDs(symsA) {
		if _, ok := symsB[id]; !ok {
			diff.Removed = append(diff.Removed, symsA[id])
		}
	}
	for _, id := range sortedIDs(symsA) {
		symB, ok := symsB[id]
		if !ok || symsA[id].Signature == symB.Signature {
			continue
		}
		change := SignatureChange{
			Symbol:      id,
			From:        symsA[id].Signature,
			To:          symB.Signature,
			PtrReceiver: symB.PtrReceiver,
		}
		if reader.DiffersOnlyInSpelling(change.From, change.To) {
			diff.Spelling = append(diff.Spelling, change)
			continue
		}
		diff.Changed = append(diff.Changed, change)
	}

	diff.Registries = detectRegistries(pkgsA, pkgsB, reader)

	return diff
}

// comparablePackages splits a record's packages into the ones this comparison
// reads and the import paths it drops.
//
// A package under a testdata directory is not part of a module's exported API —
// the go tool does not build it and no consumer can import it — so a version
// that happens to carry one more of them is not a version that added a package.
// Reported as an exclusion, never dropped silently.
func comparablePackages(r InterfaceRecord) (kept []PackageInterface, excluded []string) {
	for _, p := range r.Packages {
		if isTestdataPackage(p.ImportPath) {
			excluded = append(excluded, p.ImportPath)
			continue
		}
		kept = append(kept, p)
	}
	return kept, excluded
}

// isTestdataPackage reports whether an import path has a "testdata" element.
func isTestdataPackage(importPath string) bool {
	return slices.Contains(strings.Split(importPath, "/"), "testdata")
}

// collectSymbols indexes every exported declaration of every package by identity.
func collectSymbols(pkgs []PackageInterface) map[SymbolID]Symbol {
	out := make(map[SymbolID]Symbol)
	for _, p := range pkgs {
		for _, f := range p.Funcs {
			id := SymbolID{Package: p.ImportPath, Kind: SymbolFunc, Name: f.Name}
			out[id] = Symbol{ID: id, Signature: f.Signature, Position: f.Position}
		}
		for _, t := range p.Types {
			id := SymbolID{Package: p.ImportPath, Kind: SymbolType, Name: t.Name}
			out[id] = Symbol{ID: id, Signature: t.Signature, Position: t.Position}
			for _, m := range t.Methods {
				mid := SymbolID{Package: p.ImportPath, Kind: SymbolMethod, Name: t.Name + "." + m.Name}
				out[mid] = Symbol{ID: mid, Signature: m.Signature, Position: m.Position, PtrReceiver: m.PtrReceiver}
			}
		}
		for _, c := range p.Consts {
			id := SymbolID{Package: p.ImportPath, Kind: SymbolConst, Name: c.Name}
			out[id] = Symbol{ID: id, Signature: c.Type, Position: c.Position}
		}
		for _, v := range p.Vars {
			id := SymbolID{Package: p.ImportPath, Kind: SymbolVar, Name: v.Name}
			out[id] = Symbol{ID: id, Signature: v.Type, Position: v.Position}
		}
	}
	return out
}

// sortedIDs returns the map's keys in the canonical order: package, then kind,
// then name.
func sortedIDs(m map[SymbolID]Symbol) []SymbolID {
	ids := make([]SymbolID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, compareSymbolID)
	return ids
}

func compareSymbolID(x, y SymbolID) int {
	if c := strings.Compare(x.Package, y.Package); c != 0 {
		return c
	}
	if c := strings.Compare(string(x.Kind), string(y.Kind)); c != 0 {
		return c
	}
	return strings.Compare(x.Name, y.Name)
}

// missingFrom returns the import paths of want that have no package in have.
func missingFrom(want, have []PackageInterface) []string {
	index := make(map[string]struct{}, len(have))
	for _, p := range have {
		index[p.ImportPath] = struct{}{}
	}
	var out []string
	for _, p := range want {
		if _, ok := index[p.ImportPath]; !ok {
			out = append(out, p.ImportPath)
		}
	}
	slices.Sort(out)
	return out
}

// mergeSorted returns the sorted union of two string slices.
func mergeSorted(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// detectRegistries finds the string-keyed function/value tables either record
// exports, deduplicated across the two sides.
func detectRegistries(pkgsA, pkgsB []PackageInterface, reader SignatureReader) []RegistrySurface {
	found := map[SymbolID]RegistrySurface{}
	record := func(pkgs []PackageInterface, side RegistrySide) {
		for _, s := range registrySurfacesOf(pkgs, side, reader) {
			if prev, ok := found[s.Symbol]; ok && prev.Side != side {
				prev.Side = RegistryInBoth
				found[s.Symbol] = prev
				continue
			}
			found[s.Symbol] = s
		}
	}
	record(pkgsA, RegistryInA)
	record(pkgsB, RegistryInB)

	out := make([]RegistrySurface, 0, len(found))
	for _, s := range found {
		out = append(out, s)
	}
	slices.SortFunc(out, func(x, y RegistrySurface) int {
		return compareSymbolID(x.Symbol, y.Symbol)
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// registrySurfacesOf scans one record's packages for registry-shaped exports.
//
// Both spellings of the surface count. A package may export the table as a
// variable, and it may hand it out from a function instead — sprig's FuncMap()
// is a function, and a detector that only read variables would have missed the
// case the check exists for.
func registrySurfacesOf(pkgs []PackageInterface, side RegistrySide, reader SignatureReader) []RegistrySurface {
	var out []RegistrySurface
	for _, p := range pkgs {
		local := localTypeUnderlying(p)
		add := func(id SymbolID, shape string) {
			out = append(out, RegistrySurface{Symbol: id, Shape: shape, Side: side})
		}
		for _, v := range p.Vars {
			if shape, ok := reader.RegistryShape(v.Type, local); ok {
				add(SymbolID{Package: p.ImportPath, Kind: SymbolVar, Name: v.Name}, shape)
			}
		}
		for _, c := range p.Consts {
			if shape, ok := reader.RegistryShape(c.Type, local); ok {
				add(SymbolID{Package: p.ImportPath, Kind: SymbolConst, Name: c.Name}, shape)
			}
		}
		for _, f := range p.Funcs {
			if shape, ok := reader.ResultRegistryShape(f.Signature, local); ok {
				add(SymbolID{Package: p.ImportPath, Kind: SymbolFunc, Name: f.Name}, shape)
			}
		}
		for _, t := range p.Types {
			for _, m := range t.Methods {
				if shape, ok := reader.ResultRegistryShape(m.Signature, local); ok {
					add(SymbolID{Package: p.ImportPath, Kind: SymbolMethod, Name: t.Name + "." + m.Name}, shape)
				}
			}
		}
	}
	return out
}

// localTypeUnderlying maps each named type the package declares to the text of
// what it is declared as, so a registry handed out under a local alias
// ("type Registry map[string]Handler") is still recognised.
func localTypeUnderlying(p PackageInterface) map[string]string {
	out := make(map[string]string, len(p.Types))
	for _, t := range p.Types {
		if _, under, ok := strings.Cut(t.Signature, "type "+t.Name); ok {
			out[t.Name] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(under), "="))
		}
	}
	return out
}
