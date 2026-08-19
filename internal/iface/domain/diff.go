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
	// MovedTo is the B-side identity when the declaration's import path changed
	// along with its signature, which happens across a major-version path pair.
	// Zero when both sides carry the same identity, which is every same-path
	// comparison.
	//
	// Symbol stays the A-side identity because that is what a consumer of the
	// baseline version calls, and therefore what its recorded call-graph nodes
	// are spelled as.
	MovedTo SymbolID
}

// RenamedSymbol is one declaration that exists in both records under the same
// package-relative identity and with the same signature, and whose import path
// differs only because the module path does.
//
// It is an obligation on the consumer — the import must be rewritten — and it is
// not a removal, an addition or a signature change, so it is reported on its own
// and excluded from the breaking count, exactly as a spelling change is.
type RenamedSymbol struct {
	From SymbolID
	To   SymbolID
	// Signature is the text both sides carry; they are equal by construction.
	Signature string
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

	// RenamedPath is declarations carried across a major-version path pair
	// unchanged: same package-relative identity, same signature, different import
	// path. It is reported separately and is NOT part of BreakingCount.
	//
	// It is empty for every same-path comparison, where the two sides spell every
	// identity the same way and nothing can be renamed.
	RenamedPath []RenamedSymbol

	// MajorPathPair records that the two coordinates are the same module path
	// after a trailing "/vN" is stripped from either side — a cross-major bump,
	// where every import path changes whether or not any declaration did.
	MajorPathPair bool

	// Registries are string-keyed function/value tables either record exports.
	Registries []RegistrySurface

	// ExcludedTestdataPackages are import paths dropped from the comparison on
	// both sides because they sit under a testdata directory, named so their
	// absence is a stated exclusion rather than a silent one.
	ExcludedTestdataPackages []string

	// FrameMismatch is true when the two records were not measured in the same
	// build frame, including when only one of them names a frame at all.
	//
	// The comparison is still computed and still reported: refusing would leave
	// the reader with nothing. But every difference it lists may be a difference
	// between two platforms rather than between two versions, so the result
	// carries this flag and the surfaces that print it say so.
	FrameMismatch bool
}

// SameFrame reports whether two records describe the same build configuration.
// Two records that name no frame are the same in name only — each holds every
// platform's declarations at once — so that pair is NOT the same frame.
func SameFrame(a, b InterfaceRecord) bool {
	if a.BuildFrame.IsZero() || b.BuildFrame.IsZero() {
		return false
	}
	return a.BuildFrame == b.BuildFrame
}

// BreakingCount is the number of exported declarations that changed in a way a
// consumer can be broken by: one that is gone, and one whose signature is no
// longer the same signature. Spelling differences are excluded by construction.
func (d InterfaceDiff) BreakingCount() int {
	return len(d.Removed) + len(d.Changed)
}

// HasChanges reports whether the comparison found any delta at all — spelling
// and path renames included.
func (d InterfaceDiff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0 ||
		len(d.Spelling) > 0 || len(d.RenamedPath) > 0
}

// ZeroBreakingOverNonTrivialDelta reports the case a reader is most likely to
// misread: the comparison found no breaking change, and it did find something.
//
// A zero next to a delta is not a safety result. This comparison reads exported
// signatures, so it cannot see behaviour, and a release that respells a surface,
// adds to it or moves it to a new import path has plainly been worked on. That
// is precisely when "no breaking change" wants checking against something this
// command does not measure.
//
// A genuinely empty delta is excluded: there is nothing there to misread.
func (d InterfaceDiff) ZeroBreakingOverNonTrivialDelta() bool {
	return d.BreakingCount() == 0 && d.HasChanges()
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
	diff := InterfaceDiff{RecordA: a, RecordB: b, FrameMismatch: !SameFrame(a, b)}

	pkgsA, exclA := comparablePackages(a)
	pkgsB, exclB := comparablePackages(b)
	diff.ExcludedTestdataPackages = mergeSorted(exclA, exclB)

	// A cross-major bump changes every import path in the module, so comparing by
	// fully-qualified identity would report the entire surface as removed and
	// re-added. Under a major-version path pair the comparison keys on the
	// identity the path change does not touch: the package path relative to the
	// module, the kind, and the name.
	pathA, pathB := a.Coordinate.Path(), b.Coordinate.Path()
	diff.MajorPathPair = isMajorPathPair(pathA, pathB)
	relA, relB := "", ""
	if diff.MajorPathPair {
		relA, relB = pathA, pathB
	}

	diff.PackagesAdded = missingFrom(pkgsB, pkgsA, relB, relA)
	diff.PackagesRemoved = missingFrom(pkgsA, pkgsB, relA, relB)

	symsA := collectSymbols(pkgsA)
	symsB := collectSymbols(pkgsB)
	keyedB := indexByIdentity(symsB, relB)

	matchedA := make(map[SymbolID]struct{}, len(symsA))
	matchedB := make(map[SymbolID]struct{}, len(symsB))
	for _, idA := range sortedIDs(symsA) {
		idB, ok := keyedB[identityOf(idA, relA)]
		if !ok {
			continue
		}
		matchedA[idA] = struct{}{}
		matchedB[idB] = struct{}{}

		symA, symB := symsA[idA], symsB[idB]
		if symA.Signature == symB.Signature {
			if idA != idB {
				diff.RenamedPath = append(diff.RenamedPath, RenamedSymbol{
					From:        idA,
					To:          idB,
					Signature:   symB.Signature,
					PtrReceiver: symB.PtrReceiver,
				})
			}
			continue
		}
		change := SignatureChange{
			Symbol:      idA,
			From:        symA.Signature,
			To:          symB.Signature,
			PtrReceiver: symB.PtrReceiver,
		}
		if idA != idB {
			change.MovedTo = idB
		}
		if reader.DiffersOnlyInSpelling(change.From, change.To) {
			diff.Spelling = append(diff.Spelling, change)
			continue
		}
		diff.Changed = append(diff.Changed, change)
	}

	for _, id := range sortedIDs(symsB) {
		if _, ok := matchedB[id]; !ok {
			diff.Added = append(diff.Added, symsB[id])
		}
	}
	for _, id := range sortedIDs(symsA) {
		if _, ok := matchedA[id]; !ok {
			diff.Removed = append(diff.Removed, symsA[id])
		}
	}

	diff.Registries = detectRegistries(pkgsA, pkgsB, reader)

	return diff
}

// isMajorPathPair reports whether two module paths are the same module under two
// major versions: equal once a trailing "/vN" is stripped from either, and not
// already equal.
//
// The "+incompatible" side needs no special handling — a pre-modules major
// carries no path suffix at all, so github.com/x/y and github.com/x/y/v3 are the
// pair, and the version string never enters this comparison.
func isMajorPathPair(a, b string) bool {
	return a != b && stripMajorSuffix(a) == stripMajorSuffix(b)
}

// stripMajorSuffix removes a trailing major-version element from a module path.
// Only /v2 and above are module path suffixes: /v0 and /v1 are not, and a path
// that ends in one of those is a path element that happens to look like a major.
func stripMajorSuffix(path string) string {
	i := strings.LastIndex(path, "/v")
	if i < 0 {
		return path
	}
	digits := path[i+2:]
	if len(digits) == 0 || digits == "0" || digits == "1" || digits[0] == '0' {
		return path
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return path
		}
	}
	return path[:i]
}

// symbolIdentity is the identity a symbol keeps across a module path change: the
// package path relative to the module, the kind and the name.
type symbolIdentity struct {
	RelPackage string
	Kind       SymbolKind
	Name       string
}

// identityOf renders a symbol's path-independent identity. modulePath is empty
// for a same-path comparison, where the identity is the fully-qualified one and
// this reduces to today's exact comparison.
func identityOf(id SymbolID, modulePath string) symbolIdentity {
	return symbolIdentity{
		RelPackage: relativePackage(id.Package, modulePath),
		Kind:       id.Kind,
		Name:       id.Name,
	}
}

// relativePackage returns an import path relative to its module path, or the
// import path unchanged when it does not sit under that module — which the
// records should never contain, and which must not be silently folded onto some
// other package's identity if they do.
func relativePackage(importPath, modulePath string) string {
	if modulePath == "" {
		return importPath
	}
	if importPath == modulePath {
		return ""
	}
	if rest, ok := strings.CutPrefix(importPath, modulePath+"/"); ok {
		return "/" + rest
	}
	return importPath
}

// indexByIdentity maps each path-independent identity to the symbol carrying it.
//
// The mapping is one-to-one and needs no collision handling: identityOf differs
// from the symbol's own identity only in the package component, and
// relativePackage sends a package under the module to "" or to a "/"-prefixed
// path while sending anything else to its own import path unchanged. An import
// path cannot begin with "/", so no two distinct packages of one record can
// reduce to the same component, and the symbols themselves are already keyed by
// a unique SymbolID.
func indexByIdentity(syms map[SymbolID]Symbol, modulePath string) map[symbolIdentity]SymbolID {
	out := make(map[symbolIdentity]SymbolID, len(syms))
	for id := range syms {
		out[identityOf(id, modulePath)] = id
	}
	return out
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

// missingFrom returns the import paths of want that have no package in have,
// compared relative to each side's module path.
//
// wantModule and haveModule are empty for a same-path comparison and the
// comparison is then on the import paths themselves. Across a major path pair
// they make the pair's own path shift invisible: sprig and sprig/v3 both hold
// the module's root package, so neither is a package added or removed, while a
// genuinely new subpackage still is — reported under the import path the side it
// exists on actually spells.
func missingFrom(want, have []PackageInterface, wantModule, haveModule string) []string {
	index := make(map[string]struct{}, len(have))
	for _, p := range have {
		index[relativePackage(p.ImportPath, haveModule)] = struct{}{}
	}
	var out []string
	for _, p := range want {
		if _, ok := index[relativePackage(p.ImportPath, wantModule)]; !ok {
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
