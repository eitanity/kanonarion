package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/iface/domain"
)

// The text rendering of an interface record.
//
// The record is the answer to "the API as shipped", so this renderer prints
// every declaration the record holds for a type — its fields, the methods
// declared on it, and the methods and fields that are callable on it only
// because it embeds something else. Those last are marked "promoted" and name
// the embedding they arrive through: "declared on this type" and "callable on
// this type" are different facts about a type, and a reader deciding whether an
// upgrade breaks them needs to tell them apart.
//
// Promotion is resolved against the whole record, never the filtered view, so
// --package and --symbol narrow what is printed without changing what a
// printed type is said to offer.

// promotionIndex resolves an embedded type's spelling to the declaration the
// record holds for it. Types are reachable by import path (the enclosing
// package's own types) and by package name (the qualifier an embedded
// "pkg.Type" spelling carries, which is a package name, not an import path).
type promotionIndex struct {
	byImportPath map[string]map[string]domain.TypeDecl
	pkgNameToXfe map[string][]string // package name -> import paths declaring it
}

func newPromotionIndex(r domain.InterfaceRecord) promotionIndex {
	idx := promotionIndex{
		byImportPath: make(map[string]map[string]domain.TypeDecl, len(r.Packages)),
		pkgNameToXfe: make(map[string][]string, len(r.Packages)),
	}
	for _, pkg := range r.Packages {
		types := make(map[string]domain.TypeDecl, len(pkg.Types))
		for _, t := range pkg.Types {
			types[t.Name] = t
		}
		idx.byImportPath[pkg.ImportPath] = types
		idx.pkgNameToXfe[pkg.Name] = append(idx.pkgNameToXfe[pkg.Name], pkg.ImportPath)
	}
	return idx
}

// lookup resolves an embedded spelling as written inside package fromPath.
// Reports false when the record holds no declaration for it — which is the
// normal case for a type embedded from the standard library or from a
// dependency, neither of which this record describes.
func (idx promotionIndex) lookup(fromPath, spelling string) (domain.TypeDecl, string, bool) {
	name := strings.TrimPrefix(strings.TrimSpace(spelling), "*")
	if i := strings.IndexByte(name, '['); i >= 0 { // generic instantiation
		name = name[:i]
	}
	if name == "" {
		return domain.TypeDecl{}, "", false
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		qualifier, bare := name[:i], name[i+1:]
		for _, path := range idx.pkgNameToXfe[qualifier] {
			if t, ok := idx.byImportPath[path][bare]; ok {
				return t, path, true
			}
		}
		return domain.TypeDecl{}, "", false
	}
	t, ok := idx.byImportPath[fromPath][name]
	return t, fromPath, ok
}

// promotedDecl is one declaration a type offers through embedding: the line to
// print, and the chain of embeddings it arrives through.
type promotedDecl struct {
	name string
	kind string // "func" or "field"
	text string
	via  string
}

// unresolvedEmbed is an embedded type the record holds no declaration for, so
// what it promotes cannot be listed. Named rather than dropped: the alternative
// is output that looks complete and is not.
type unresolvedEmbed struct {
	spelling string
	via      string
}

// maxPromotionDepth bounds the embedding walk. Go itself has no depth limit;
// this stops a record whose types embed one another from spinning, and no real
// API nests this deep.
const maxPromotionDepth = 16

// embedRef is one embedded type reached during the walk.
type embedRef struct {
	decl    domain.TypeDecl
	pkgPath string
	via     string
}

// resolvePromoted walks t's embeddings breadth-first and returns what they make
// callable on t, following Go's own promotion rules: a name declared at a
// shallower depth shadows the same name deeper in, and two declarations of one
// name at the same depth promote neither.
func resolvePromoted(t domain.TypeDecl, pkgPath string, idx promotionIndex) ([]promotedDecl, []unresolvedEmbed) {
	shadowed := make(map[string]bool, len(t.Methods)+len(t.Fields))
	for _, m := range t.Methods {
		shadowed[m.Name] = true
	}
	for _, f := range t.Fields {
		shadowed[f.Name] = true
	}

	var out []promotedDecl
	var unresolved []unresolvedEmbed
	visited := map[string]bool{pkgPath + "." + t.Name: true}

	level, unres := embeddingsOf(t, pkgPath, "", idx, visited)
	unresolved = append(unresolved, unres...)

	for depth := 0; depth < maxPromotionDepth && len(level) > 0; depth++ {
		// Collect every candidate at this depth before deciding any of them:
		// a name offered twice at one depth is ambiguous and promotes nothing.
		candidates := make(map[string][]promotedDecl)
		for _, ref := range level {
			for _, m := range ref.decl.Methods {
				candidates[m.Name] = append(candidates[m.Name], promotedDecl{
					name: m.Name, kind: "func", text: m.Signature, via: ref.via,
				})
			}
			for _, f := range ref.decl.Fields {
				candidates[f.Name] = append(candidates[f.Name], promotedDecl{
					name: f.Name, kind: "field", text: fieldText(f), via: ref.via,
				})
			}
		}
		names := make([]string, 0, len(candidates))
		for name := range candidates {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if shadowed[name] {
				continue
			}
			// Shadowed for every deeper level either way: an ambiguous name at
			// this depth still blocks the same name below it.
			shadowed[name] = true
			if len(candidates[name]) == 1 {
				out = append(out, candidates[name][0])
			}
		}

		var next []embedRef
		for _, ref := range level {
			deeper, unres := embeddingsOf(ref.decl, ref.pkgPath, ref.via, idx, visited)
			next = append(next, deeper...)
			unresolved = append(unresolved, unres...)
		}
		level = next
	}

	sort.SliceStable(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out, dedupeEmbeds(unresolved)
}

// dedupeEmbeds collapses repeats so one unresolvable embedding is named once.
func dedupeEmbeds(in []unresolvedEmbed) []unresolvedEmbed {
	if len(in) < 2 {
		return in
	}
	seen := make(map[unresolvedEmbed]bool, len(in))
	out := in[:0]
	for _, u := range in {
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// embeddingsOf resolves one type's embedded fields and embedded interfaces.
func embeddingsOf(t domain.TypeDecl, pkgPath, via string, idx promotionIndex, visited map[string]bool) ([]embedRef, []unresolvedEmbed) {
	spellings := make([]string, 0, len(t.Fields)+len(t.EmbeddedTypes))
	for _, f := range t.Fields {
		if f.Embedded {
			spellings = append(spellings, f.Name)
		}
	}
	spellings = append(spellings, t.EmbeddedTypes...)

	var refs []embedRef
	var unresolved []unresolvedEmbed
	for _, spelling := range spellings {
		chain := spelling
		if via != "" {
			chain = via + " -> " + spelling
		}
		decl, path, ok := idx.lookup(pkgPath, spelling)
		if !ok {
			unresolved = append(unresolved, unresolvedEmbed{spelling: spelling, via: via})
			continue
		}
		key := path + "." + decl.Name
		if visited[key] {
			continue
		}
		visited[key] = true
		refs = append(refs, embedRef{decl: decl, pkgPath: path, via: chain})
	}
	return refs, unresolved
}

// fieldText renders one struct field as the record holds it.
func fieldText(f domain.FieldDecl) string {
	text := f.Name + " " + f.Type
	if f.Tag != "" {
		text += " " + f.Tag
	}
	return text
}

func printRecordText(r domain.InterfaceRecord, idx promotionIndex, stdout io.Writer) error {
	for _, pkg := range r.Packages {
		if _, err := fmt.Fprintf(stdout, "\npackage %s // %s\n", pkg.Name, pkg.ImportPath); err != nil {
			return fmt.Errorf("writing package header: %w", err)
		}
		for _, t := range pkg.Types {
			if err := printTypeText(t, pkg.ImportPath, idx, stdout); err != nil {
				return err
			}
		}
		for _, f := range pkg.Funcs {
			if _, err := fmt.Fprintf(stdout, "  %s\n", f.Signature); err != nil {
				return fmt.Errorf("writing func: %w", err)
			}
		}
		for _, c := range pkg.Consts {
			if _, err := fmt.Fprintf(stdout, "  const %s\n", valueText(c)); err != nil {
				return fmt.Errorf("writing const: %w", err)
			}
		}
		for _, v := range pkg.Vars {
			if _, err := fmt.Fprintf(stdout, "  var %s\n", valueText(v)); err != nil {
				return fmt.Errorf("writing var: %w", err)
			}
		}
		for _, pf := range pkg.ParseFailures {
			if _, err := fmt.Fprintf(stdout, "  [parse failure] %s: %s\n", pf.File, pf.Error); err != nil {
				return fmt.Errorf("writing parse failure: %w", err)
			}
		}
	}
	return nil
}

// valueText renders a const or var. A declaration the record holds no type for
// says so rather than printing a blank column: the source declared none, which
// is a fact about the API and not a gap in the reading.
func valueText(v domain.ValueDecl) string {
	if v.Type == "" {
		return v.Name + " (no declared type)"
	}
	return v.Name + " " + v.Type
}

func printTypeText(t domain.TypeDecl, pkgPath string, idx promotionIndex, stdout io.Writer) error {
	if _, err := fmt.Fprintf(stdout, "  type %s (%s)\n", t.Name, t.Kind.String()); err != nil {
		return fmt.Errorf("writing type: %w", err)
	}
	for _, f := range t.Fields {
		line := "    field " + fieldText(f)
		if f.Embedded {
			line = "    embeds " + f.Type
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", line); err != nil {
			return fmt.Errorf("writing field: %w", err)
		}
	}
	for _, e := range t.EmbeddedTypes {
		if _, err := fmt.Fprintf(stdout, "    embeds %s\n", e); err != nil {
			return fmt.Errorf("writing embedded type: %w", err)
		}
	}
	for _, m := range t.Methods {
		// m.Signature already begins with "func".
		if _, err := fmt.Fprintf(stdout, "    %s\n", m.Signature); err != nil {
			return fmt.Errorf("writing method: %w", err)
		}
	}
	promoted, unresolved := resolvePromoted(t, pkgPath, idx)
	for _, p := range promoted {
		text := p.text
		if p.kind == "field" {
			text = "field " + text
		}
		if _, err := fmt.Fprintf(stdout, "    promoted %s  // via %s\n", text, p.via); err != nil {
			return fmt.Errorf("writing promoted declaration: %w", err)
		}
	}
	for _, u := range unresolved {
		via := ""
		if u.via != "" {
			via = ", embedded through " + u.via
		}
		if _, err := fmt.Fprintf(stdout,
			"    [promotions from %s not shown: this record describes no such type%s]\n",
			u.spelling, via,
		); err != nil {
			return fmt.Errorf("writing unresolved embedding: %w", err)
		}
	}
	return nil
}
