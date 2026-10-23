// Package yamlkeys refuses a YAML mapping key that the Go type it decodes into
// does not name, so a misspelt setting is an error rather than a setting that
// silently never applies.
//
// It walks the parsed node against the type's yaml tags instead of using
// yaml.v3's KnownFields: that error names neither the key's full path nor a
// spelling the reader may have meant, and a config file has top-level sections
// the type cannot know about (a registered backend's own section).
package yamlkeys

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// UnknownKeyError is a mapping key the schema does not define.
type UnknownKeyError struct {
	// Key is the key's full dotted path, e.g. "stages.fetch.allowed_vcs_host".
	Key string
	// Suggestion is the nearest key the schema defines at that level, "" when
	// none is close.
	Suggestion string
	// File is the file the key was read from, "" when the caller did not say.
	File string
}

func (e *UnknownKeyError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown key %q", e.Key)
	if e.File != "" {
		fmt.Fprintf(&b, " in %s", e.File)
	}
	if e.Suggestion != "" {
		fmt.Fprintf(&b, " (did you mean %q?)", e.Suggestion)
	}
	return b.String()
}

// InFile names file on err when it is an UnknownKeyError, as a parser returns
// it; parsers take bytes, so the caller that read the file is the one that
// knows it. A wrapped error is returned as is: its text is already fixed.
func InFile(err error, file string) error {
	uk, ok := err.(*UnknownKeyError) //nolint:errorlint // only the unwrapped error's text can still change
	if !ok {
		return err
	}
	named := *uk
	named.File = file
	return &named
}

// Check refuses the first mapping key in doc that typ's yaml tags do not name,
// at any depth. Map keys are free; their values are checked against the map's
// element type. extra names further top-level keys that are known.
func Check(doc *yaml.Node, typ reflect.Type, extra ...string) error {
	c := checker{seen: map[*yaml.Node]reflect.Type{}}
	return c.walk(doc, typ, "", extra)
}

type checker struct {
	// seen stops an anchor reused through many aliases being walked again for
	// the same type, which is what keeps an alias bomb linear here.
	seen map[*yaml.Node]reflect.Type
}

func (c checker) walk(n *yaml.Node, typ reflect.Type, path string, extra []string) error {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return c.walk(n.Content[0], typ, path, extra)
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if prev, ok := c.seen[n]; ok && prev == typ {
		return nil
	}
	c.seen[n] = typ
	switch typ.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return nil
		}
		return c.walkStruct(n, typ, path, extra)
	case reflect.Map:
		if n.Kind == yaml.MappingNode {
			return c.walkMap(n, typ.Elem(), path)
		}
	case reflect.Slice, reflect.Array:
		if n.Kind == yaml.SequenceNode {
			return c.walkSeq(n, typ.Elem(), path)
		}
	}
	return nil
}

// walkMap checks each value of a map; its keys are free.
func (c checker) walkMap(n *yaml.Node, elem reflect.Type, path string) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if err := c.walk(n.Content[i+1], elem, join(path, n.Content[i].Value), nil); err != nil {
			return err
		}
	}
	return nil
}

func (c checker) walkSeq(n *yaml.Node, elem reflect.Type, path string) error {
	for i, item := range n.Content {
		if err := c.walk(item, elem, fmt.Sprintf("%s[%d]", path, i), nil); err != nil {
			return err
		}
	}
	return nil
}

func (c checker) walkStruct(n *yaml.Node, typ reflect.Type, path string, extra []string) error {
	fields, open := structFields(typ)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		if key.Tag == "!!merge" {
			if err := c.walkMerge(val, typ, path, extra); err != nil {
				return err
			}
			continue
		}
		ft, ok := fields[key.Value]
		switch {
		case ok:
			if err := c.walk(val, ft, join(path, key.Value), nil); err != nil {
				return err
			}
		case open || slices.Contains(extra, key.Value):
		default:
			known := slices.Concat(slices.Collect(maps.Keys(fields)), extra)
			return &UnknownKeyError{Key: join(path, key.Value), Suggestion: Nearest(key.Value, known)}
		}
	}
	return nil
}

// walkMerge checks the mapping (or the sequence of mappings) a "<<" key merges
// in, as if its keys were written in place.
func (c checker) walkMerge(val *yaml.Node, typ reflect.Type, path string, extra []string) error {
	for val != nil && val.Kind == yaml.AliasNode {
		val = val.Alias
	}
	if val != nil && val.Kind == yaml.SequenceNode {
		for _, m := range val.Content {
			if err := c.walk(m, typ, path, extra); err != nil {
				return err
			}
		}
		return nil
	}
	return c.walk(val, typ, path, extra)
}

// structFields maps each yaml key the struct decodes to its field type. open
// reports an inline map, which accepts any key.
func structFields(typ reflect.Type) (fields map[string]reflect.Type, open bool) {
	fields = map[string]reflect.Type{}
	for f := range typ.Fields() {
		// The decoder reads an embedded struct of unexported type, so this does.
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if strings.Contains(opts, "inline") {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Map {
				open = true
				continue
			}
			inner, innerOpen := structFields(ft)
			maps.Copy(fields, inner)
			open = open || innerOpen
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		fields[name] = f.Type
	}
	return fields, open
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// spellings maps a British spelling the schema's American keys are often
// written in to that American spelling.
var spellings = strings.NewReplacer("licence", "license")

// Nearest returns the key in known that key most likely misspells: within an
// edit distance of 2, or equal once a British spelling is made American. Ties
// go to the alphabetically first, so the suggestion is stable. "" when none is
// close.
func Nearest(key string, known []string) string {
	sorted := slices.Sorted(slices.Values(known))
	best, bestDist := "", 3
	for _, k := range sorted {
		d := min(distance(key, k), distance(spellings.Replace(key), k))
		if d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

// distance is the Levenshtein edit distance between a and b.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
