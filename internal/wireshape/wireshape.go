// Package wireshape enumerates the collections a record domain seals over.
//
// A record's content hash is taken over its canonical JSON, so the ORDER of
// every collection in that JSON is part of the seal. When the order is a
// property of the record — a total order over its elements — two measurements
// of one thing seal identically. When it is an arrangement the producer
// happened to emit, they do not, and the store fills with records that disagree
// about a measurement that did not change.
//
// Interface extraction proved it: golang.org/x/tools ships directories where two
// files declare a function of the same name, the comparator was keyed on the
// name alone, and sort.Slice is not stable — so one module version held eight
// records under seven digests, five of them minutes apart.
//
// The per-domain determinism guards shuffle the collections a record carries and
// assert one digest. Collections reports which collections those are, from the
// TYPE rather than from a list somebody kept in their head, so a collection
// added to a sealed shape cannot go unshuffled: the guard for a record with no
// collections at all asserts that Collections is empty, and gains a failure the
// day one appears.
package wireshape

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Collections returns the JSON path of every slice reachable from typ, sorted.
// A path reads like the JSON does: "packages[].funcs" is the funcs array inside
// an element of the packages array, and "per_module_results{}.stages" is the
// stages array inside a map value.
//
// The walk stops at a type that renders its own JSON, since what such a type
// emits is not readable from its Go fields. Pass those types to Opaque so the
// walk can say it stopped deliberately; an unlisted one fails the test, because
// a type that might hide a collection and might not is exactly the silent case
// this package exists to remove.
func Collections(t *testing.T, typ reflect.Type, opaque ...map[string]string) []string {
	t.Helper()

	known := map[string]string{
		"time.Time": "an RFC3339 string",
	}
	for _, m := range opaque {
		for k, v := range m {
			known[k] = v
		}
	}
	found := map[string]bool{}
	walk(t, typ, "", known, found, map[reflect.Type]bool{})

	out := make([]string, 0, len(found))
	for path := range found {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func walk(t *testing.T, typ reflect.Type, path string, opaque map[string]string, found map[string]bool, seen map[reflect.Type]bool) {
	t.Helper()

	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	// A recursive shape — a node holding its own children — would otherwise
	// descend forever. Its collections are already recorded at the shallower
	// path, which is the one a reader would name.
	if seen[typ] {
		return
	}
	if typ.Implements(reflect.TypeFor[json.Marshaler]()) || reflect.PointerTo(typ).Implements(reflect.TypeFor[json.Marshaler]()) {
		if _, ok := opaque[typ.String()]; !ok {
			t.Errorf("%s renders its own JSON at %q and is not listed as opaque: "+
				"state what it emits, or the walk cannot say whether it hides a collection", typ, path)
		}
		return
	}
	switch typ.Kind() {
	case reflect.Slice, reflect.Array:
		// A byte slice is a base64 string on the wire, not a collection whose
		// order a producer could arrange differently.
		if typ.Elem().Kind() == reflect.Uint8 {
			return
		}
		found[path] = true
		walk(t, typ.Elem(), path+"[]", opaque, found, seen)
	case reflect.Map:
		walk(t, typ.Elem(), path+"{}", opaque, found, seen)
	case reflect.Struct:
		seen[typ] = true
		defer delete(seen, typ)
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			child := name
			if path != "" {
				child = path + "." + name
			}
			walk(t, field.Type, child, opaque, found, seen)
		}
	}
}
