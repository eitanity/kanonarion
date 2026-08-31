package cli

import (
	"encoding/json"
	"path"
	"reflect"
	"strings"
	"testing"

	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

// This is the structural guard on every CLI view that replaced a published
// domain struct, and it is what stops such a surface regrowing at a level nobody
// is reading.
//
// A domain struct anywhere in a view republishes ITS field names, and every
// field of every type below it, so a view can be correct at the top and still be
// one field away from being the contract again. The walk is over the whole
// reachable type graph, not the top level, because that is exactly the mistake
// the first attempt at this made — and it is over EVERY such view, because a
// guard scoped to one of them says nothing about the next command to publish a
// domain type. That has been this defect's shape every time it recurred.

// projectionView is one published view and the domain types it is allowed to
// carry through untouched.
type projectionView struct {
	name string
	root reflect.Type
	// admitted are domain types the surface publishes DIRECTLY because they
	// already carry explicit snake_case tags of their own: a wire type, not a Go
	// one. Admitting one is a decision recorded here, by name, per view.
	admitted map[reflect.Type]bool
}

// projectionViews lists the views under the guard. A command that stops
// publishing a domain struct joins this list in the same change.
func projectionViews() []projectionView {
	return []projectionView{
		{
			name: "licenseDocument",
			root: reflect.TypeOf(licenseDocument{}),
			admitted: map[reflect.Type]bool{
				reflect.TypeOf(licdomain.Obligations{}): true,
			},
		},
		{
			name: "scanRunDiffDocument",
			root: reflect.TypeOf(scanRunDiffDocument{}),
		},
	}
}

// isDomainStruct reports whether a type belongs to one of this tree's domain
// packages, whichever one — the guard is about the class, not about licences.
func isDomainStruct(rt reflect.Type) bool {
	pkg := rt.PkgPath()
	return strings.HasPrefix(pkg, "github.com/eitanity/kanonarion/internal/") && path.Base(pkg) == "domain"
}

// TestCLIViewsAreTotalProjections refuses, in every listed view, a domain
// struct, an anonymous field and a field with no json tag.
func TestCLIViewsAreTotalProjections(t *testing.T) {
	// A type that marshals itself decides its own wire form, and its Go fields
	// never reach the document — a coordinate is a string, a timestamp is a
	// string, a database snapshot is an object of its own naming. The walk stops
	// there rather than reporting the unexported innards of time.Time as an
	// unnamed surface.
	marshaler := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	selfEncoding := func(rt reflect.Type) bool {
		return rt.Implements(marshaler) || reflect.PointerTo(rt).Implements(marshaler)
	}

	for _, view := range projectionViews() {
		t.Run(view.name, func(t *testing.T) {
			seen := map[reflect.Type]bool{}
			var walk func(reflect.Type, string)
			walk = func(rt reflect.Type, at string) {
				for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice ||
					rt.Kind() == reflect.Array || rt.Kind() == reflect.Map {
					if selfEncoding(rt) {
						return
					}
					rt = rt.Elem()
				}
				if rt.Kind() != reflect.Struct || seen[rt] || view.admitted[rt] || selfEncoding(rt) {
					return
				}
				seen[rt] = true
				if isDomainStruct(rt) {
					t.Errorf("%s reaches the domain type %s.%s: an embedded or named domain struct publishes "+
						"its own field names, which is the link these views exist to cut",
						at, path.Base(path.Dir(rt.PkgPath())), rt.Name())
					return
				}
				for i := 0; i < rt.NumField(); i++ {
					f := rt.Field(i)
					if !f.IsExported() {
						continue
					}
					if f.Anonymous {
						t.Errorf("%s embeds %s: an embedded type publishes ITS field names", at, f.Type)
					}
					if f.Tag.Get("json") == "" {
						t.Errorf("%s.%s has no json tag, so its wire name is a Go identifier", at, f.Name)
					}
					walk(f.Type, at+"."+f.Name)
				}
			}
			walk(view.root, view.name)
		})
	}
}
