package domain

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// EscapeKind names how a module type's value was handed to code outside the
// module.
type EscapeKind string

const (
	// EscapeConversion is a conversion of the type to an interface type.
	EscapeConversion EscapeKind = "interface-conversion"
	// EscapeTypeArgument is the type passed as a type argument to a generic
	// function or type declared outside the module, or to an owned one that
	// converts or hands on that type parameter.
	EscapeTypeArgument EscapeKind = "type-argument"
)

// ErrInvalidDependencyDispatch is returned for a dispatch fact no extraction
// would record.
var ErrInvalidDependencyDispatch = errors.New("invalid dependency dispatch")

// DispatchEscape is one place a module type left the module's static view: a
// conversion to an interface, or a type argument to a generic that hands it on.
type DispatchEscape struct {
	Kind EscapeKind
	// Type is the escaping type as written, relative to the method's package.
	Type string
	// Via is the interface type converted to, or the generic instantiated.
	Via string
	// Function is the node ID of the function holding the site.
	Function string
	// Site is the instruction's position; zero where it has none.
	Site SourcePosition
}

// DependencyDispatch records that an exported method of a module type can be
// called by a dependency the record holds no body for. A dependency cannot name
// a module type, so it reaches the method only through a value it was handed as
// an interface or a type argument; Escape is the first such hand-off in a stable
// order. Interfaces are the package-level interfaces declared outside the
// module that contain the method and that the escaping type satisfies.
// The zero value means the method's type never escapes.
//
// ProductionEscape and ProductionInterfaces are the same over hand-offs in
// production code only, zero when every hand-off is in a test: a test's
// hand-off is real to callers, which cover both scopes, and to no consumer's
// build.
type DependencyDispatch struct {
	Escape               DispatchEscape
	Interfaces           []string
	ProductionEscape     DispatchEscape
	ProductionInterfaces []string
}

// NewDependencyDispatch builds a fact from every hand-off and from the
// production ones, refusing the zero value and every shape Validate refuses.
func NewDependencyDispatch(all, production DependencyDispatch) (DependencyDispatch, error) {
	d := DependencyDispatch{
		Escape: all.Escape, Interfaces: all.Interfaces,
		ProductionEscape: production.Escape, ProductionInterfaces: production.Interfaces,
	}
	if d.IsZero() {
		return DependencyDispatch{}, fmt.Errorf("%w: no escape", ErrInvalidDependencyDispatch)
	}
	if err := d.Validate(); err != nil {
		return DependencyDispatch{}, err
	}
	return d, nil
}

// IsZero reports whether the method carries no dispatch fact.
func (d DependencyDispatch) IsZero() bool {
	return d.Escape == DispatchEscape{} && len(d.Interfaces) == 0 && !d.InProduction() && len(d.ProductionInterfaces) == 0
}

// InProduction reports whether at least one hand-off is in production code.
func (d DependencyDispatch) InProduction() bool { return d.ProductionEscape != DispatchEscape{} }

// Production is the fact over production hand-offs only, zero when none is.
func (d DependencyDispatch) Production() DependencyDispatch {
	return DependencyDispatch{Escape: d.ProductionEscape, Interfaces: d.ProductionInterfaces}
}

// Validate accepts the zero value and every fact NewDependencyDispatch builds.
// It is applied on both legs of the store, as ExportDirective's is.
func (d DependencyDispatch) Validate() error {
	if d.IsZero() {
		return nil
	}
	if err := validateHandOff(d.Escape, d.Interfaces); err != nil {
		return err
	}
	if !d.InProduction() {
		if len(d.ProductionInterfaces) > 0 {
			return fmt.Errorf("%w: production interfaces with no production hand-off", ErrInvalidDependencyDispatch)
		}
		return nil
	}
	if err := validateHandOff(d.ProductionEscape, d.ProductionInterfaces); err != nil {
		return err
	}
	for _, iface := range d.ProductionInterfaces {
		if !slices.Contains(d.Interfaces, iface) {
			return fmt.Errorf("%w: production interface %q is not among %q", ErrInvalidDependencyDispatch, iface, d.Interfaces)
		}
	}
	return nil
}

// validateHandOff refuses an escape or interface list no extraction records.
func validateHandOff(e DispatchEscape, interfaces []string) error {
	if e.Kind != EscapeConversion && e.Kind != EscapeTypeArgument {
		return fmt.Errorf("%w: unknown escape kind %q", ErrInvalidDependencyDispatch, e.Kind)
	}
	if e.Type == "" || e.Via == "" || e.Function == "" {
		return fmt.Errorf("%w: %s needs a type, a target and a function, got %q, %q, %q",
			ErrInvalidDependencyDispatch, e.Kind, e.Type, e.Via, e.Function)
	}
	if e.Site.Line < 0 || (e.Site.File == "") != (e.Site.Line == 0) {
		return fmt.Errorf("%w: site %q:%d", ErrInvalidDependencyDispatch, e.Site.File, e.Site.Line)
	}
	seen := make(map[string]bool, len(interfaces))
	for _, iface := range interfaces {
		if iface == "" || seen[iface] {
			return fmt.Errorf("%w: interfaces must be named and distinct, got %q",
				ErrInvalidDependencyDispatch, interfaces)
		}
		seen[iface] = true
	}
	return nil
}

// SortedInterfaces is Interfaces in the canonical order, as a copy.
func (d DependencyDispatch) SortedInterfaces() []string {
	return slices.Sorted(slices.Values(d.Interfaces))
}

// EscapeString renders the hand-off, e.g. "*ResponseError converted to error at
// pkg.newResponseError (errors.go:12)".
func (d DependencyDispatch) EscapeString() string {
	e := d.Escape
	verb := " converted to "
	if e.Kind == EscapeTypeArgument {
		verb = " passed as a type argument to "
	}
	line := e.Type + verb + e.Via + " at " + e.Function
	if e.Site.File != "" {
		line += " (" + e.Site.File + ":" + strconv.Itoa(e.Site.Line) + ")"
	}
	return line
}

// Describe renders the fact as a sink detail: the declared interfaces a
// dependency can call the method through, or the hand-off when none is declared.
// Production().Describe() is the same over production hand-offs.
func (d DependencyDispatch) Describe() string {
	if d.Escape == (DispatchEscape{}) {
		return ""
	}
	if len(d.Interfaces) > 0 {
		return "a dependency can call it through " + strings.Join(d.SortedInterfaces(), ", ") + "; " + d.EscapeString()
	}
	return d.EscapeString() + "; a dependency handed the value can call it through an interface it asserts in its own body"
}
