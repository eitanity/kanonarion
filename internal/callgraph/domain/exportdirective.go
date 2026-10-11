package domain

import (
	"errors"
	"fmt"
	"strings"
)

// ExportKind names who calls a function from outside Go.
type ExportKind string

const (
	// ExportWasm is //go:wasmexport: the WebAssembly host calls the function.
	ExportWasm ExportKind = "wasmexport"
	// ExportC is //export, and TinyGo's //go:export, which TinyGo treats as the
	// same: C code, assembly or a vector table calls the function.
	ExportC ExportKind = "export"
	// ExportInterrupt is TinyGo's //go:interrupt: the hardware calls the function.
	ExportInterrupt ExportKind = "interrupt"
)

// ErrInvalidExportDirective is returned for a directive no toolchain would
// accept: an unknown kind, an export with no name, or an interrupt with one.
var ErrInvalidExportDirective = errors.New("invalid export directive")

// ExportDirective is the directive that hands a package-level function to a
// caller outside Go. The zero value means the function carries none.
type ExportDirective struct {
	Kind ExportKind
	// Name is the symbol the function is exported as. An interrupt has none.
	Name string
}

// NewExportDirective builds a directive, refusing the zero value and every
// shape Validate refuses.
func NewExportDirective(kind ExportKind, name string) (ExportDirective, error) {
	d := ExportDirective{Kind: kind, Name: name}
	if d.IsZero() {
		return ExportDirective{}, fmt.Errorf("%w: no kind", ErrInvalidExportDirective)
	}
	if err := d.Validate(); err != nil {
		return ExportDirective{}, err
	}
	return d, nil
}

// IsZero reports whether the function carries no directive.
func (d ExportDirective) IsZero() bool { return d == ExportDirective{} }

// Validate accepts the zero value, which is "no directive", and every directive
// NewExportDirective builds. It is applied on both legs of the store so a record
// cannot carry a directive this build would not have recorded.
func (d ExportDirective) Validate() error {
	if d.IsZero() {
		return nil
	}
	switch d.Kind {
	case ExportWasm, ExportC:
		if d.Name == "" || strings.ContainsAny(d.Name, " \t\r\n") {
			return fmt.Errorf("%w: %s needs one name, got %q", ErrInvalidExportDirective, d.Kind, d.Name)
		}
	case ExportInterrupt:
		if d.Name != "" {
			return fmt.Errorf("%w: interrupt takes no name, got %q", ErrInvalidExportDirective, d.Name)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidExportDirective, d.Kind)
	}
	return nil
}

// String renders the directive as source spells it, and "" for the zero value.
// //go:export renders as //export, the kind it was recorded as.
func (d ExportDirective) String() string {
	switch d.Kind {
	case ExportWasm:
		return "//go:wasmexport " + d.Name
	case ExportC:
		return "//export " + d.Name
	case ExportInterrupt:
		return "//go:interrupt"
	}
	return ""
}

// ParseExportDirective reads one comment line. matched is false when the line is
// none of the four directives; err is set when it is one but takes a shape the
// toolchains ignore or refuse, so the caller can say so instead of dropping it.
// The arity rules are TinyGo's (compiler/symbol.go): an interrupt's arguments
// are ignored, an export needs exactly one name.
func ParseExportDirective(comment string) (directive ExportDirective, matched bool, err error) {
	fields := strings.Fields(comment)
	if len(fields) == 0 {
		return ExportDirective{}, false, nil
	}
	var kind ExportKind
	switch fields[0] {
	case "//go:wasmexport":
		kind = ExportWasm
	case "//export", "//go:export":
		kind = ExportC
	case "//go:interrupt":
		return ExportDirective{Kind: ExportInterrupt}, true, nil
	default:
		return ExportDirective{}, false, nil
	}
	if len(fields) != 2 {
		return ExportDirective{}, true, fmt.Errorf("%w: %s takes one name, got %d", ErrInvalidExportDirective, fields[0], len(fields)-1)
	}
	// strings.Fields leaves a non-empty name with no space in it, which Validate
	// accepts, so the directive is built directly.
	return ExportDirective{Kind: kind, Name: fields[1]}, true, nil
}
