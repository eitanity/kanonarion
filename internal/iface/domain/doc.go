// Package domain defines the types and invariants for public interface
// extraction. The root aggregate is InterfaceRecord, which captures every
// exported type, function, constant, variable, and method for a module's
// packages, derived from source using go/parser and go/doc.
//
// No code from the target module is executed. Extraction operates on source
// as inert text; full type-checking via go/types is intentionally out of
// scope. Callers needing resolved types should layer a go/types adapter on
// top of the extracted record.
package domain
