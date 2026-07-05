// Package domain defines the types and invariants for example-function
// harvesting. The root aggregate is ExampleRecord, which groups all Example*
// functions harvested from a module's _test.go files.
//
// No code from the target module is executed. Extraction operates on source
// as inert text via Go's standard AST packages.
package domain
