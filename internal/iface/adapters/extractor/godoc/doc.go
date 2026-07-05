// Package godoc implements ports.InterfaceExtractor using go/parser and
// go/doc. It operates entirely on source text — no code is executed and no
// full type-checking is performed. Cross-package type resolution is
// intentionally out of scope: this adapter operates on source text only.
package godoc
