// Package local implements ports.StageRegistry with the built-in extraction
// stages (license, interface, callgraph, example) in canonical execution
// order. A gRPC or plugin-based StageRegistry can be substituted without any
// change to the application layer.
package local
