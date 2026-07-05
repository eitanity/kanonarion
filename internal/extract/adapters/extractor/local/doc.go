// Package local implements ports.Extractor by routing each named stage to its
// corresponding local use case.
//
// This package is, by design, where cross-context composition lives: it
// imports the callgraph, example, iface, and license application packages and
// adapts their use cases to the single ports.Extractor seam. That is the
// correct DDD placement — the extract application layer stays free of those
// contexts and depends only on the port; the composition is confined to this
// adapter. A future out-of-process implementation (e.g.
// adapters/extractor/grpc) can sit alongside this package and satisfy the
// same ports.Extractor interface without touching the application layer.
package local
