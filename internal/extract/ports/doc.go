// Package ports defines the interfaces the extract application layer requires
// from the outside world.
//
// The driven ports are:
//
// - ExtractionStore — persistence for the ExtractionRun aggregate.
// - Extractor — runs a single named stage for one module. This is the
// key boundary: it lets the application coordinate the four extraction
// stages without importing the callgraph/example/iface/license contexts;
// that cross-context composition is confined to the adapter.
// - StageRegistry — the set of known stages and their canonical order.
//
// The extract context reuses Clock from fetch/ports (injected in the
// application Config); it is not re-declared here.
package ports
