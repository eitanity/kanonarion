// Package application contains the extraction orchestration use case.
//
// It walks every module in a walk, runs the requested stages in canonical
// order through ports.Extractor (honouring inter-stage dependencies, e.g.
// callgraph implies interface), records each StageResult, rolls up the
// overall status, hashes, and persists the ExtractionRun.
//
// All timestamps come from an injected fetch/ports.Clock — the application
// layer never calls time.Now, so runs are reproducible under a
// fixed clock. The layer depends only on extract/ports and pure domain
// logic; it performs no stage work itself.
package application
