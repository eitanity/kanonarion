package kanonarion

import (
	callgraphports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	exampleports "code.eitanity.com/kanonarion/internal/example/ports"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	ifaceports "code.eitanity.com/kanonarion/internal/iface/ports"
	licenseports "code.eitanity.com/kanonarion/internal/license/ports"
)

// Store capabilities. Beyond its port, a store in a Storage value may
// implement these interfaces, and kanonarion checks for each at the point it
// needs it. FactRecordComposer is required: Storage.Validate refuses a Facts
// store without it. Every other one is optional, and without it the read it
// serves answers as the comment on it says.

// FactRecordComposer is the read every extraction stage and the call-graph
// child take a module's fetch record through: every measurement of the
// coordinate, at any fetch pipeline version, composed into one record.
// Required of Storage.Facts.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
type FactRecordComposer = fetchports.FactRecordComposer

// SupersededArtefactLister names the artefacts of a published coordinate the
// fetch ledger holds only as local-source measurements, so reads of it leave
// them out. Optional on Storage.Facts; without it none are left out.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type SupersededArtefactLister = fetchports.SupersededArtefactLister

// CallGraphCoordinateLister lists analysed coordinates from the store's keys.
// Optional on Storage.CallGraphs; without it the listing composes every
// summary, which answers the same at a higher cost.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphCoordinateLister = callgraphports.CallGraphCoordinateLister

// CallGraphForeignModuleReader names the modules other than the analysed one
// a served record built with bodies. Optional on Storage.CallGraphs; without
// it no answer is qualified by them.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphForeignModuleReader = callgraphports.CallGraphForeignModuleReader

// CallGraphFrontierFinder answers one level of a transitive traversal in one
// read. Optional on Storage.CallGraphs; without it each symbol is read on its
// own, with the same answer.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphFrontierFinder = callgraphports.CallGraphFrontierFinder

// CallGraphRecordLister returns every stored generation of a coordinate.
// Optional on Storage.CallGraphs; without it CallGraphHistory refuses, and a
// reachability answer missing the scan's frame does not name the frames held.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphRecordLister = callgraphports.CallGraphRecordLister

// CallGraphSourceReader reads the record composed from the generations a
// CallGraphComposeRequest names. Optional on Storage.CallGraphs; without it
// the unrestricted record answers, and an analysis does not settle a
// toolchain conflict by the toolchain it ran with.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphSourceReader = callgraphports.CallGraphSourceReader

// CallGraphUnservedReader names the coordinates holding graphs only at a
// superseded pipeline. Optional on Storage.CallGraphs; without it no answer
// names what it could not search.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphUnservedReader = callgraphports.CallGraphUnservedReader

// CallGraphWorktreeRouter reports which working tree answered for a local
// coordinate. Optional on Storage.CallGraphs; without it WorktreeRouting
// reports nothing found.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphWorktreeRouter = callgraphports.CallGraphWorktreeRouter

// CallGraphIdenticalGenerationReader finds a stored generation identical to a
// fresh analysis, so the analysis writes nothing new. Optional on
// Storage.CallGraphs; without it every analysis appends a generation.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphIdenticalGenerationReader = callgraphports.IdenticalGenerationReader

// CallGraphWorktreeGenerationReader reads the generations of a local
// coordinate from one working tree. Optional on Storage.CallGraphs; without it
// a working-tree analysis does not reuse a stored graph.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type CallGraphWorktreeGenerationReader = callgraphports.WorktreeGenerationReader

// InterfaceRecordLister returns every stored generation of a coordinate.
// Optional on Storage.Interfaces; without it InterfaceHistory refuses.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type InterfaceRecordLister = ifaceports.InterfaceRecordLister

// InterfaceGenerationLister lists every stored generation from the store's
// keys. Optional on Storage.Interfaces; without it the listing composes every
// summary.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type InterfaceGenerationLister = ifaceports.InterfaceGenerationLister

// InterfaceIdenticalGenerationReader is CallGraphIdenticalGenerationReader
// for Storage.Interfaces.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type InterfaceIdenticalGenerationReader = ifaceports.IdenticalGenerationReader

// ExampleRecordLister returns every stored generation of a coordinate.
// Optional on Storage.Examples; without it ExampleHistory refuses.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type ExampleRecordLister = exampleports.ExampleRecordLister

// ExamplePipelinesHeldReader names the pipeline versions a coordinate's
// example records are held at. Optional on Storage.Examples; without it
// PipelinesHeld refuses.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type ExamplePipelinesHeldReader = exampleports.PipelinesHeldReader

// ExampleIdenticalGenerationReader is CallGraphIdenticalGenerationReader for
// Storage.Examples.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type ExampleIdenticalGenerationReader = exampleports.IdenticalGenerationReader

// LicenseRecordLister returns every stored generation of a coordinate.
// Optional on Storage.Licenses; without it LicenseHistory refuses.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type LicenseRecordLister = licenseports.LicenceRecordLister

// LicensePipelinesHeldReader names the pipeline versions a coordinate's
// licence records are held at. Optional on Storage.Licenses; without it
// PipelinesHeld refuses.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type LicensePipelinesHeldReader = licenseports.PipelinesHeldReader

// LicenseIdenticalGenerationReader is CallGraphIdenticalGenerationReader for
// Storage.Licenses.
//
// Stability: optional substitution port (implemented by consumers); unstable
// pre-v1.
type LicenseIdenticalGenerationReader = licenseports.IdenticalGenerationReader
