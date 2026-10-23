// Package kanonarion is the public API façade for the kanonarion module.
//
// It is a thin, hand-curated surface: internal packages stay
// internal, and this package re-exports a deliberately small, named subset for
// external consumers — the open-core enterprise build and other downstreams.
// Three (now four, per) consumer relationships are exposed: result
// types received by consumers, query use cases called by consumers,
// substitution ports implemented by consumers, and the driver/serving/identity
// surface.
//
// The write boundary: the driver hands out whole operations — serve one
// coordinate, walk and extract a working tree, analyse a published version as
// `inspect` does, re-scan a stored walk — and the per-module staleness
// resolver. The stage use cases those compose (walk, extract, scan, rescan,
// the batched latest resolver) are never reachable from here, so the CLI and
// a consumer run one composition and the stages stay free to change.
//
// Stability: the entire surface is unstable pre-v1 (v0.x). Minor releases may
// break it until the v1 freeze. Every exported identifier carries a doc comment
// and a Stability line stating its consumer relationship; the relationship
// determines its compatibility semantics (§4): result-type fields may
// grow within a major, use cases may gain methods, but published ports evolve
// only by adding a new optional interface — never by widening an existing one.
package kanonarion
