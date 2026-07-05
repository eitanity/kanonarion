// Package govulncheck implements ports.VulnerabilityScanner by driving the
// external govulncheck binary.
//
// Preflight resolves govulncheck on PATH so a walk scan can fail fast with an
// actionable install message before any expensive setup. Scan runs govulncheck
// (source or binary mode) against a pinned file:// database snapshot and a
// pre-populated GOMODCACHE, then parses its JSON stream into a
// domain.VulnerabilityRecord. No scanned module code is executed by this
// package itself; govulncheck performs its own analysis in a child process.
package govulncheck
