// Package osv implements ports.VulnerabilityDatabase against the Go
// vulnerability database at vuln.go.dev.
//
// It pins a DatabaseSnapshot by downloading the bulk /vulndb.zip endpoint in a
// single request, validates that the zip carries the govulncheck file:// v1
// layout (index/db.json, index/modules.json plus per-ID JSON), and persists the
// snapshot body through the VulnerabilityStore for reproducible offline
// re-scans so scans run against a fixed, content-addressed database rather than
// the live network.
package osv
