// Package domain holds the standard-library chain-of-custody value objects.
//
// The Go standard library ships with the toolchain rather than through the
// module proxy, so it can never carry a proxy module's chain of custody (VCS
// origin → proxy download → h1 dirhash cross-verified against sumdb and the
// local go.sum). This package models the equivalent, necessarily
// different-anchored chain kanonarion establishes for it:
//
//   - the canonical source tarball go{VERSION}.src.tar.gz acquired from
//     go.dev/dl;
//   - its SHA-256 matched against Go's published release manifest;
//   - the go.googlesource.com/go tag → commit VCS anchor;
//   - the SHA-256/384/512 digests over the tarball bytes; and
//   - the BSD-3-Clause licence extracted from the tarball's LICENSE file.
//
// The integrity anchor here (a published checksum plus a source-repo tag) is
// deliberately weaker than a module's sumdb transparency-log entry, and it is
// recorded as such: VerificationStatus values are distinct from the fetch
// stage's sumdb statuses so the two are never presented as equivalent.
package domain
