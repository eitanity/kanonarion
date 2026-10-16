package gotoolchain

import "strings"

// IgnoredName reports whether the go tool ignores a file or directory of this
// name when it matches packages: `go help packages` names every name beginning
// with "_" or ".".
func IgnoredName(name string) bool {
	return strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")
}

// IgnoredDir reports whether the go tool leaves a directory of this name, and
// everything under it, out of a "./..." match: an IgnoredName, or "testdata".
// "vendor" is not included; each walker states its own rule for vendored code.
func IgnoredDir(name string) bool {
	return name == "testdata" || IgnoredName(name)
}

// IgnoredPath reports whether any element of a slash-separated relative path is
// an IgnoredDir, so the go tool never reads what lies under it. "." and empty
// elements name no directory and are skipped.
func IgnoredPath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if seg != "." && seg != "" && IgnoredDir(seg) {
			return true
		}
	}
	return false
}
