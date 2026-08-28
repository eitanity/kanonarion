package domain

import "strings"

// ModuleUnresolved is the module reported for a file under vendor/ that no
// module in vendor/modules.txt owns.
//
// It is stated rather than guessed. A module path is not a segment count —
// github.com/IBM/ibm-cos-sdk-go, golang.org/x/crypto and
// github.com/minio/minio-go/v7 have three, three and four — so any fixed split
// of a vendored path invents a value for most of them, and an invented value is
// plausible enough to be acted on: there is nothing at github.com/IBM to
// upgrade, pin or exempt.
const ModuleUnresolved = "(unresolved)"

// VendoredModuleIndex attributes a file under vendor/ to the module that
// published it, by longest-prefix match over the module paths
// vendor/modules.txt lists.
//
// Longest prefix, not first match: module paths nest, and both
// github.com/minio/minio-go and github.com/minio/minio-go/v7 can be listed at
// once, so a file beneath the v7 directory belongs to v7 and to nothing else.
// It is the same nesting the per-module digest excludes on, read the other way
// round — there, a listed child's files are not the parent's; here, they are
// the child's.
//
// It lives in this context because "which listed module owns this path" is a
// fact about a vendored tree, and there is one answer to it. Every analysis
// that reads a vendored file asks the same question, and two implementations
// of it would be free to disagree about one file — which is how the first
// answer, a fixed two-segment split of the path, survived in two scanners at
// once.
type VendoredModuleIndex struct {
	listed map[string]bool
}

// NewVendoredModuleIndex indexes the module paths vendor/modules.txt lists.
// An empty list is legitimate: a project with no vendored tree has no file to
// attribute, and one whose listing could not be read attributes every vendored
// file to ModuleUnresolved rather than to a guess.
func NewVendoredModuleIndex(modulePaths []string) VendoredModuleIndex {
	listed := make(map[string]bool, len(modulePaths))
	for _, p := range modulePaths {
		if p != "" {
			listed[p] = true
		}
	}
	return VendoredModuleIndex{listed: listed}
}

// Vendored reports whether rel — a slash-separated path relative to the scan
// root — lies under a vendor/ segment and, when it does, the module that owns
// it: the longest listed module path prefixing it, or ModuleUnresolved when no
// listed module does.
//
// Both halves are returned together because a caller that needs the module
// almost always needs to know it is looking at a dependency: a `//go:debug`
// under vendor/ does not take effect in the current build, and the flag that
// records that must come from the same reading of the path as the module does.
func (i VendoredModuleIndex) Vendored(rel string) (vendored bool, modulePath string) {
	rest, ok := underVendor(rel)
	if !ok {
		return false, ""
	}
	parts := strings.Split(rest, "/")
	for n := len(parts); n > 0; n-- {
		if candidate := strings.Join(parts[:n], "/"); i.listed[candidate] {
			return true, candidate
		}
	}
	return true, ModuleUnresolved
}

// Module returns the module a scanned file belongs to. rel is the file's
// slash-separated path relative to the scan root; projectModule is the module
// go.mod declares.
//
// A file outside vendor/ is the project's own. A file under vendor/ resolves as
// Vendored describes.
func (i VendoredModuleIndex) Module(rel, projectModule string) string {
	vendored, modulePath := i.Vendored(rel)
	if !vendored {
		return projectModule
	}
	return modulePath
}

// underVendor returns the portion of a slash path below its first vendor/
// segment, and whether the path lies under one at all.
func underVendor(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for n, p := range parts {
		if p == "vendor" {
			return strings.Join(parts[n+1:], "/"), true
		}
	}
	return "", false
}
