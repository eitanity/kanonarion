package godoc

import (
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"path"
	"runtime"
	"sort"

	"github.com/eitanity/kanonarion/internal/iface/domain"
)

// hostFrame is the build configuration extraction measures in when no other is
// declared: the one this process is running on. It is a placeholder for a frame
// the caller chooses, not a claim that the host platform is the interesting one
// — but it is a real, buildable configuration, which "every platform at once"
// never was.
func hostFrame() domain.BuildFrame {
	return domain.BuildFrame{
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		CgoEnabled: true,
	}
}

// buildContext returns the go/build context that decides which files in a
// package directory belong to frame.
//
// The evaluation is go/build's own. Build constraints are the go command's
// question — which files does this build contain — and a hand-rolled parser of
// //go:build lines and _GOOS_GOARCH filename suffixes would be a second,
// divergent answer to a question the toolchain already answers exactly.
//
// build.Default supplies only the facts that come from the compiling toolchain
// and cannot be derived from the frame: the release tags (go1.1 … go1.N), the
// tool tags, and the compiler name. Everything a caller's environment could
// otherwise smuggle in is overridden: GOOS and GOARCH come from the frame, and
// BuildTags is cleared so a GOFLAGS setting on the extracting host cannot change
// what a stored public API contains.
func buildContext(frame domain.BuildFrame, fsys fs.FS) *build.Context {
	ctxt := build.Default
	ctxt.GOOS = frame.GOOS
	ctxt.GOARCH = frame.GOARCH
	ctxt.CgoEnabled = frame.CgoEnabled
	ctxt.BuildTags = nil
	ctxt.UseAllFiles = false
	ctxt.Dir = ""
	ctxt.GOPATH = ""
	ctxt.GOROOT = ""

	// The source is a module zip, not a directory on disk, so the context reads
	// through the fs.FS. Only JoinPath and OpenFile are reached by MatchFile;
	// the rest of the hooks are left at their defaults deliberately, so a future
	// call that needs them fails loudly against the real filesystem rather than
	// quietly answering about the wrong tree.
	ctxt.JoinPath = path.Join
	ctxt.OpenFile = func(name string) (io.ReadCloser, error) {
		f, err := fsys.Open(name)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", name, err)
		}
		return f, nil
	}
	return &ctxt
}

// inFrame reports whether the file at dir/name is part of a build of frame.
//
// A file that cannot be read or whose build constraint cannot be evaluated is
// reported as excluded together with the reason, never silently kept or silently
// dropped: the caller records that reason as a parse failure so the record
// states which files it could not decide about.
func inFrame(ctxt *build.Context, dir, name string) (bool, error) {
	match, err := ctxt.MatchFile(dir, name)
	if err != nil {
		return false, fmt.Errorf("evaluating build constraints for %s: %w", path.Join(dir, name), err)
	}
	return match, nil
}

// sortedDirs returns dirs in a fixed order. The record is sorted by import path
// before it is hashed, so the order packages are parsed in does not reach the
// stored bytes today; it does reach progress output and any future per-package
// short circuit, and a set iterated in map order is the same hazard this change
// exists to remove.
func sortedDirs(dirs []string) []string {
	sort.Strings(dirs)
	return dirs
}
