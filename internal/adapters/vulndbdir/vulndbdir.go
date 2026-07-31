// Package vulndbdir is the shared-kernel adapter for reading an extracted
// govulncheck advisory database directory — the file:// layout a scan is
// pointed at — and reporting how many advisories it holds.
//
// It exists because govulncheck reports "No vulnerabilities found." and exits 0
// against a database that holds nothing. There is no warning and no
// distinguishing signal, so a scan that consulted no advisories is
// indistinguishable from one that consulted every advisory and cleared the
// build. A verdict sealed from that is a confident negative derived from no
// analysis, which is the one thing this tool must never emit.
//
// The directory is the right place to measure. It is the exact bytes handed to
// the scanner: not the archive they were extracted from, not the version string
// the archive asserts about itself, and not the store row that quotes that
// version. Anything upstream of the extraction is a claim about the database;
// the extracted tree is the database.
package vulndbdir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// advisoryDir is the subdirectory of an extracted database holding one JSON
// document per advisory, as the govulncheck file:// layout defines it
// (index/db.json, index/modules.json, ID/<ID>.json).
const advisoryDir = "ID"

// indexFile is the one document under ID/ that is not an advisory: some
// generations of the layout carry an ID/index.json listing the rest. Counting
// it would let a database holding nothing but its own table of contents report
// one advisory, which is precisely the plausible-but-wrong count that makes a
// guard worse than none.
const indexFile = "index.json"

// CountAdvisories reports how many advisory documents the extracted database
// rooted at dir holds.
//
// Zero is a legitimate answer, not an error: a database that holds no
// advisories is readable, well-formed and empty, and the caller — not this
// adapter — owns what to do about that. An error means the directory could not
// be read at all, which is a different fact and must not be reported as
// emptiness.
//
// A missing ID directory counts as zero for the same reason. The fabricated
// empty database that motivated this measurement carries index/db.json and
// index/modules.json and no ID tree whatsoever, and calling that unreadable
// would route the clearest possible case of "no advisories" through the wrong
// arm.
//
// The whole ID subtree is walked rather than only its top level, because the
// layout is defined by a name prefix ("ID/") and a suffix (".json") and has
// never promised to stay flat.
//
// What this can detect and what it cannot: it detects a database that holds no
// advisories at all. It cannot detect a database that was truncated to a
// plausible-looking subset — three advisories still parse, still count, and
// still produce a clean scan. Nothing readable from the directory distinguishes
// a genuinely small database from a large one that lost most of itself, so the
// count is reported rather than judged, and the reader who wants that
// distinction gets it from the count recorded beside the verdict.
func CountAdvisories(dir string) (int, error) {
	root := filepath.Join(dir, advisoryDir)
	count := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".json") || name == indexFile {
			return nil
		}
		count++
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("counting advisories under %s: %w", root, err)
	}
	return count, nil
}
