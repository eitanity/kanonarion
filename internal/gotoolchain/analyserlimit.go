package gotoolchain

import (
	"go/version"
	"regexp"
)

// AnalyserLimit is a load refused because the source is newer than the Go the
// analysing binary was compiled with. go/types and go/parser are linked into the
// binary, so the go on PATH cannot lift it; only a newer build of the binary can.
type AnalyserLimit struct {
	// Required is the Go the source asks for, as the refusal spells it ("go1.27").
	Required string
	// Built is the Go the analysing binary was compiled with ("go1.26").
	Built string
}

// newerSourceRefusal is go/types refusing a package whose go version is newer
// than its own. Both halves are required so prose quoting one cannot match.
var newerSourceRefusal = regexp.MustCompile(
	`package requires newer Go version (go[0-9][^ )]*) \(application built with (go[0-9][^ )]*)\)`)

// newerGoListWarning is go/packages' account of the same gap for a package
// with no go version of its own, such as the standard library: it is attached
// only to a package that failed, so its errors cannot be trusted as the module's.
var newerGoListWarning = regexp.MustCompile(
	`This application uses version (go[0-9][^ ]*) of the source-processing packages but runs version (go[0-9][^ ]*) of 'go list'`)

// ownStatement is Statement's own spelling, so a parent reading a child's
// stderr, which carries the statement rather than the loader's words, reads it.
var ownStatement = regexp.MustCompile(
	`this kanonarion cannot read this code: it was built with (go[0-9][^ ]*) and the code requires (go[0-9][^ .]*(?:\.[0-9]+)*)\.`)

// ReadNewerSourceRefusal reads go/types' refusal alone, the highest requirement
// winning: a tool satisfying the largest one satisfies every package refused.
func ReadNewerSourceRefusal(detail string) (AnalyserLimit, bool) {
	return readLimit(detail, newerSourceRefusal, 1, 2, AnalyserLimit{}, false)
}

// ReadAnalyserLimit reads either account of the gap out of a load failure.
func ReadAnalyserLimit(detail string) (AnalyserLimit, bool) {
	l, ok := ReadNewerSourceRefusal(detail)
	// The warning states the binary's Go first and the go command's second.
	l, ok = readLimit(detail, newerGoListWarning, 2, 1, l, ok)
	return readLimit(detail, ownStatement, 2, 1, l, ok)
}

func readLimit(detail string, re *regexp.Regexp, req, built int, l AnalyserLimit, ok bool) (AnalyserLimit, bool) {
	for _, m := range re.FindAllStringSubmatch(detail, -1) {
		if !ok || version.Compare(m[req], l.Required) > 0 {
			l, ok = AnalyserLimit{Required: m[req], Built: m[built]}, true
		}
	}
	return l, ok
}

// ClearedBy reports whether a binary built with goVersion can read the code.
func (l AnalyserLimit) ClearedBy(goVersion string) bool {
	return version.Compare(goVersion, l.Required) >= 0
}

// Clause states the gap as part of a sentence about the module.
func (l AnalyserLimit) Clause() string {
	return "the kanonarion that ran was built with " + l.Built + " and the code requires " + l.Required
}

// Statement says what the gap is, so no reader looks for a fault in the source.
func (l AnalyserLimit) Statement() string {
	return "this kanonarion cannot read this code: it was built with " + l.Built +
		" and the code requires " + l.Required + ". It type-checks source with the Go compiled into " +
		"the binary, so the go on PATH and GOTOOLCHAIN cannot change this; the source was not judged."
}

// AnalyserLimitError refuses an analysis whose answer would rest on source the
// binary could not read.
type AnalyserLimitError struct{ Limit AnalyserLimit }

func (e *AnalyserLimitError) Error() string { return e.Limit.Statement() + " " + e.Limit.Remedy() }

// Remedy names what lifts the gap: a binary built with a new enough Go.
func (l AnalyserLimit) Remedy() string {
	return "Use a kanonarion built with " + l.Required + " or newer: a newer release, or " +
		"`go install github.com/eitanity/kanonarion@latest` run with " + l.Required + " or newer."
}
