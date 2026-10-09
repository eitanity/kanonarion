package gotoolchain

import (
	"go/version"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
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

// analysingGo is the Go this binary was compiled with: its go/parser and
// go/types are the ones that read the source.
var analysingGo = runtime.Version()

// AnalysingGo returns the Go this binary was compiled with.
func AnalysingGo() string { return analysingGo }

// SetAnalysingGo replaces the Go this binary reports itself built with and
// returns the restore. It is a test seam: a suite runs on one toolchain and
// must still exercise a limit that binds and one that does not.
func SetAnalysingGo(v string) (restore func()) {
	prev := analysingGo
	analysingGo = v
	return func() { analysingGo = prev }
}

// Binds reports whether the limit still holds for this binary. One an older
// build recorded and this binary clears is lifted by measuring again.
func (l AnalyserLimit) Binds() bool { return !l.ClearedBy(analysingGo) }

// MayPredateThisGo reports whether a record measured under v could have met a
// limit this binary clears: v is unrecorded, or older than this binary's Go.
func MayPredateThisGo(v Version) bool {
	if !version.IsValid(analysingGo) {
		return false
	}
	return !v.Recorded() || version.Compare(string(v), analysingGo) < 0
}

// GoDirective reads the go directive ("1.27.2") out of a go.mod, or "" when it
// has none or cannot be parsed, which claims no limit.
func GoDirective(goMod []byte) string {
	f, err := modfile.ParseLax("go.mod", goMod, nil)
	if err != nil || f.Go == nil {
		return ""
	}
	return f.Go.Version
}

// LimitForDirective is the limit a module's go directive ("1.27.2") puts on
// this binary, if the directive is newer than the Go it was built with. Only
// then can a refusal by the parser be this binary's rather than the source's.
// A development build names no comparable release, so it claims no limit.
func LimitForDirective(directive string) (AnalyserLimit, bool) {
	return limitOver(directive, analysingGo)
}

// DirectiveNewerThan reports whether a binary built with goVersion is too old
// for a module's go directive.
func DirectiveNewerThan(directive, goVersion string) bool {
	_, ok := limitOver(directive, goVersion)
	return ok
}

func limitOver(directive, built string) (AnalyserLimit, bool) {
	if directive == "" || !version.IsValid(built) {
		return AnalyserLimit{}, false
	}
	required := "go" + strings.TrimPrefix(directive, "go")
	if !version.IsValid(required) || version.Compare(required, built) <= 0 {
		return AnalyserLimit{}, false
	}
	return AnalyserLimit{Required: required, Built: built}, true
}

// UnreadSource is the source files a binary's parser refused under such a
// limit. They were not analysed, so nothing in them is a finding either way.
type UnreadSource struct {
	Limit AnalyserLimit
	// Files are module-relative and sorted.
	Files []string
}

// NewUnreadSource returns the files under the limit, sorted, or nil when none
// were refused, so a record that met no limit carries nothing.
func NewUnreadSource(l AnalyserLimit, files []string) *UnreadSource {
	if len(files) == 0 {
		return nil
	}
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	return &UnreadSource{Limit: l, Files: sorted}
}

// Summary states the files and the gap in one clause.
func (u UnreadSource) Summary() string {
	return "not analysed: " + plural(len(u.Files), "file") + " (" + strings.Join(u.Files, ", ") + "): " + u.Limit.Clause()
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
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
		" and the code requires " + l.Required + ". It reads source with the Go compiled into " +
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
