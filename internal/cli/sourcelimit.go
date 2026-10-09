package cli

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// analyserLimitJSON is a record's analyser limit under --json: the files this
// kanonarion's parser refused, the Go the code requires and the Go that ran.
// Remedy is present only while the limit still binds this binary.
type analyserLimitJSON struct {
	Required  string   `json:"required"`
	Built     string   `json:"built"`
	Files     []string `json:"files"`
	Statement string   `json:"statement"`
	Remedy    string   `json:"remedy,omitempty"`
}

func toAnalyserLimitJSON(u *gotoolchain.UnreadSource) *analyserLimitJSON {
	if u == nil {
		return nil
	}
	out := &analyserLimitJSON{
		Required: u.Limit.Required, Built: u.Limit.Built,
		Files: append([]string{}, u.Files...), Statement: u.Summary(),
	}
	if u.Limit.Binds() {
		out.Remedy = u.Limit.Remedy()
	}
	return out
}

// writeAnalyserLimit states a record's analyser limit and what lifts it: a
// newer kanonarion, or re-running this one when it already reads the code.
func writeAnalyserLimit(w io.Writer, indent string, u *gotoolchain.UnreadSource, rerun string) error {
	if u == nil {
		return nil
	}
	if _, err := fmt.Fprintf(w, "%s%s.\n", indent, u.Summary()); err != nil {
		return fmt.Errorf("writing analyser limit: %w", err)
	}
	return writeAnalyserLimitRemedy(w, indent, u, rerun)
}

// writeAnalyserLimitRemedy is the remedy line alone, for an output whose
// failure line already states the limit.
func writeAnalyserLimitRemedy(w io.Writer, indent string, u *gotoolchain.UnreadSource, rerun string) error {
	if u == nil {
		return nil
	}
	next := u.Limit.Remedy()
	if !u.Limit.Binds() {
		next = "This kanonarion was built with " + gotoolchain.AnalysingGo() + " and reads it: run " + rerun
	}
	if _, err := fmt.Fprintf(w, "%s%s\n", indent, next); err != nil {
		return fmt.Errorf("writing analyser limit remedy: %w", err)
	}
	return nil
}

// unreadIn counts the files of the package at importPath the record did not
// read, so a package listed empty is not read as one with no API.
func unreadIn(u *gotoolchain.UnreadSource, modulePath, importPath string) int {
	if u == nil {
		return 0
	}
	dir := "."
	if importPath != modulePath {
		dir = strings.TrimPrefix(importPath, modulePath+"/")
	}
	n := 0
	for _, f := range u.Files {
		if path.Dir(f) == dir {
			n++
		}
	}
	return n
}

// unreadSuffix renders unreadIn for a package line.
func unreadSuffix(u *gotoolchain.UnreadSource, modulePath, importPath string) string {
	n := unreadIn(u, modulePath, importPath)
	switch n {
	case 0:
		return ""
	case 1:
		return " (1 file not analysed)"
	default:
		return fmt.Sprintf(" (%d files not analysed)", n)
	}
}

// localAnalysisErr wraps a local analysis failure, and refuses at 20 when it
// is the analyser limit: the remedy is a newer build of this binary, not an
// invocation of it.
func localAnalysisErr(what string, err error) error {
	var lim *gotoolchain.AnalyserLimitError
	if errors.As(err, &lim) {
		return &exitError{code: ExitConfig, msg: what + ": " + lim.Error()}
	}
	return fmt.Errorf("%s: %w", what, err)
}

// analyserLimitExit is the extracting commands' refusal for a record that met
// a limit binding this binary: 20, since the remedy is another build of it.
// The output above it already printed the remedy, as callgraph's does.
func analyserLimitExit(subject string, u *gotoolchain.UnreadSource) error {
	if u == nil || !u.Limit.Binds() {
		return nil
	}
	return &exitError{code: ExitConfig, msg: subject + " — " + u.Limit.Statement()}
}
