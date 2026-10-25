package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	cganalyser "github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
	"github.com/eitanity/kanonarion/internal/walk/adapters/buildlist/tinygo"
)

// invokedCmd and invokedArgs are this invocation's command and positionals, so
// a remedy can hand back the command the reader typed with one flag added.
var (
	invokedCmd  *cobra.Command
	invokedArgs []string
)

// buildFrameFlags declare the frame; a TinyGo re-run replaces them, never adds.
var buildFrameFlags = []string{"tinygo", "target", "goos", "goarch"}

// plainWord is an argument a shell reads back unchanged.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9_./@:=,+-]+$`)

func shellWord(s string) string {
	if plainWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// tinyGoRerun is the command this invocation ran, flags as given, with
// --tinygo in place of any frame flag. Root flags such as --store-root are left
// out, as every other printed remedy leaves them.
func tinyGoRerun() string {
	if invokedCmd == nil {
		return "kanonarion" + gotoolchain.TinyGoFlag
	}
	words := []string{invokedCmd.CommandPath()}
	for _, a := range invokedArgs {
		words = append(words, shellWord(a))
	}
	root := invokedCmd.Root()
	invokedCmd.Flags().Visit(func(f *pflag.Flag) {
		if root.PersistentFlags().Lookup(f.Name) != nil || slices.Contains(buildFrameFlags, f.Name) {
			return
		}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			for _, v := range sv.GetSlice() {
				words = append(words, "--"+f.Name, shellWord(v))
			}
			return
		}
		if f.Value.Type() == "bool" {
			if f.Value.String() == "true" {
				words = append(words, "--"+f.Name)
			} else {
				words = append(words, "--"+f.Name+"=false")
			}
			return
		}
		words = append(words, "--"+f.Name, shellWord(f.Value.String()))
	})
	return strings.Join(words, " ") + gotoolchain.TinyGoFlag
}

// tinyGoPackagesIn returns the packages a standard-frame failure could not find
// in std, when TinyGo provides every one of them. One it does not provide keeps
// today's remedy: --tinygo would not find that one either.
func tinyGoPackagesIn(ctx context.Context, detail string) ([]string, bool) {
	if declaredTinyGo.Declared() {
		return nil, false
	}
	if _, limited := gotoolchain.ReadAnalyserLimit(detail); limited {
		return nil, false
	}
	pkgs := gotoolchain.MissingStdPackages(detail)
	if len(pkgs) == 0 {
		return nil, false
	}
	for _, p := range pkgs {
		if !tinygo.Provides(ctx, p) {
			return nil, false
		}
	}
	return pkgs, true
}

// incompleteGraphRemedy is cgdomain.IncompleteGraphRemedy, except that a load
// that failed on packages only TinyGo provides is sent to the TinyGo build.
func incompleteGraphRemedy(ctx context.Context, coord coordinate.ModuleCoordinate, cause cgdomain.FailureCause, detail, dir string) string {
	if pkgs, ok := tinyGoPackagesIn(ctx, detail); ok {
		return gotoolchain.TinyGoPackageRemedy(pkgs, cgdomain.TinyGoReanalysisInstruction(coord, dir))
	}
	return cgdomain.IncompleteGraphRemedy(coord, cause, detail, dir)
}

// withTinyGoRemedy appends the TinyGo remedy to a go list refusal whose missing
// packages TinyGo provides; any other refusal, or one raised by a command that
// takes no --tinygo, is returned as it is.
func withTinyGoRemedy(ctx context.Context, refusal string) string {
	if invokedCmd == nil || invokedCmd.Flags().Lookup("tinygo") == nil {
		return refusal
	}
	pkgs, ok := tinyGoPackagesIn(ctx, refusal)
	if !ok {
		return refusal
	}
	return refusal + "\n" + gotoolchain.TinyGoPackageRemedy(pkgs, tinyGoRerun())
}

// ---- files only TinyGo builds ----

// ignoredRecordMarker opens the go list line naming a package's ignored files.
// No module record can begin with it.
const ignoredRecordMarker = "#ignored\t"

// goListIgnoredFmt adds, for a non-standard package with ignored Go files, one
// marker line: import path, directory, then each file, tab-separated.
// The separators are template literals, so the argument stays one line.
const goListIgnoredFmt = `{{if and (not .Standard) .IgnoredGoFiles}}{{"\n#ignored\t"}}` +
	`{{.ImportPath}}{{"\t"}}{{.Dir}}{{range .IgnoredGoFiles}}{{"\t"}}{{.}}{{end}}{{end}}`

// shownGoListArgs is args as a refusal quotes them, without goListIgnoredFmt:
// the record a reader sees is the one they asked for.
func shownGoListArgs(args []string) string {
	shown := make([]string, len(args))
	for i, a := range args {
		shown[i] = strings.TrimSuffix(a, goListIgnoredFmt)
	}
	return strings.Join(shown, " ")
}

// ignoredGoFiles is one package's Go files the frame left out.
type ignoredGoFiles struct {
	importPath string
	dir        string
	files      []string // base names
}

// splitIgnoredRecords removes the marker lines from go list output and returns
// them parsed beside what is left.
func splitIgnoredRecords(out []byte) ([]byte, []ignoredGoFiles) {
	var kept []string
	var pkgs []ignoredGoFiles
	for line := range strings.SplitSeq(string(out), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), ignoredRecordMarker)
		if !ok {
			kept = append(kept, line)
			continue
		}
		f := strings.Split(rest, "\t")
		if len(f) < 3 {
			continue
		}
		path, _, _ := strings.Cut(f[0], " [")
		pkgs = append(pkgs, ignoredGoFiles{importPath: path, dir: f[1], files: f[2:]})
	}
	return []byte(strings.Join(kept, "\n")), pkgs
}

// reportIgnoredPackages hands a working tree load's ignored files to frameExcludes.
func reportIgnoredPackages(root string, pkgs []cganalyser.IgnoredPackage) {
	out := make([]ignoredGoFiles, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, ignoredGoFiles{importPath: p.ImportPath, dir: p.Dir, files: p.Files})
	}
	frameExcludes.report(root, out)
}

// frameExcludeCommands are the commands whose standard-frame answer states the
// files only TinyGo builds.
var frameExcludeCommands = []string{
	"kanonarion walk", "kanonarion sbom", "kanonarion local", "kanonarion audit", "kanonarion inspect",
}

// frameExcludes collects, for one invocation, the files only TinyGo builds that
// the standard frame left out. A --json document takes them; Run states the
// rest on stderr, once.
var frameExcludes = &frameExcludeCollector{}

type frameExcludeCollector struct {
	mu      sync.Mutex
	enabled bool
	seen    map[string]bool
	files   []string
}

// enable switches collection on for the commands that state it, and never
// under a declared TinyGo frame, which builds these files.
func (c *frameExcludeCollector) enable(cmd *cobra.Command) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = slices.Contains(frameExcludeCommands, cmd.CommandPath())
}

func (c *frameExcludeCollector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled, c.seen, c.files = false, nil, nil
}

// report reads each ignored file's constraint and keeps those only TinyGo
// builds, named relative to root when under it and by import path otherwise.
// A file that cannot be opened is not counted; go list has just read it.
func (c *frameExcludeCollector) report(root string, pkgs []ignoredGoFiles) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || declaredTinyGo.Declared() {
		return
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	for _, p := range pkgs {
		for _, name := range p.files {
			path := filepath.Join(p.dir, name)
			if c.seen[path] || !tinyGoOnlyFile(path) {
				continue
			}
			c.seen[path] = true
			label := p.importPath + "/" + name
			if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
				label = filepath.ToSlash(rel)
			}
			c.files = append(c.files, label)
		}
	}
}

// tinyGoOnlyFile reports whether the file at path builds only under TinyGo.
func tinyGoOnlyFile(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- a file go list or go/packages named in the analysed build
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // read-only
	only, err := gotoolchain.BuildsOnlyUnderTinyGo(f)
	return err == nil && only
}

// frameExcludesJSON is the document's account: the files and the command that
// analyses them.
type frameExcludesJSON struct {
	Files   []string `json:"files"`
	Command string   `json:"command"`
}

// take hands over what no document or statement has carried yet, nil when none.
func (c *frameExcludeCollector) take() *frameExcludesJSON {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.files) == 0 {
		return nil
	}
	files := c.files
	c.files = nil
	sort.Strings(files)
	return &frameExcludesJSON{Files: files, Command: tinyGoRerun()}
}

// maxNamedFiles is how many files the stderr statement names.
const maxNamedFiles = 5

// statement is the stderr line.
func (j *frameExcludesJSON) statement() string {
	named := j.Files
	more := ""
	if len(named) > maxNamedFiles {
		more = fmt.Sprintf(" … and %d more", len(named)-maxNamedFiles)
		named = named[:maxNamedFiles]
	}
	return fmt.Sprintf("notice: %d file(s) built only by TinyGo are not in this frame (%s%s): "+
		"their imports and code are not analysed; analyse the TinyGo build with %s\n",
		len(j.Files), strings.Join(named, ", "), more, j.Command)
}

// flush states on w what no document took.
func (c *frameExcludeCollector) flush(w io.Writer) {
	if j := c.take(); j != nil {
		_, _ = io.WriteString(w, j.statement()) //nolint:errcheck // best-effort stderr at exit, as storeSetAside.flush
	}
}

// rawJSON is take for a document assembled from raw messages; nil when none.
func (c *frameExcludeCollector) rawJSON() (json.RawMessage, error) {
	j := c.take()
	if j == nil {
		return nil, nil
	}
	b, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("marshalling frame_excludes: %w", err)
	}
	return b, nil
}
