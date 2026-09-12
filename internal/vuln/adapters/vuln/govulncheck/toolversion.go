package govulncheck

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// builtWithGo reads the Go release a Go binary was compiled by, out of the build
// information the linker stamps into it — the same stamp `go version -m <bin>`
// prints, read here directly rather than through a child.
//
// It is asked at resolution time, beside the presence check, because that
// version — not the host toolchain and not any environment variable — decides
// which projects the tool can analyse at all. govulncheck type-checks the
// project's source in-process with the go/types compiled into it, so a binary
// built with go1.26 cannot parse go1.27 source however new the go on PATH is.
//
// Read from the file rather than by running the go command for two reasons: a
// scan's Go children are pinned offline and to one toolchain, and a probe that
// joined them would be one more child to keep pinned; and the answer is wanted
// even where no go command can be run at all. An unreadable answer is "": the
// version explains a failure, it never gates a scan.
func builtWithGo(_ context.Context, bin string) string {
	info, err := buildinfo.ReadFile(bin)
	if err != nil || info == nil {
		return ""
	}
	return strings.TrimSpace(info.GoVersion)
}

// tooNewForScanner matches the go/types refusal govulncheck reports when the
// source it is type-checking asks for a newer language version than the release
// that compiled it. Both halves are required so a module quoting the phrase in
// its own prose cannot match, on the same terms goenv.IsToolchainTooOld states.
var tooNewForScanner = regexp.MustCompile(
	`package requires newer Go version (go[0-9][^ )]*) \(application built with (go[0-9][^ )]*)\)`)

// scannerTooOld reads the two versions out of a govulncheck package-load
// failure: the one the project requires and the one the tool was built with.
//
// The highest requirement wins, for the reason goenv's own reader gives: one
// load can refuse for several packages at once, and a tool satisfying the
// largest requirement satisfies all of them.
func scannerTooOld(detail string) (required, built string, ok bool) {
	for _, m := range tooNewForScanner.FindAllStringSubmatch(detail, -1) {
		if required == "" || goenv.HigherGoVersion(m[1], required) {
			required, built, ok = m[1], m[2], true
		}
	}
	return required, built, ok
}

// scannerTooOldRefusal is what an operator is shown instead of nine lines of
// type errors about their own files.
//
// The type errors are true and they are not the finding: the project is fine and
// the tool cannot read it. Naming the tool's build version, the version the
// project requires and the command that rebuilds it is the whole difference
// between "your project is broken" and "run this".
//
// GOTOOLCHAIN is named as NOT the remedy because it is the first thing an
// operator reaches for and it does not work — measured with and without it, the
// failure is identical. The type checker is inside the binary; only rebuilding
// the binary changes it.
func scannerTooOldRefusal(bin, built, required string) string {
	if built == "" {
		built = "an older release"
	}
	gobin := filepath.Dir(bin)
	remedy := fmt.Sprintf("GOTOOLCHAIN=%s GOBIN=%s go install golang.org/x/vuln/cmd/govulncheck@latest",
		rebuildToolchain(required), gobin)
	return fmt.Sprintf(
		"govulncheck cannot read this project's source: %s was built with %s and the project requires %s. "+
			"govulncheck type-checks the source with the go/types compiled into it, so the go on PATH and "+
			"GOTOOLCHAIN cannot change this — only rebuilding the tool can. Rebuild it with: %s",
		bin, built, required, remedy)
}

// rebuildToolchain names a toolchain that satisfies required and that the go
// command will accept.
//
// A refusal names a LANGUAGE version ("go1.27"), which is not a toolchain name,
// so it cannot be pasted into GOTOOLCHAIN as it stands. A release already
// unpacked on this host is preferred, because that is the one the rebuild can
// use with nothing downloaded; failing that, the first release of the required
// line is named and the go command fetches it.
func rebuildToolchain(required string) string {
	if found := goenv.OnDiskToolchainsAtLeast(required); len(found) > 0 {
		return found[0].Name
	}
	if strings.Count(required, ".") == 1 {
		return required + ".0"
	}
	return required
}
