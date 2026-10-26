package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"code.eitanity.com/kanonarion/internal/adapters/goenv"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// listedPackage is the part of a `go list -json` entry the mode decision reads.
type listedPackage struct {
	ImportPath string
	CgoFiles   []string
}

// scanModeFor decides how govulncheck runs in dir. Without a TinyGo frame it is
// source mode and spawns nothing. Under one, a closure that compiles C cannot be
// loaded by the host toolchain, so it is matched at module level instead.
//
// A go list that fails is returned as the scan's failure, never as a mode: a
// closure nobody could list has not been shown to be free of C.
func (s *Scanner) scanModeFor(ctx context.Context, tc *goenv.Toolchains, env []string, dir string) (domain.ScanMode, *scanFailure, error) {
	if !s.tinygo.Declared() {
		return domain.ScanModeSource, nil, nil
	}
	args := append(append([]string{"list"}, s.tinygo.ListArgs()...), "-deps", "-json", "./...")
	var stderr *limitWriter
	out, err := goChildLoop(ctx, tc, env, dir, args, func(cmd *exec.Cmd) ([]byte, string, error) {
		stderr = &limitWriter{limit: stderrLimit}
		cmd.Stderr = stderr
		o, e := cmd.Output()
		return o, stderr.String(), e //nolint:wrapcheck // goChildLoop's caller names the command
	})
	if serr := stoppedScan(ctx, err); serr != nil {
		return "", nil, serr
	}
	if err != nil {
		return "", s.listFailure(err, stderr.String()), nil
	}
	cgo, perr := cgoPackages(out)
	if perr != nil {
		return "", s.listFailure(fmt.Errorf("its output did not parse: %w", perr), ""), nil
	}
	if len(cgo) == 0 {
		s.logger.Info("vuln-scan: the TinyGo closure compiles no C; running govulncheck source mode",
			"tinygo", s.tinygo.Target(), "dir", dir)
		return domain.ScanModeSource, nil, nil
	}
	s.logger.Info("vuln-scan: the TinyGo closure compiles C the host toolchain cannot load; running govulncheck at module level",
		"tinygo", s.tinygo.Target(), "dir", dir,
		"cgo_packages", strings.Join(cgo[:min(3, len(cgo))], ", "), "cgo_package_count", len(cgo))
	return domain.ScanModeModule, nil, nil
}

// cgoPackages is the import paths, in listed order, of the packages in a
// `go list -json` stream that list CgoFiles.
func cgoPackages(out []byte) ([]string, error) {
	var cgo []string
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			return cgo, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decoding go list output: %w", err)
		}
		if len(p.CgoFiles) > 0 {
			cgo = append(cgo, p.ImportPath)
		}
	}
}

// listFailure is a go list that could not settle the mode, recorded as the scan
// failure a load error is, with the frame named because it may be the cause.
func (s *Scanner) listFailure(err error, stderr string) *scanFailure {
	reason := "go list -deps -json ./... failed: " + err.Error()
	if d := strings.TrimSpace(stderr); d != "" {
		reason += "; stderr: " + d
	}
	return &scanFailure{status: domain.StatusScanFailed, errorDetail: reason + s.tinygo.ResolutionClause()}
}

// scanArgs is the govulncheck invocation for mode. Module level takes no
// package pattern, which govulncheck refuses there.
func (s *Scanner) scanArgs(dbArg string, mode domain.ScanMode) []string {
	if mode == domain.ScanModeModule {
		return append([]string{"-json", "-db", dbArg, "-scan", "module"}, s.tinygo.ListArgs()...)
	}
	return s.sourceArgs(dbArg)
}
