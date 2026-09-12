package govulncheck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Scanner runs the govulncheck binary, resolved from PATH.
type Scanner struct {
	pipelineVersion string
	vulnStore       ports.VulnerabilityStore
	logger          *slog.Logger
}

// New returns a new Scanner.
func New(pipelineVersion string, vulnStore ports.VulnerabilityStore) *Scanner {
	return &Scanner{
		pipelineVersion: pipelineVersion,
		vulnStore:       vulnStore,
		logger:          slog.Default(),
	}
}

// WithLogger returns a copy of the Scanner using the given logger.
func (s *Scanner) WithLogger(logger *slog.Logger) *Scanner {
	copy := *s
	copy.logger = logger
	return &copy
}

// ErrGovulncheckNotFound indicates the govulncheck binary is not resolvable on
// PATH. Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest
var ErrGovulncheckNotFound = errors.New(
	"govulncheck not found in PATH (install with: go install golang.org/x/vuln/cmd/govulncheck@latest)")

// lookupGovulncheck resolves the govulncheck binary on PATH, returning an
// error that wraps ErrGovulncheckNotFound when it is absent.
func lookupGovulncheck() (string, error) {
	bin, err := exec.LookPath("govulncheck")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGovulncheckNotFound, err)
	}
	return bin, nil
}

// resolvedTool is the scanner this host offers: where it is, and which Go
// release compiled it.
//
// The second half is not decoration. govulncheck type-checks the project in
// process, so its BUILD version decides which projects can be scanned at all —
// and when one cannot be, that version is the only thing that explains why. A
// presence check alone left a current project reporting nine lines of type
// errors about its own files.
type resolvedTool struct {
	bin string
	// builtWith is the Go release the binary was compiled by, in "go1.26.5" form,
	// or "" when it could not be read. It is never a gate: a probe that cannot run
	// must not stop a scan that would have worked.
	builtWith string
}

// resolveGovulncheck resolves the binary and asks what built it.
func resolveGovulncheck(ctx context.Context) (resolvedTool, error) {
	bin, err := lookupGovulncheck()
	if err != nil {
		return resolvedTool{}, err
	}
	return resolvedTool{bin: bin, builtWith: builtWithGo(ctx, bin)}, nil
}

// Preflight implements ports.VulnerabilityScanner: it verifies govulncheck is
// resolvable on PATH so a walk scan can fail fast with an actionable error
// before any expensive snapshot fetch or module scanning.
func (s *Scanner) Preflight(_ context.Context) error {
	_, err := lookupGovulncheck()
	return err
}

func (s *Scanner) logMem(ctx context.Context, phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.logger.DebugContext(ctx, "vuln_scan_memory_telemetry",
		slog.String("phase", phase),
		slog.Uint64("alloc_mb", m.Alloc/1024/1024),
		slog.Uint64("total_alloc_mb", m.TotalAlloc/1024/1024),
		slog.Uint64("sys_mb", m.Sys/1024/1024),
		slog.Uint64("heap_alloc_mb", m.HeapAlloc/1024/1024),
		slog.Uint64("heap_objects", m.HeapObjects),
		slog.Int("num_gc", int(m.NumGC)),
	)
}

// ScannerMetadata returns identity and version information.
func (s *Scanner) ScannerMetadata() ports.ScannerMetadata {
	return ports.ScannerMetadata{
		Name:    "govulncheck",
		Version: "v1.3.0",
	}
}

// Ensure Scanner implements ports.VulnerabilityScanner.
var _ ports.VulnerabilityScanner = (*Scanner)(nil)
