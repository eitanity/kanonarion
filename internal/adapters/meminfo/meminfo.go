// Package meminfo reads how much memory the host can hand to new work.
//
// It exists so a worker pool whose workers each hold multiple GB can size
// itself against a real budget rather than against the CPU count alone. The
// reading is deliberately a best-effort one: a host that cannot answer returns
// an error, and every caller is required to treat that as "unknown" and fall
// back to its CPU-derived cap. Refusing to run because the memory could not be
// measured would turn a diagnostic gap into an outage.
package meminfo

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procMeminfo is the kernel's memory summary on Linux. It is a field rather
// than a hard-coded path so tests can point the reader at a fixture and pin
// the parsing against real /proc/meminfo text.
const procMeminfo = "/proc/meminfo"

// memAvailableKey is the /proc/meminfo line the reader wants: the kernel's own
// estimate of how much memory is available for new allocations without
// swapping. It is preferred over MemFree, which excludes reclaimable page cache
// and so understates the budget by however much of the host is caching files —
// on a machine that has just run a large build, most of it.
const memAvailableKey = "MemAvailable:"

// ErrUnavailable reports that no memory reading could be taken. It never means
// the host has no memory; it means the question was not answered, so the caller
// must fall back rather than conclude a budget of zero.
var ErrUnavailable = errors.New("available memory could not be read")

// Reader reports the host's available memory by reading the kernel's own
// summary. It satisfies the vuln ports.HostMemory port.
type Reader struct {
	// path is the file to read. Empty means the host's real /proc/meminfo.
	path string
}

// New returns a Reader over the host's /proc/meminfo.
func New() *Reader { return &Reader{} }

// NewFromFile returns a Reader over an explicit meminfo-format file. It exists
// for tests: the host's own /proc/meminfo is not a fixture a test can vary.
func NewFromFile(path string) *Reader { return &Reader{path: path} }

// AvailableBytes returns the host's MemAvailable in bytes.
//
// Every failure — the file being absent (any non-Linux host), unreadable, or
// carrying no MemAvailable line — is reported as ErrUnavailable. The
// distinction between "this OS has no /proc" and "this /proc is malformed"
// matters to nobody at the call site: both mean the cap must come from the CPU
// count instead, and both are logged with the underlying cause attached.
func (r *Reader) AvailableBytes() (uint64, error) {
	path := r.path
	if path == "" {
		path = procMeminfo
	}

	f, err := os.Open(path) // #nosec G304 -- path is a fixed kernel path, or a test fixture.
	if err != nil {
		return 0, fmt.Errorf("%w: opening %s: %w", ErrUnavailable, path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, memAvailableKey) {
			continue
		}
		// The line reads "MemAvailable:   12345678 kB" — a decimal count in the
		// unit the third field names. Only kB is emitted by any kernel that has
		// this line, so an unrecognised unit is treated as unreadable rather than
		// silently assumed: a wrong scale would produce a confident, wrong budget.
		fields := strings.Fields(strings.TrimPrefix(line, memAvailableKey))
		if len(fields) < 2 || !strings.EqualFold(fields[1], "kB") {
			return 0, fmt.Errorf("%w: malformed %s line in %s: %q", ErrUnavailable, memAvailableKey, path, line)
		}
		kb, perr := strconv.ParseUint(fields[0], 10, 64)
		if perr != nil {
			return 0, fmt.Errorf("%w: parsing %s in %s: %w", ErrUnavailable, memAvailableKey, path, perr)
		}
		return kb * 1024, nil
	}
	if serr := scanner.Err(); serr != nil {
		return 0, fmt.Errorf("%w: reading %s: %w", ErrUnavailable, path, serr)
	}
	return 0, fmt.Errorf("%w: no %s line in %s", ErrUnavailable, memAvailableKey, path)
}
