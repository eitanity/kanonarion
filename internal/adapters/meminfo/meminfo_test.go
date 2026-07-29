package meminfo_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/meminfo"
)

// writeMeminfo writes body to a temp file and returns its path.
func writeMeminfo(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meminfo")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

// realMeminfo is a verbatim excerpt of a Linux /proc/meminfo, so the parser is
// pinned against the real format rather than against a shape invented here.
const realMeminfo = `MemTotal:       16116984 kB
MemFree:          224816 kB
MemAvailable:    8342184 kB
Buffers:          188128 kB
Cached:          7719340 kB
`

func TestAvailableBytes_ParsesMemAvailable(t *testing.T) {
	r := meminfo.NewFromFile(writeMeminfo(t, realMeminfo))

	got, err := r.AvailableBytes()
	if err != nil {
		t.Fatalf("AvailableBytes() error = %v, want nil", err)
	}
	const want = 8342184 * 1024
	if got != want {
		t.Fatalf("AvailableBytes() = %d, want %d (MemAvailable is in kB, not bytes)", got, want)
	}
}

// TestAvailableBytes_MissingFileIsUnavailable covers every non-Linux host: the
// answer is "unknown", reported as ErrUnavailable, never a budget of zero.
func TestAvailableBytes_MissingFileIsUnavailable(t *testing.T) {
	r := meminfo.NewFromFile(filepath.Join(t.TempDir(), "absent"))

	got, err := r.AvailableBytes()
	if !errors.Is(err, meminfo.ErrUnavailable) {
		t.Fatalf("AvailableBytes() error = %v, want ErrUnavailable", err)
	}
	if got != 0 {
		t.Fatalf("AvailableBytes() = %d on failure, want 0 alongside the error", got)
	}
}

// TestAvailableBytes_MalformedIsUnavailable proves a wrong scale is never
// guessed at. A unit the parser does not recognise would otherwise produce a
// confident budget that is off by a factor of 1024.
func TestAvailableBytes_MalformedIsUnavailable(t *testing.T) {
	for name, body := range map[string]string{
		"no MemAvailable line": "MemTotal:       16116984 kB\nMemFree: 224816 kB\n",
		"unrecognised unit":    "MemAvailable:    8342184 MB\n",
		"missing unit":         "MemAvailable:    8342184\n",
		"non-numeric value":    "MemAvailable:    lots kB\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := meminfo.NewFromFile(writeMeminfo(t, body))
			if _, err := r.AvailableBytes(); !errors.Is(err, meminfo.ErrUnavailable) {
				t.Fatalf("AvailableBytes() error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// TestAvailableBytes_HostReading exercises New() against the real host. On
// Linux it must produce a non-zero reading; elsewhere it must degrade to
// ErrUnavailable rather than panic or return a fabricated number.
func TestAvailableBytes_HostReading(t *testing.T) {
	got, err := meminfo.New().AvailableBytes()
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Skipf("host has a readable /proc/meminfo on %s; nothing to assert", runtime.GOOS)
		}
		if !errors.Is(err, meminfo.ErrUnavailable) {
			t.Fatalf("AvailableBytes() on %s error = %v, want ErrUnavailable", runtime.GOOS, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("AvailableBytes() on linux error = %v, want a reading", err)
	}
	if got == 0 {
		t.Fatal("AvailableBytes() on linux = 0; a live host always has some available memory")
	}
}
