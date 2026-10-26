// Package gosumfile implements ports.SumDBClient against a project's local
// go.sum file instead of the network checksum database (sum.golang.org).
//
// It is the verifier used in --from-modcache mode: the build has already
// verified every module against go.sum, so the recorded h1 entries are the
// source of truth and no transparency-log query is needed. A module absent
// from go.sum yields Available=false, which the fetch pipeline treats as a
// hard failure in this mode.
package gosumfile

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"code.eitanity.com/kanonarion/internal/coordinate"

	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/ports"
)

// Client implements ports.SumDBClient backed by a parsed go.sum file.
type Client struct {
	// zip maps "path@version" to the module zip h1 hash.
	zip map[string]domain2.ModuleHash
	// gomod maps "path@version" to the go.mod h1 hash.
	gomod map[string]domain2.ModuleHash
	// badZip and badGoMod map "path@version" to the error for a zip or
	// go.mod line of that module whose hash does not parse, naming the line.
	badZip, badGoMod map[string]error
	// logger states a bad line that a good line of the same kind outranks.
	logger *slog.Logger
	// path is the go.sum path, retained for error messages.
	path string
}

var _ ports.SumDBClient = (*Client)(nil)

// New parses the go.sum file at path and returns a Client; logger receives
// the bad lines a lookup tolerates. A missing go.sum is
// not an error here — it parses to an empty client, and every Lookup then
// reports Available=false so the caller's hard-fail policy fires with a clear
// "not in go.sum" reason rather than a load error.
func New(path string, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	c := &Client{
		zip:      make(map[string]domain2.ModuleHash),
		gomod:    make(map[string]domain2.ModuleHash),
		badZip:   make(map[string]error),
		badGoMod: make(map[string]error),
		path:     path,
		logger:   logger,
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator-supplied project go.sum
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading go.sum %q: %w", path, err)
	}
	if err := c.parse(string(data)); err != nil {
		return nil, fmt.Errorf("parsing go.sum %q: %w", path, err)
	}
	return c, nil
}

// parse populates the hash maps from go.sum content. Each line has the shape
//
//	<module> <version> h1:<base64>=
//	<module> <version>/go.mod h1:<base64>=
//
// A line without exactly three fields is skipped: it is a blank line or one
// that is not a hash line at all. A three-field line whose hash does not parse
// is remembered with its line number. As in the go command, a line of the
// same kind that parses answers for the module and the bad one is ignored,
// stated at warn; with no such line the lookup fails on it. The file as a
// whole is never refused, and the module is never reported absent.
func (c *Client) parse(content string) error {
	sc := bufio.NewScanner(strings.NewReader(content))
	// go.sum lines are short, but raise the buffer to tolerate unusually long
	// module paths without a token-too-long error.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for lineno := 1; sc.Scan(); lineno++ {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 {
			continue
		}
		modPath, verField, hashStr := fields[0], fields[1], fields[2]
		version, isGoMod := strings.CutSuffix(verField, "/go.mod")
		k := key(modPath, version)
		hash, err := domain2.ParseModuleHash(hashStr)
		if err == nil && hash.IsZero() {
			err = fmt.Errorf("invalid module hash %q: a go.sum line carries a hash, never an absence", hashStr)
		}
		bad := c.badZip
		if isGoMod {
			bad = c.badGoMod
		}
		switch {
		case err != nil:
			if _, seen := bad[k]; !seen {
				bad[k] = fmt.Errorf("malformed go.sum line %d: %w", lineno, err)
			}
		case isGoMod:
			c.gomod[k] = hash
		default:
			c.zip[k] = hash
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scanning go.sum: %w", err)
	}
	return nil
}

// Lookup returns the h1 hashes recorded in go.sum for the coordinate. A module
// with no zip entry in go.sum reports Available=false with a "not in go.sum"
// reason; the caller's --from-modcache policy turns that into a hard failure.
func (c *Client) Lookup(_ context.Context, coord coordinate.ModuleCoordinate) ports.SumDBResult {
	k := key(coord.Path(), coord.Version())
	zipHash, hasZip := c.zip[k]
	goModHash, hasGoMod := c.gomod[k]
	for _, leg := range []struct {
		has bool
		bad error
	}{{hasZip, c.badZip[k]}, {hasGoMod, c.badGoMod[k]}} {
		switch {
		case leg.bad == nil:
		case leg.has:
			c.logger.Warn("go.sum: a line whose hash does not parse is ignored; another line answers for the module",
				slog.String("go_sum", c.path), slog.String("coordinate", coord.String()), slog.String("error", leg.bad.Error()))
		default:
			// go.sum names this module only on a line that cannot be read, so
			// it says nothing usable about it: a failed lookup naming the
			// line, never the absence below.
			return ports.SumDBResult{
				Available:      false,
				Reason:         fmt.Sprintf("%s in %s for %s", leg.bad, c.path, coord),
				Unavailability: ports.SumDBUnavailabilityFailure,
				Err:            leg.bad,
			}
		}
	}
	if !hasZip {
		// An absent entry is go.sum's real answer, and this adapter performs no
		// network I/O, so the outcome is policy-unavailable: nothing here can flake
		// and a later attempt would read the same file.
		return ports.SumDBResult{
			Available:      false,
			Reason:         fmt.Sprintf("no go.sum entry for %s in %s", coord, c.path),
			Unavailability: ports.SumDBUnavailabilityPolicy,
		}
	}
	return ports.SumDBResult{
		Available: true,
		ZipHash:   zipHash,
		GoModHash: goModHash,
	}
}

func key(path, version string) string {
	return path + "@" + version
}
