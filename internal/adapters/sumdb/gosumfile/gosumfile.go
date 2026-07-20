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
	"os"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// Client implements ports.SumDBClient backed by a parsed go.sum file.
type Client struct {
	// zip maps "path@version" to the module zip h1 hash.
	zip map[string]domain2.ModuleHash
	// gomod maps "path@version" to the go.mod h1 hash.
	gomod map[string]domain2.ModuleHash
	// path is the go.sum path, retained for error messages.
	path string
}

var _ ports.SumDBClient = (*Client)(nil)

// New parses the go.sum file at path and returns a Client. A missing go.sum is
// not an error here — it parses to an empty client, and every Lookup then
// reports Available=false so the caller's hard-fail policy fires with a clear
// "not in go.sum" reason rather than a load error.
func New(path string) (*Client, error) {
	c := &Client{
		zip:   make(map[string]domain2.ModuleHash),
		gomod: make(map[string]domain2.ModuleHash),
		path:  path,
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
// Malformed lines are skipped; a go.sum written by the Go toolchain is always
// well-formed, so a skipped line reflects a comment or blank, not data loss.
func (c *Client) parse(content string) error {
	sc := bufio.NewScanner(strings.NewReader(content))
	// go.sum lines are short, but raise the buffer to tolerate unusually long
	// module paths without a token-too-long error.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 {
			continue
		}
		modPath, verField, hashStr := fields[0], fields[1], fields[2]
		hash, err := domain2.ParseModuleHash(hashStr)
		if err != nil {
			continue
		}
		if strings.HasSuffix(verField, "/go.mod") {
			version := strings.TrimSuffix(verField, "/go.mod")
			c.gomod[key(modPath, version)] = hash
		} else {
			c.zip[key(modPath, verField)] = hash
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
	k := key(coord.Path, coord.Version)
	zipHash, ok := c.zip[k]
	if !ok {
		return ports.SumDBResult{
			Available: false,
			Reason:    fmt.Sprintf("no go.sum entry for %s in %s", coord, c.path),
		}
	}
	return ports.SumDBResult{
		Available: true,
		ZipHash:   zipHash,
		GoModHash: c.gomod[k],
	}
}

func key(path, version string) string {
	return path + "@" + version
}
