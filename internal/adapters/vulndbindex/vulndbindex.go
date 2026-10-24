// Package vulndbindex is the shared-kernel adapter that decodes
// index/modules.json, the module index an advisory database carries. The osv
// adapter and the vuln application layer both read it, so the decode and its
// size cap exist once.
package vulndbindex

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// Entry is the index's path inside an advisory database zip.
const Entry = "index/modules.json"

// MaxBytes caps the decompressed index. The published index is ~3 MB; the cap
// leaves headroom while refusing a decompression bomb.
const MaxBytes = 256 << 20

// ErrTooLarge is returned for an index larger than MaxBytes, rather than
// decoding a truncated prefix of it.
var ErrTooLarge = errors.New("index/modules.json is larger than the cap")

// ErrMissing is returned for a zip that carries no index.
var ErrMissing = errors.New("no index/modules.json")

// FromZip reads and decodes the index out of an advisory database zip.
func FromZip(data []byte) (ports.AdvisoryIndex, error) {
	return fromZip(data, MaxBytes)
}

func fromZip(data []byte, limit int64) (ports.AdvisoryIndex, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening the advisory database zip: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != Entry {
			continue
		}
		raw, rerr := readCapped(f, limit)
		if rerr != nil {
			return nil, rerr
		}
		return Decode(raw)
	}
	return nil, ErrMissing
}

func readCapped(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Name, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", ErrTooLarge, limit)
	}
	return raw, nil
}

// Decode parses the index into the comparison shape, sorting each module's
// entries so two readings of one generation compare equal regardless of the
// order the file listed them in.
func Decode(raw []byte) (ports.AdvisoryIndex, error) {
	var index []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
			Fixed    string `json:"fixed"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("unmarshal modules index: %w", err)
	}
	out := make(ports.AdvisoryIndex, len(index))
	for _, m := range index {
		entries := make([]ports.AdvisoryIndexEntry, 0, len(m.Vulns))
		for _, v := range m.Vulns {
			entries = append(entries, ports.AdvisoryIndexEntry{ID: v.ID, Modified: v.Modified, Fixed: v.Fixed})
		}
		sort.Slice(entries, func(i, j int) bool {
			a, b := entries[i], entries[j]
			if a.ID != b.ID {
				return a.ID < b.ID
			}
			if a.Modified != b.Modified {
				return a.Modified < b.Modified
			}
			return a.Fixed < b.Fixed
		})
		out[m.Path] = entries
	}
	return out, nil
}
