// Package ziparchive is the shared-kernel adapter for reading ZIP archives.
//
// Per, archive extraction is infrastructure: it must not be performed
// directly from an application or domain layer. This package centralises the
// archive/zip dependency so the bounded contexts (fetch, walk, license, iface,
// vuln) consume already-parsed entries through small ports they own, mirroring
// the iface InterfaceExtractor pattern.
package ziparchive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/dirhash"
)

// Archive is a read-only view over an in-memory module ZIP. Entry names are the
// raw archive names (typically "<module>@<version>/<path>").
type Archive struct {
	zr *zip.Reader
}

// New parses data as a ZIP archive. The bytes are not copied; the caller must
// keep them alive for the lifetime of the Archive.
func New(data []byte) (*Archive, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("parsing zip: %w", err)
	}
	return &Archive{zr: zr}, nil
}

// Names returns every entry name in the archive, sorted lexicographically for
// deterministic iteration.
func (a *Archive) Names() []string {
	out := make([]string, 0, len(a.zr.File))
	for _, f := range a.zr.File {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// ReadFile returns the contents of the entry with the exact name. The boolean
// is false (with a nil error) when no such entry exists.
func (a *Archive) ReadFile(name string) (_ []byte, found bool, retErr error) {
	for _, f := range a.zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, true, fmt.Errorf("opening zip entry %q: %w", name, err)
		}
		defer func() {
			if cerr := rc.Close(); cerr != nil && retErr == nil {
				retErr = fmt.Errorf("closing zip entry %q: %w", name, cerr)
			}
		}()
		data, rerr := io.ReadAll(rc)
		if rerr != nil {
			return nil, true, fmt.Errorf("reading zip entry %q: %w", name, rerr)
		}
		return data, true, nil
	}
	return nil, false, nil
}

// FS presents the archive as an fs.FS rooted at the module root by stripping
// prefix from every entry name (e.g. "<module>@<version>/").
func (a *Archive) FS(prefix string) fs.FS {
	return &strippedFS{zr: a.zr, prefix: prefix}
}

// Hasher is the injectable form of HashModuleZip. It satisfies the module-zip
// hashing port consumed by fetch/domain so the domain holds no archive/zip
// dependency.
type Hasher struct{}

// HashModuleZip implements the fetch/domain module-zip hashing port.
func (Hasher) HashModuleZip(data []byte) (string, error) { return HashModuleZip(data) }

// HashModuleZip returns the dirhash h1 of a module ZIP — the same hash the Go
// proxy/checksum database covers. data must be a module ZIP built with the
// standard golang.org/x/mod/zip layout.
func HashModuleZip(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("reading module zip: %w", err)
	}
	names := make([]string, len(zr.File))
	byName := make(map[string]*zip.File, len(zr.File))
	for i, f := range zr.File {
		names[i] = f.Name
		byName[f.Name] = f
	}
	h, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) {
		f := byName[name]
		if f == nil {
			return nil, fmt.Errorf("file %q not in zip", name)
		}
		rc, oerr := f.Open()
		if oerr != nil {
			return nil, fmt.Errorf("opening %q in module zip: %w", name, oerr)
		}
		return rc, nil
	})
	if err != nil {
		return "", fmt.Errorf("hashing module zip: %w", err)
	}
	return h, nil
}

// ExtractStream extracts a ZIP read from r (of the given byte size) into dest.
// It is zip-slip safe: entries that would escape dest are rejected. The ZIP is
// staged to a temp file so the whole archive is never buffered in memory.
func ExtractStream(r io.Reader, dest string) error {
	tmpZip, err := os.CreateTemp("", "kanonarion-zip-*")
	if err != nil {
		return fmt.Errorf("create temp zip file: %w", err)
	}
	defer func() {
		_ = tmpZip.Close()
		_ = os.Remove(tmpZip.Name())
	}()

	n, err := io.Copy(tmpZip, r)
	if err != nil {
		return fmt.Errorf("write temp zip file: %w", err)
	}
	if _, err := tmpZip.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek temp zip file: %w", err)
	}

	zr, err := zip.NewReader(tmpZip, n)
	if err != nil {
		return fmt.Errorf("open zip reader: %w", err)
	}

	for _, f := range zr.File {
		clean := filepath.Join(dest, filepath.Clean("/"+f.Name))
		if !strings.HasPrefix(clean, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("zip entry %q escapes destination directory", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(clean, 0750); err != nil { /* #nosec G301 -- 0750 is intentional */
				return fmt.Errorf("create directory %q: %w", clean, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(clean), 0750); err != nil { /* #nosec G301 -- 0750 is intentional */
			return fmt.Errorf("create parent directory for %q: %w", clean, err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}
		dst, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()) /* #nosec G304 -- path sanitised against zip-slip above */
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("create destination file %q: %w", clean, err)
		}
		if _, err := io.Copy(dst, rc); err != nil { /* #nosec G110 -- zip sourced from trusted store, size bounded by fetch stage */
			_ = dst.Close()
			_ = rc.Close()
			return fmt.Errorf("copy zip entry %q: %w", f.Name, err)
		}
		_ = dst.Close()
		_ = rc.Close()
	}
	return nil
}

// maxEntryDepth bounds the number of path components in a zip entry name the
// FS view will synthesise directories for. Legitimate Go module zips nest only
// a handful of directories deep; an adversarial proxy-fetched zip (
// relates) can carry pathologically deep names purely to drive
// unbounded fs.WalkDir recursion.
const maxEntryDepth = 256

// isSafeEntryName reports whether name is a clean, relative, forward-slash
// path safe to expose through the fs.FS view. It rejects the malformed and
// adversarial shapes that would otherwise make strippedFS synthesise a
// zero-width or self-referential directory component and recurse forever:
// absolute paths, backslashes, empty segments ("a//b"), and "."/".."
// segments. Real module-zip entry names never take these shapes.
func isSafeEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return false
	}
	segs := strings.Split(name, "/")
	if len(segs) > maxEntryDepth {
		return false
	}
	for i, s := range segs {
		// A trailing "/" (directory marker) yields one empty final segment;
		// that is the only empty segment we tolerate.
		if s == "" && i != len(segs)-1 {
			return false
		}
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}

// strippedFS wraps a zip.Reader and strips a fixed prefix from all file paths,
// presenting a module zip as a plain fs.FS rooted at the module root.
type strippedFS struct {
	zr     *zip.Reader
	prefix string
}

func (s *strippedFS) Open(name string) (fs.File, error) {
	full := s.prefix + name
	for _, f := range s.zr.File {
		if !isSafeEntryName(f.Name) {
			continue
		}
		if f.Name == full {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening zip entry %s: %w", f.Name, err)
			}
			fi := f.FileInfo()
			return &zipFileWrapper{ReadCloser: rc, info: fi}, nil
		}
	}
	// Try to synthesise a directory entry.
	return &syntheticDir{name: name, fs: s}, nil
}

// zipFileWrapper wraps zip.ReadCloser to satisfy fs.File.
type zipFileWrapper struct {
	io.ReadCloser
	info fs.FileInfo
}

func (z *zipFileWrapper) Stat() (fs.FileInfo, error) { return z.info, nil }
func (z *zipFileWrapper) ReadDir(int) ([]fs.DirEntry, error) {
	return nil, fmt.Errorf("not a directory")
}

// ReadDir implements fs.ReadDirFS by listing zip entries under the given dir.
func (s *strippedFS) ReadDir(dir string) ([]fs.DirEntry, error) {
	prefix := s.prefix
	if dir != "." {
		prefix += dir + "/"
	}

	seen := map[string]bool{}
	var entries []fs.DirEntry

	for _, f := range s.zr.File {
		if !isSafeEntryName(f.Name) {
			continue
		}
		if !strings.HasPrefix(f.Name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(f.Name, prefix)
		if rel == "" {
			continue
		}
		// Only entries at this level (no nested slash).
		slash := strings.IndexByte(rel, '/')
		if slash < 0 {
			// file at this level
			if !seen[rel] {
				seen[rel] = true
				fi := f.FileInfo()
				entries = append(entries, fs.FileInfoToDirEntry(fi))
			}
		} else {
			// directory
			dname := rel[:slash]
			if !seen[dname] {
				seen[dname] = true
				entries = append(entries, &syntheticDirEntry{name: dname})
			}
		}
	}
	return entries, nil
}

// ReadFile implements fs.ReadFileFS.
func (s *strippedFS) ReadFile(name string) ([]byte, error) {
	full := s.prefix + name
	for _, f := range s.zr.File {
		if !isSafeEntryName(f.Name) {
			continue
		}
		if f.Name == full {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening zip entry %s: %w", f.Name, err)
			}
			defer rc.Close() //nolint:errcheck
			data, rerr := io.ReadAll(rc)
			if rerr != nil {
				return nil, fmt.Errorf("reading zip entry %s: %w", f.Name, rerr)
			}
			return data, nil
		}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

type syntheticDir struct {
	name string
	fs   *strippedFS
}

func (d *syntheticDir) Stat() (fs.FileInfo, error) { return &syntheticDirInfo{name: d.name}, nil }
func (d *syntheticDir) Read([]byte) (int, error)   { return 0, fmt.Errorf("is a directory") }
func (d *syntheticDir) Close() error               { return nil }
func (d *syntheticDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.fs.ReadDir(d.name)
	if err != nil {
		return nil, err
	}
	if n > 0 && n < len(entries) {
		return entries[:n], nil
	}
	return entries, nil
}

type syntheticDirInfo struct{ name string }

func (i *syntheticDirInfo) Name() string       { return i.name }
func (i *syntheticDirInfo) Size() int64        { return 0 }
func (i *syntheticDirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (i *syntheticDirInfo) ModTime() time.Time { return time.Time{} }
func (i *syntheticDirInfo) IsDir() bool        { return true }
func (i *syntheticDirInfo) Sys() any           { return nil }

type syntheticDirEntry struct{ name string }

func (e *syntheticDirEntry) Name() string               { return e.name }
func (e *syntheticDirEntry) IsDir() bool                { return true }
func (e *syntheticDirEntry) Type() fs.FileMode          { return fs.ModeDir }
func (e *syntheticDirEntry) Info() (fs.FileInfo, error) { return &syntheticDirInfo{name: e.name}, nil }
