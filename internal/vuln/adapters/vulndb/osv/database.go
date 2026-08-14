package osv

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/goenv"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"golang.org/x/mod/semver"
)

const vulnGoDevBase = "https://vuln.go.dev"

// downloadProgressInterval bounds the silent gap during the snapshot download:
// one progress line per this many bytes received. The bulk vulndb.zip is a
// multi-megabyte body over a single connection, so without these lines a slow
// link is indistinguishable from a hang.
const downloadProgressInterval = 512 * 1024

// maxDBJSONBytes caps the index/db.json read out of the downloaded zip. The
// file is a tiny {"modified": "..."} object; the bound defends the version
// probe against a decompression bomb in an adversarial zip.
const maxDBJSONBytes = 1 << 20

// ErrNetworkForbidden reports that the environment declares no network access
// and the advisory-database request was refused before any I/O.
//
// The advisory set is the thing a scan is judged against, so acquiring it
// across a boundary the operator closed is not a lesser breach than fetching a
// module across it: the finding would carry a basis this enclave was never
// allowed to see. It wraps goenv.ErrNetworkForbidden, so the refusal reads the
// same to a caller as the module proxy's.
var ErrNetworkForbidden = fmt.Errorf("%w: the environment declares no advisory-database download", goenv.ErrNetworkForbidden)

// snapshotRemedies names the ways to judge a scan without the network. It is
// appended to the refusal so the message that stops the run also says what to
// run instead — and what already works: a store that carries a snapshot answers
// scans offline without any of this, because the scan use cases prefer the
// stored generation and only reach the network when there is none.
const snapshotRemedies = "a store that already holds a snapshot still answers scans offline: " +
	"drop --fresh so the stored generation is used, or pin one with " +
	"--snapshot-source/--snapshot-version (kanonarion vuln-snapshot-list shows what is held)"

// modulevuln holds a single OSV entry from the modules index.
type modulevuln struct {
	id    string
	fixed string // semver without 'v' prefix; empty = not yet fixed
}

// Database implements ports.VulnerabilityDatabase fetching from vuln.go.dev.
type Database struct {
	client    *http.Client
	vulnStore ports.VulnerabilityStore
	logger    *slog.Logger

	mu          sync.RWMutex
	moduleIndex map[string][]modulevuln // map module path -> vulnerability entries
}

// New returns a new Database.
func New(client *http.Client, vulnStore ports.VulnerabilityStore) *Database {
	if client == nil {
		client = http.DefaultClient
	}
	return &Database{client: client, vulnStore: vulnStore, logger: slog.Default()}
}

// WithLogger returns a copy of the Database using the given logger.
func (d *Database) WithLogger(logger *slog.Logger) *Database {
	copy := New(d.client, d.vulnStore)
	copy.logger = logger
	return copy
}

// Snapshot fetches the full Go vulnerability database in a single request to
// vuln.go.dev's bulk /vulndb.zip endpoint and returns it verbatim, suitable for
// use as a local govulncheck -db source. The zip already ships in the
// govulncheck file:// layout (index/db.json, index/modules.json, ID/<ID>.json);
// we validate that layout and read the snapshot Version from index/db.json
// before handing the body back, failing closed on any layout mismatch.
func (d *Database) Snapshot(ctx context.Context) (domain.DatabaseSnapshot, io.ReadCloser, error) {
	zipData, err := d.fetchVulnDBZip(ctx)
	if err != nil {
		return domain.DatabaseSnapshot{}, nil, fmt.Errorf("fetch vulndb.zip: %w", err)
	}

	version, err := validateSnapshotZip(zipData)
	if err != nil {
		return domain.DatabaseSnapshot{}, nil, fmt.Errorf("validate vulndb.zip: %w", err)
	}

	// Seal the snapshot against the bytes just downloaded. This is the only place
	// that sees them before anything else does, so it is the only place that can
	// establish what "this snapshot" means; every later reader checks the blob it
	// holds against this hash rather than trusting the version string, which is
	// metadata the blob itself asserts.
	snapshot, err := domain.NewDatabaseSnapshot("vuln.go.dev", version, time.Now(), domain.HashSnapshotContent(zipData))
	if err != nil {
		return domain.DatabaseSnapshot{}, nil, fmt.Errorf("pinning vulndb.zip snapshot: %w", err)
	}

	return snapshot, io.NopCloser(bytes.NewReader(zipData)), nil
}

// LatestVersion reads the generation stamp vuln.go.dev currently publishes from
// the standalone index/db.json — a single tiny {"modified": "..."} object — and
// returns it without touching the multi-megabyte bulk body.
//
// The stamp is the same string Snapshot reports as the snapshot's Version: both
// come from index/db.json's modified field, one read out of the downloaded zip
// and one read directly. An empty stamp is an error rather than a version,
// because the caller's next step is a comparison and "" compares equal to
// nothing anyone stored.
func (d *Database) LatestVersion(ctx context.Context) (string, error) {
	url := vulnGoDevBase + "/index/db.json"
	resp, err := d.request(ctx, url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDBJSONBytes))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	version, err := decodeDBModified(data)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", fmt.Errorf("%s has empty modified field", url)
	}
	return version, nil
}

// maxModulesIndexBytes caps the index/modules.json read out of a stored
// snapshot zip. The published index is ~3 MB uncompressed; the bound leaves
// generous headroom while defending against a decompression bomb.
const maxModulesIndexBytes = 256 << 20

// PublishedAdvisoryIndex fetches the standalone module index the database
// publishes — the same index/modules.json the bulk zip carries, served
// gzip-compressed at a fraction of the body's size — so two generations can be
// compared without downloading either in full.
func (d *Database) PublishedAdvisoryIndex(ctx context.Context) (ports.AdvisoryIndex, error) {
	data, err := d.fetchRawGZ(ctx, vulnGoDevBase+"/index/modules.json.gz")
	if err != nil {
		return nil, fmt.Errorf("fetch published modules index: %w", err)
	}
	return decodeAdvisoryIndex(data)
}

// SnapshotAdvisoryIndex reads index/modules.json out of an already-stored
// snapshot. The bytes are the store's, so this costs a local read and no
// network: it is the "before" half of a generation comparison.
func (d *Database) SnapshotAdvisoryIndex(ctx context.Context, identity domain.DatabaseSnapshot) (ports.AdvisoryIndex, error) {
	zr, err := d.openStoredSnapshot(ctx, identity)
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name != "index/modules.json" {
			continue
		}
		data, rerr := readZipFile(f, maxModulesIndexBytes)
		if rerr != nil {
			return nil, rerr
		}
		return decodeAdvisoryIndex(data)
	}
	return nil, fmt.Errorf("stored snapshot %s@%s has no index/modules.json", identity.Source(), identity.Version())
}

// openStoredSnapshot reads a stored snapshot's bytes out of the store and opens
// them as a zip. Every read of a stored snapshot goes through here so that
// "already stored" means the same thing to each of them — a local read, and no
// network under any circumstance.
func (d *Database) openStoredSnapshot(ctx context.Context, identity domain.DatabaseSnapshot) (*zip.Reader, error) {
	rc, err := d.vulnStore.GetDatabaseSnapshot(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("get stored snapshot %s@%s: %w", identity.Source(), identity.Version(), err)
	}
	defer func() { _ = rc.Close() }()

	zipData, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read stored snapshot %s@%s: %w", identity.Source(), identity.Version(), err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("open stored snapshot %s@%s: %w", identity.Source(), identity.Version(), err)
	}
	return zr, nil
}

// decodeAdvisoryIndex parses index/modules.json into the comparison shape,
// sorting each module's entries so two readings of one generation compare equal
// regardless of the order the file happened to list them in.
func decodeAdvisoryIndex(data []byte) (ports.AdvisoryIndex, error) {
	var index []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
			Fixed    string `json:"fixed"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
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

// fetchVulnDBZip downloads the bulk /vulndb.zip body in one request, logging
// byte-based progress so a slow first run does not look like a hang.
func (d *Database) fetchVulnDBZip(ctx context.Context) ([]byte, error) {
	url := vulnGoDevBase + "/vulndb.zip"
	resp, err := d.request(ctx, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	d.logger.Info("vulnerability database snapshot: downloading",
		"source", "vuln.go.dev", "content_length", resp.ContentLength)
	data, err := d.readWithProgress(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, err
	}
	d.logger.Info("vulnerability database snapshot: download complete",
		"zip_bytes", len(data))
	return data, nil
}

// readWithProgress reads body fully into memory, emitting a progress line every
// downloadProgressInterval bytes. contentLength may be -1 (unknown), in which
// case it is logged as-is and progress is still reported by bytes received.
func (d *Database) readWithProgress(body io.Reader, contentLength int64) ([]byte, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 64*1024)
	var total, nextLog int64 = 0, downloadProgressInterval
	for {
		n, readErr := body.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			total += int64(n)
			for total >= nextLog {
				d.logger.Info("vulnerability database snapshot: download progress",
					"downloaded_bytes", total, "content_length", contentLength)
				nextLog += downloadProgressInterval
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read vulndb.zip body: %w", readErr)
		}
	}
	return buf.Bytes(), nil
}

// responseError maps a vuln.go.dev HTTP response to an error, distinguishing
// rate limiting (429, surfacing Retry-After when present) from other non-200
// statuses. It returns nil for HTTP 200.
// request performs every outbound GET this adapter makes, so the no-network
// contract is asked once instead of at four call sites that could each forget
// to — which is how the advisory download stayed outside the contract while the
// module proxy honoured it.
//
// The refusal is returned before the request is even built: no socket, no DNS,
// no timeout. On a non-2xx the body is closed here, so a caller only ever holds
// a response it must close.
func (d *Database) request(ctx context.Context, url string) (*http.Response, error) {
	if goenv.NetworkForbidden() {
		return nil, fmt.Errorf("%w: %s not fetched; %s", ErrNetworkForbidden, url, snapshotRemedies)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", url, err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if err := responseError(resp, url); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

func responseError(resp *http.Response, url string) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			return fmt.Errorf("rate limited by vuln.go.dev (HTTP 429): retry after %s", retryAfter)
		}
		return fmt.Errorf("rate limited by vuln.go.dev (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status fetching %s: %s", url, resp.Status)
	}
	return nil
}

// validateSnapshotZip checks that data is a zip carrying the govulncheck file://
// layout — index/db.json, index/modules.json, and at least one ID/<ID>.json —
// and returns the snapshot version parsed from index/db.json's modified field.
// It fails closed on any missing layout element. Pure (no network I/O) so the
// untrusted-zip ingestion path can be tested and fuzzed directly.
func validateSnapshotZip(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open vulndb.zip: %w", err)
	}

	var hasModules, hasEntry bool
	var dbContent []byte
	var dbFound bool
	for _, f := range zr.File {
		switch {
		case f.Name == "index/db.json":
			dbFound = true
			dbContent, err = readZipFile(f, maxDBJSONBytes)
			if err != nil {
				return "", err
			}
		case f.Name == "index/modules.json":
			hasModules = true
		case strings.HasPrefix(f.Name, "ID/") && strings.HasSuffix(f.Name, ".json"):
			hasEntry = true
		}
	}

	if !dbFound {
		return "", fmt.Errorf("missing index/db.json")
	}
	if !hasModules {
		return "", fmt.Errorf("missing index/modules.json")
	}
	if !hasEntry {
		return "", fmt.Errorf("missing ID/<ID>.json entries")
	}

	version, err := decodeDBModified(dbContent)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", fmt.Errorf("index/db.json has empty modified field")
	}
	return version, nil
}

// readZipFile opens a single zip entry and reads up to limit bytes. The limit
// bounds memory against a decompression bomb in an adversarial entry.
func readZipFile(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Name, err)
	}
	return data, nil
}

// fetchRawGZ fetches a gzip-compressed URL and returns the decompressed bytes.
func (d *Database) fetchRawGZ(ctx context.Context, url string) ([]byte, error) {
	resp, err := d.request(ctx, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader for %s: %w", url, err)
	}
	defer func() { _ = gr.Close() }()
	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("read gzip body from %s: %w", url, err)
	}
	return data, nil
}

// decodeDBModified parses index/db.json and returns the modified timestamp.
func decodeDBModified(data []byte) (string, error) {
	var meta struct {
		Modified string `json:"modified"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("unmarshal db.json: %w", err)
	}
	return meta.Modified, nil
}

// decodeModulesIndex parses index/modules.json into the module-path lookup
// used by CheckVulnerable.
func decodeModulesIndex(data []byte) (map[string][]modulevuln, error) {
	var index []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID    string `json:"id"`
			Fixed string `json:"fixed,omitempty"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("unmarshal modules index: %w", err)
	}
	moduleIndex := make(map[string][]modulevuln, len(index))
	for _, entry := range index {
		vulns := make([]modulevuln, len(entry.Vulns))
		for i, v := range entry.Vulns {
			vulns[i] = modulevuln{id: v.ID, fixed: v.Fixed}
		}
		moduleIndex[entry.Path] = vulns
	}
	return moduleIndex, nil
}

// GetSnapshot retrieves a previously-pinned snapshot from the store.
func (d *Database) GetSnapshot(ctx context.Context, identity domain.DatabaseSnapshot) (io.ReadCloser, error) {
	rc, err := d.vulnStore.GetDatabaseSnapshot(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("get database snapshot: %w", err)
	}
	return rc, nil
}

// ensureIndex lazily loads the modules index (module path -> advisory entries)
// once, guarding the load with the write lock so concurrent callers cannot race
// to fetch it twice.
func (d *Database) ensureIndex(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.moduleIndex != nil {
		return nil
	}
	data, err := d.fetchRawGZ(ctx, vulnGoDevBase+"/index/modules.json.gz")
	if err != nil {
		return fmt.Errorf("fetch modules index: %w", err)
	}
	moduleIndex, err := decodeModulesIndex(data)
	if err != nil {
		return err
	}
	d.moduleIndex = moduleIndex
	return nil
}

// CheckVulnerable checks if the given modules at specific versions have any known
// vulnerabilities in the database. This is a lightweight metadata check that
// uses the modules index fixed-version field to exclude already-patched versions.
func (d *Database) CheckVulnerable(ctx context.Context, modules []coordinate.ModuleCoordinate) (map[coordinate.ModuleCoordinate][]string, error) {
	if err := d.ensureIndex(ctx); err != nil {
		return nil, err
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	res := make(map[coordinate.ModuleCoordinate][]string)
	for _, m := range modules {
		entries, ok := d.moduleIndex[m.Path()]
		if !ok {
			continue
		}
		var affecting []string
		for _, e := range entries {
			if isAffectedVersion(m.Version(), e.fixed) {
				affecting = append(affecting, e.id)
			}
		}
		if len(affecting) > 0 {
			res[m] = affecting
		}
	}
	return res, nil
}

// advisoryAffects reports whether coord's version falls within the affected
// SEMVER ranges of the advisory block matching coord's module path. Unlike the
// coarse index/modules.json fixed-version field — which collapses an advisory's
// per-branch backports to a single (highest) fixed version — this evaluates the
// full affected[].ranges introduced/fixed event list, so a version patched on an
// older branch (below the highest fix) is correctly cleared instead of
// over-reported. When no affected block matches the module path, or a matched
// block carries no comparable SEMVER range, it stays conservative and reports
// true so a known-affected module is never silently dropped.
func advisoryAffects(coord coordinate.ModuleCoordinate, adv *osvAdvisory) bool {
	matched := false
	for _, a := range adv.Affected {
		if a.Package.Name != coord.Path() {
			continue
		}
		matched = true
		if versionInAffectedRanges(coord.Version(), a.Ranges) {
			return true
		}
	}
	// No block names this module path: the advisory cannot refine the coarse
	// index verdict, so keep it (conservative — never drop a known-affected hit).
	return !matched
}

// versionInAffectedRanges reports whether version lies within any affected
// interval described by the OSV SEMVER ranges. An unparseable version, or a set
// of ranges with no comparable SEMVER entry, is treated as affected so the
// precise check never turns a coarse-index hit into a false clear.
func versionInAffectedRanges(version string, ranges []osvRange) bool {
	v := vPrefix(version)
	if !semver.IsValid(v) {
		return true
	}
	sawSemver := false
	for _, r := range ranges {
		if r.Type != "" && r.Type != "SEMVER" {
			continue // only SEMVER ranges are version-comparable
		}
		sawSemver = true
		if semverRangeContains(v, r.Events) {
			return true
		}
	}
	return !sawSemver
}

// semverRangeContains walks a range's flat introduced/fixed event list as a
// sequence of half-open intervals [introduced, fixed) and reports whether v
// falls in any of them. A trailing introduced with no matching fixed is an
// open-ended interval [introduced, +inf). The special introduced "0" is the
// zero version, so it opens an interval with no lower bound. v is expected
// v-prefixed and valid.
func semverRangeContains(v string, events []osvEvent) bool {
	open := false  // inside an interval awaiting its fixed bound
	lowOK := false // v is at or above the current interval's lower bound
	for _, ev := range events {
		switch {
		case ev.Introduced != "":
			open = true
			lowOK = ev.Introduced == "0" || semver.Compare(v, vPrefix(ev.Introduced)) >= 0
		case ev.Fixed != "":
			if open && lowOK && semver.Compare(v, vPrefix(ev.Fixed)) < 0 {
				return true
			}
			open = false
		}
	}
	return open && lowOK
}

// isAffectedVersion reports whether version is affected by a vulnerability
// whose minimum fixed version is fixed. An empty fixed means no patch exists
// yet (all versions affected). semver.Compare requires 'v' prefix; we
// normalise both inputs before comparing.
func isAffectedVersion(version, fixed string) bool {
	if fixed == "" {
		return true
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !strings.HasPrefix(fixed, "v") {
		fixed = "v" + fixed
	}
	if !semver.IsValid(version) || !semver.IsValid(fixed) {
		return true // conservative: treat as affected when version cannot be parsed
	}
	return semver.Compare(version, fixed) < 0
}

// maxAdvisoryBytes caps a single ID/<ID>.json advisory read. Advisory records
// are small; the bound defends the per-advisory enrichment fetch against a
// decompression/size bomb in an adversarial entry.
const maxAdvisoryBytes = 1 << 20

// osvAdvisory is the subset of the OSV advisory schema the metadata path reads
// to enrich a finding: the human summary and timestamps, the retraction
// timestamp, the affected version ranges (to render an affected-range string and
// the fixed version), and the ecosystem-specific imported symbols (the at-risk
// symbols).
type osvAdvisory struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Aliases   []string  `json:"aliases"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
	// Withdrawn is the OSV top-level retraction timestamp, absent on a live
	// advisory — hence the pointer, which distinguishes "not withdrawn" from a
	// zero timestamp that decoded from something.
	//
	// The Go vulnerability database does carry it: GO-2026-4923 was published
	// 2026-04-06 and withdrawn 2026-04-08, and remained in the pinned snapshot
	// with both timestamps and a "WITHDRAWN: " summary prefix. Leaving the field
	// out of this struct is what made the retraction unreadable, so the prose
	// prefix was the only trace of it and nothing read prose.
	Withdrawn *time.Time `json:"withdrawn"`
	// References are the advisory's own links, each an OSV {type, url} pair. The
	// bytes were always on the wire — every advisory document this adapter
	// fetches carries the array — and this struct simply did not decode them, so
	// a finding recorded nothing about where the advisory was published or which
	// commit fixed it. Measured on the pinned snapshot: 4130 of 4134 advisories
	// carry at least one, 15132 URLs in total, of which 3160 are FIX links.
	References []osvReference `json:"references"`
	Affected   []osvAffected  `json:"affected"`
}

// osvReference is one entry of an advisory's references array. The type travels
// with the URL because it is what separates a FIX commit from a WEB mention.
type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// osvAffected is one affected-package block of an OSV advisory.
type osvAffected struct {
	Package struct {
		Name string `json:"name"`
	} `json:"package"`
	Ranges            []osvRange `json:"ranges"`
	EcosystemSpecific struct {
		Imports []osvImport `json:"imports"`
	} `json:"ecosystem_specific"`
}

// osvRange is a version range with introduced/fixed events.
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent is a single introduced or fixed boundary in a range.
type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// osvImport is an imported package with its at-risk symbols.
type osvImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

// LookupFindings returns enriched findings for every advisory affecting coord.
// It loads the modules index, filters to advisories that affect coord's version
// (reusing the same fixed-version logic as CheckVulnerable), then fetches each
// matching ID/<ID>.json advisory to populate the human summary, affected range,
// fixed version and at-risk symbols. When a single advisory's enrichment fetch
// fails the finding degrades to its bare ID and known fixed version rather than
// disappearing — the module is still known-affected — and the failure is logged.
func (d *Database) LookupFindings(ctx context.Context, coord coordinate.ModuleCoordinate) ([]domain.VulnerabilityFinding, error) {
	if err := d.ensureIndex(ctx); err != nil {
		return nil, err
	}

	d.mu.RLock()
	entries := append([]modulevuln(nil), d.moduleIndex[coord.Path()]...)
	d.mu.RUnlock()

	var findings []domain.VulnerabilityFinding
	for _, e := range entries {
		// Coarse pre-filter: the index fixed version is the advisory's single
		// highest fix, so it only ever over-includes (a version below any real
		// fix). It never wrongly excludes, making it a safe cheap skip before the
		// per-advisory fetch.
		if !isAffectedVersion(coord.Version(), e.fixed) {
			continue
		}
		finding := domain.VulnerabilityFinding{ID: e.id, FixedIn: normaliseFixed(e.fixed)}
		adv, err := d.fetchAdvisory(ctx, e.id)
		if err != nil {
			// Enrichment failed: we cannot refine against the full ranges, so keep
			// the conservative coarse-index verdict rather than dropping a
			// known-affected hit. The finding degrades to its bare ID + index fix.
			d.logger.Warn("vuln metadata: advisory enrichment failed",
				"advisory", e.id, "coordinate", coord, "error", err)
			findings = append(findings, finding)
			continue
		}
		// Precise multi-range match: index/modules.json collapses per-branch
		// backports to one highest fixed, over-reporting a version patched on an
		// older branch. Re-evaluate against the advisory's full affected
		// range set and drop the finding when this version is truly not affected.
		if !advisoryAffects(coord, adv) {
			d.logger.Debug("vuln metadata: version cleared by full-range match",
				"advisory", e.id, "coordinate", coord)
			continue
		}
		enrichFinding(&finding, coord, adv)
		findings = append(findings, finding)
	}
	domain.SortFindings(findings)
	return findings, nil
}

// fetchAdvisory retrieves and decodes a single ID/<ID>.json OSV advisory.
func (d *Database) fetchAdvisory(ctx context.Context, id string) (*osvAdvisory, error) {
	url := vulnGoDevBase + "/ID/" + id + ".json"
	resp, err := d.request(ctx, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAdvisoryBytes))
	if err != nil {
		return nil, fmt.Errorf("read advisory %s: %w", url, err)
	}
	var adv osvAdvisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return nil, fmt.Errorf("unmarshal advisory %s: %w", url, err)
	}
	return &adv, nil
}

// advisoryReferences projects the advisory's references onto the domain pair,
// preserving a nil as nil: a finding whose advisory carried no references must
// not put an empty array on the sealed wire that no other record carries.
//
// Nothing is filtered by type. A reference type this build does not recognise
// is still what the advisory published, and dropping it would make the record
// state less than was read.
func advisoryReferences(refs []osvReference) []domain.AdvisoryReference {
	if refs == nil {
		return nil
	}
	out := make([]domain.AdvisoryReference, 0, len(refs))
	for _, r := range refs {
		out = append(out, domain.AdvisoryReference{Type: r.Type, URL: r.URL})
	}
	return out
}

// enrichFinding populates summary/details/aliases/timestamps — including the
// retraction timestamp, which decides whether the match counts as a finding at
// all — from the advisory, then derives the affected-range string, the fixed
// version and the at-risk symbols from the affected block whose package matches
// coord's path.
//
// THE FIXED VERSION IS THE ONE FOR THE BRANCH IN HAND. An advisory backported
// across maintained release branches states one introduced/fixed pair per
// branch, and index/modules.json collapses them to the single highest — which
// for a Go standard-library advisory is usually the next major's release
// candidate. Reporting that told a reader on a supported stable branch to move
// to an unreleased toolchain when a point release already carried the fix, and
// it is the worst direction to be wrong in: a one-command upgrade reads as a
// wait-for-the-next-major. The pair whose interval contains coord's version is
// the answer, and it overrides the index's coarse value rather than deferring to
// it.
//
// Where no interval contains the version there is nothing to select from, and
// the coarse index value stands. On this path that combination is unreachable:
// LookupFindings has already dropped a finding whose module path is named with
// no containing range, so a block reaching here either contains the version or
// declares no comparable SEMVER range at all.
func enrichFinding(f *domain.VulnerabilityFinding, coord coordinate.ModuleCoordinate, adv *osvAdvisory) {
	modulePath := coord.Path()
	f.Summary = adv.Summary
	f.Details = adv.Details
	f.Aliases = adv.Aliases
	f.References = advisoryReferences(adv.References)
	f.PublishedAt = adv.Published
	f.ModifiedAt = adv.Modified
	if adv.Withdrawn != nil {
		f.WithdrawnAt = *adv.Withdrawn
	}

	for _, a := range adv.Affected {
		if a.Package.Name != modulePath {
			continue
		}
		rangeStr, fixed := formatAffected(a.Ranges)
		if rangeStr != "" {
			f.AffectedRange = rangeStr
		}
		if branchFix, ok := fixedForVersion(coord.Version(), a.Ranges); ok {
			f.FixedIn = branchFix
		} else if f.FixedIn == "" {
			f.FixedIn = fixed
		}
		f.AffectedSymbols = collectSymbols(a.EcosystemSpecific.Imports)
		// An entry that names this module path but no symbol within it is recorded
		// as such, so a reader can see that symbol-level reachability was never
		// available for this coordinate rather than inferring it from an empty
		// symbol list — which is also what an enrichment that never ran leaves
		// behind. The two are not the same fact and must not look alike.
		f.AdvisoryNamesNoSymbols = len(f.AffectedSymbols) == 0
	}
}

// formatAffected renders an OSV SEMVER range as a human "introduced/fixed"
// string and returns the minimum fixed version (v-prefixed) when one exists.
// ">= vX" means introduced at X with no fix; "< vY" means fixed at Y from the
// zero version; ">= vX, < vY" bounds both. An empty range yields "".
func formatAffected(ranges []osvRange) (rangeStr, fixed string) {
	var parts []string
	for _, r := range ranges {
		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "" && ev.Introduced != "0":
				parts = append(parts, ">= "+vPrefix(ev.Introduced))
			case ev.Fixed != "":
				parts = append(parts, "< "+vPrefix(ev.Fixed))
				if fixed == "" {
					fixed = vPrefix(ev.Fixed)
				}
			}
		}
	}
	return strings.Join(parts, ", "), fixed
}

// fixedForVersion returns the fixed bound of the affected interval that contains
// version — the fix for the release branch the module in hand is on — and
// reports whether any interval contained it.
//
// The events of one range are a flat sequence of introduced and fixed
// boundaries forming half-open intervals [introduced, fixed). An interval with
// no fixed bound is affected with no fix yet, which is a containing interval
// carrying no answer: it returns "" and true, so a caller does not fall back to
// another branch's fix for a version nothing has fixed.
//
// An unparseable version, or a range in a vocabulary other than SEMVER, is not
// comparable and selects nothing.
func fixedForVersion(version string, ranges []osvRange) (string, bool) {
	v := vPrefix(version)
	if !semver.IsValid(v) {
		return "", false
	}
	for _, r := range ranges {
		if r.Type != "" && r.Type != "SEMVER" {
			continue
		}
		open, lowOK := false, false
		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "":
				open = true
				lowOK = ev.Introduced == "0" || semver.Compare(v, vPrefix(ev.Introduced)) >= 0
			case ev.Fixed != "":
				if open && lowOK && semver.Compare(v, vPrefix(ev.Fixed)) < 0 {
					return vPrefix(ev.Fixed), true
				}
				open = false
			}
		}
		if open && lowOK {
			return "", true
		}
	}
	return "", false
}

// collectSymbols flattens, de-duplicates and sorts the imported symbols across
// every import block of an affected package, giving a deterministic at-risk
// symbol list independent of advisory ordering.
func collectSymbols(imports []osvImport) []string {
	seen := make(map[string]struct{})
	var syms []string
	for _, imp := range imports {
		for _, s := range imp.Symbols {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			syms = append(syms, s)
		}
	}
	sort.Strings(syms)
	return syms
}

// normaliseFixed v-prefixes a non-empty index fixed version; empty stays empty
// (no fix exists yet).
func normaliseFixed(fixed string) string {
	if fixed == "" {
		return ""
	}
	return vPrefix(fixed)
}

// vPrefix ensures a semver string carries the leading 'v' the rest of the
// codebase uses.
func vPrefix(v string) string {
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// Ensure Database implements ports.VulnerabilityDatabase.
var _ ports.VulnerabilityDatabase = (*Database)(nil)
