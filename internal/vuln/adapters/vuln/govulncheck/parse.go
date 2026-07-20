package govulncheck

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// Message is a minimal version of golang.org/x/vuln/internal/govulncheck.Message
type Message struct {
	Config   json.RawMessage `json:"config,omitempty"`
	Progress json.RawMessage `json:"progress,omitempty"`
	OSV      *OSV            `json:"osv,omitempty"`
	Finding  *Finding        `json:"finding,omitempty"`
	SBOM     json.RawMessage `json:"sbom,omitempty"`
}
type OSV struct {
	ID        string    `json:"id"`
	Aliases   []string  `json:"aliases,omitempty"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details,omitempty"`
	Published time.Time `json:"published"`
	Modified  time.Time `json:"modified"`
}
type Finding struct {
	OSV          string          `json:"osv"`
	FixedVersion string          `json:"fixed_version,omitempty"`
	Trace        json.RawMessage `json:"trace,omitempty"`
}
type Frame struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Receiver string `json:"receiver,omitempty"`
}

func (s *Scanner) processMessage(raw []byte, msg *Message, osvs map[string]*OSV, intern func(string) string) {
	// Fast pre-check to distinguish OSV from Finding
	isOSV := bytes.Contains(raw, []byte("\"osv\":")) && !bytes.Contains(raw, []byte("\"finding\":"))

	if isOSV {
		// Reuse msg struct
		msg.Config = nil
		msg.Progress = nil
		msg.OSV = nil
		msg.Finding = nil
		msg.SBOM = nil

		if err := json.Unmarshal(raw, &msg); err == nil && msg.OSV != nil {
			// Optimization: only keep what we need from OSV to save memory
			details := msg.OSV.Details
			if len(details) > 512 {
				details = details[:512] + "... (truncated)"
			}
			// Ensure strings are copied and interned
			id := intern(msg.OSV.ID)
			osvs[id] = &OSV{
				ID:        id,
				Aliases:   internStrings(msg.OSV.Aliases, intern),
				Summary:   intern(msg.OSV.Summary),
				Details:   intern(details),
				Published: msg.OSV.Published,
				Modified:  msg.OSV.Modified,
			}
			msg.OSV = nil
		}
	}
}

// stdlibModule is govulncheck's pseudo-module for Go standard-library
// advisories. Such findings are not "another module's" dependency advisory,
// so they are kept rather than filtered out by the module-attribution check.
const stdlibModule = "stdlib"

func (s *Scanner) processFinding(raw []byte, findings *[]domain.VulnerabilityFinding, findingIndex map[string]int, reachableIDs map[string]bool, intern func(string) string, scannedModule string) {
	if !bytes.Contains(raw, []byte("\"finding\":")) {
		return
	}
	// Reachability pre-check: only process findings with a non-empty trace
	// containing "function" or "symbol" (legacy/mock)
	if !bytes.Contains(raw, []byte("\"function\"")) && !bytes.Contains(raw, []byte("\"symbol\"")) {
		return
	}
	// Find osv ID without full unmarshal
	var osvID string
	osvStart := bytes.Index(raw, []byte("\"osv\":"))
	if osvStart != -1 {
		osvStart += 6
		// skip possible whitespace and find start of ID
		idStart := bytes.IndexByte(raw[osvStart:], '"')
		if idStart != -1 {
			idStart++ // skip opening quote
			idEnd := bytes.IndexByte(raw[osvStart+idStart:], '"')
			if idEnd != -1 {
				// Ensure ID is copied to avoid pinning raw buffer
				osvID = string(append([]byte(nil), raw[osvStart+idStart:osvStart+idStart+idEnd]...))
			}
		}
	}

	if osvID == "" {
		return
	}

	osvID = intern(osvID)
	idx, exists := findingIndex[osvID]

	// Targeted unmarshal of Trace only
	var partial struct {
		Finding struct {
			FixedVersion string          `json:"fixed_version"`
			Trace        json.RawMessage `json:"trace"`
		} `json:"finding"`
	}

	if err := json.Unmarshal(raw, &partial); err != nil || len(partial.Finding.Trace) == 0 {
		return
	}

	var trace []struct {
		Module   string `json:"module"`
		Function string `json:"function"`
		Receiver string `json:"receiver"`
	}
	if err := json.Unmarshal(partial.Finding.Trace, &trace); err != nil || len(trace) == 0 {
		return
	}

	// govulncheck Finding.Trace is ordered from the vulnerable symbol
	// (Trace[0]) up the call stack to the entry point. The vulnerable
	// module and symbol are therefore Trace[0], NOT the caller frames.
	vuln := trace[0]

	// govulncheck analyses the scanned module's whole dependency
	// closure and reports vulnerable dependencies too. A finding belongs to
	// THIS module's record only when the vulnerable module is this module
	// (or the stdlib pseudo-module). A vulnerable dependency gets its own
	// correct record when the walk scans it; attributing it here would be
	// double-counting. When the module is absent (legacy/mock streams) we
	// cannot filter, so we keep the finding.
	if vuln.Module != "" && vuln.Module != stdlibModule && vuln.Module != scannedModule {
		return
	}

	isReachable := vuln.Function != ""
	if !isReachable && bytes.Contains(partial.Finding.Trace, []byte("\"symbol\"")) {
		isReachable = true
	}
	if !isReachable {
		return
	}

	reachableIDs[osvID] = true
	if !exists {
		*findings = append(*findings, domain.VulnerabilityFinding{
			ID:      osvID,
			FixedIn: intern(partial.Finding.FixedVersion),
		})
		idx = len(*findings) - 1
		findingIndex[osvID] = idx
	}

	// record the vulnerable symbol from the vulnerable frame only.
	// Caller frames are the call path, not what the CVE affects. An OSV may
	// affect several symbols, surfaced across separate finding messages, so
	// accumulate distinct vulnerable symbols (bounded by the real count, no
	// arbitrary cap).
	if vuln.Function == "" {
		return
	}
	sym := vuln.Function
	if vuln.Receiver != "" {
		sym = vuln.Receiver + "." + vuln.Function
	}
	sym = intern(sym)
	existing := &(*findings)[idx]
	for _, s := range existing.AffectedSymbols {
		if s == sym {
			return
		}
	}
	existing.AffectedSymbols = append(existing.AffectedSymbols, sym)
}
func (s *Scanner) parseResults(ctx context.Context, r io.Reader, scannedModule string) ([]domain.VulnerabilityFinding, error) {
	var osvs = make(map[string]*OSV)
	// Map OSV ID -> index in findings slice
	findingIndex := make(map[string]int)
	var findings []domain.VulnerabilityFinding
	// Track which vuln IDs have symbol-level (reachable) findings.
	reachableIDs := make(map[string]bool)

	// String interning pool to reduce object count
	internPool := make(map[string]string)
	intern := func(s string) string {
		if s == "" {
			return ""
		}
		if v, ok := internPool[s]; ok {
			return v
		}
		internPool[s] = s
		return s
	}

	count := 0
	buf := make([]byte, 1024*1024) // 1MB buffer for lines
	scanner := bufio.NewScanner(r)
	scanner.Buffer(buf, 10*1024*1024) // Allow up to 10MB lines if needed

	var msg Message
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		count++
		if count%50 == 0 {
			s.logMem(ctx, fmt.Sprintf("parsing_stream_%d", count))
			// Trigger GC periodically during large stream parsing
			runtime.GC()
			if count%100 == 0 {
				debug.FreeOSMemory()
			}
		}

		s.processMessage(raw, &msg, osvs, intern)
		s.processFinding(raw, &findings, findingIndex, reachableIDs, intern, scannedModule)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan govulncheck output: %w", err)
	}
	s.logMem(ctx, "parse_decoded_stream")

	// Post-process: Fill in OSV details and set final reachability
	// We do this at the end because OSV messages might come after Findings
	for i := range findings {
		f := &findings[i]
		if entry, ok := osvs[f.ID]; ok {
			f.Aliases = entry.Aliases
			f.Summary = entry.Summary
			f.Details = entry.Details
			f.PublishedAt = entry.Published
			f.ModifiedAt = entry.Modified
		}
		f.Reachable = &domain.ReachabilityResult{
			IsReachable: reachableIDs[f.ID],
			Confidence:  domain.ConfidenceHigh,
		}
	}
	s.logMem(ctx, "parse_enriched")

	return findings, nil
}

// moduleFindings accumulates the findings attributed to one module during a
// grouped (project-rooted) parse, mirroring the single-module parse state but
// scoped to a coordinate key.
type moduleFindings struct {
	findings []domain.VulnerabilityFinding
	index    map[string]int // osv ID -> index in findings
}

// processFindingGrouped is the project-rooted counterpart to processFinding: it
// keeps every reachable finding and files it under the module that owns the
// vulnerable symbol, instead of filtering to a single scanned module. This is
// what lets one project-rooted scan derive a per-module verdict for the whole
// build. Stdlib advisories are normalised to the {stdlib, ""} key so the caller
// can attribute them to the project root deterministically.
func (s *Scanner) processFindingGrouped(raw []byte, byModule map[coordinate.ModuleCoordinate]*moduleFindings, intern func(string) string) {
	if !bytes.Contains(raw, []byte("\"finding\":")) {
		return
	}
	if !bytes.Contains(raw, []byte("\"function\"")) && !bytes.Contains(raw, []byte("\"symbol\"")) {
		return
	}

	var partial struct {
		Finding struct {
			OSV          string          `json:"osv"`
			FixedVersion string          `json:"fixed_version"`
			Trace        json.RawMessage `json:"trace"`
		} `json:"finding"`
	}
	if err := json.Unmarshal(raw, &partial); err != nil || partial.Finding.OSV == "" || len(partial.Finding.Trace) == 0 {
		return
	}

	var trace []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Function string `json:"function"`
		Receiver string `json:"receiver"`
	}
	if err := json.Unmarshal(partial.Finding.Trace, &trace); err != nil || len(trace) == 0 {
		return
	}

	// Trace[0] is the vulnerable symbol; the module that owns it is where the
	// finding attributes. A frame with no function is a module/package-level
	// finding, not a reached symbol — govulncheck source mode surfaces those
	// separately, so a grouped verdict counts only reachable findings, matching
	// the single-module parse.
	vuln := trace[0]
	if vuln.Function == "" && !bytes.Contains(partial.Finding.Trace, []byte("\"symbol\"")) {
		return
	}

	key := coordinate.ModuleCoordinate{Path: intern(vuln.Module), Version: intern(vuln.Version)}
	if key.Path == domain.StdlibModulePath {
		// Collapse every toolchain-version-tagged stdlib frame onto one key.
		key.Version = ""
	}

	osvID := intern(partial.Finding.OSV)
	mf, ok := byModule[key]
	if !ok {
		mf = &moduleFindings{index: make(map[string]int)}
		byModule[key] = mf
	}
	idx, exists := mf.index[osvID]
	if !exists {
		mf.findings = append(mf.findings, domain.VulnerabilityFinding{
			ID:      osvID,
			FixedIn: intern(partial.Finding.FixedVersion),
			// A finding recorded here was reached from the project's entry
			// points, so its reachability is known-true with high confidence —
			// the project-rooted analysis is the reachability answer.
			Reachable: &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh},
		})
		idx = len(mf.findings) - 1
		mf.index[osvID] = idx
	}

	if vuln.Function == "" {
		return
	}
	sym := vuln.Function
	if vuln.Receiver != "" {
		sym = vuln.Receiver + "." + vuln.Function
	}
	sym = intern(sym)
	existing := &mf.findings[idx]
	for _, s := range existing.AffectedSymbols {
		if s == sym {
			return
		}
	}
	existing.AffectedSymbols = append(existing.AffectedSymbols, sym)
}

// parseResultsByModule parses a project-rooted govulncheck stream, returning the
// reachable findings grouped by the module that owns each vulnerable symbol. It
// is the multi-module counterpart to parseResults; the OSV enrichment and
// deterministic finding order match, so a per-module verdict built from this map
// is identical to what a coordinate scan of that module would report for the
// same reachable findings.
func (s *Scanner) parseResultsByModule(ctx context.Context, r io.Reader) (map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding, error) {
	osvs := make(map[string]*OSV)
	byModule := make(map[coordinate.ModuleCoordinate]*moduleFindings)

	internPool := make(map[string]string)
	intern := func(s string) string {
		if s == "" {
			return ""
		}
		if v, ok := internPool[s]; ok {
			return v
		}
		internPool[s] = s
		return s
	}

	count := 0
	buf := make([]byte, 1024*1024)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(buf, 10*1024*1024)

	var msg Message
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		count++
		if count%50 == 0 {
			s.logMem(ctx, fmt.Sprintf("parsing_project_stream_%d", count))
			runtime.GC()
			if count%100 == 0 {
				debug.FreeOSMemory()
			}
		}
		s.processMessage(raw, &msg, osvs, intern)
		s.processFindingGrouped(raw, byModule, intern)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan govulncheck output: %w", err)
	}

	out := make(map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding, len(byModule))
	for coord, mf := range byModule {
		for i := range mf.findings {
			f := &mf.findings[i]
			if entry, ok := osvs[f.ID]; ok {
				f.Aliases = entry.Aliases
				f.Summary = entry.Summary
				f.Details = entry.Details
				f.PublishedAt = entry.Published
				f.ModifiedAt = entry.Modified
			}
		}
		domain.SortFindings(mf.findings)
		out[coord] = mf.findings
	}
	return out, nil
}

func internStrings(s []string, intern func(string) string) []string {
	if s == nil {
		return nil
	}
	res := make([]string, len(s))
	for i, v := range s {
		res[i] = intern(v)
	}
	return res
}
