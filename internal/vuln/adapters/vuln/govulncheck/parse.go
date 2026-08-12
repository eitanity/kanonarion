package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
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
	// Withdrawn is the OSV top-level retraction timestamp, absent on a live
	// advisory. govulncheck emits the whole advisory entry in its OSV message, so
	// the retraction was always on the wire; this struct simply did not read it,
	// and a stream-derived finding for a retracted advisory therefore reached a
	// verdict as though the advisory still stood.
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	// References are the advisory's own links, each an OSV {type, url} pair.
	// govulncheck emits the whole advisory entry in its OSV message, so these
	// were on the wire for the same reason the retraction timestamp was, and were
	// discarded at decode in the same way. Measured on a govulncheck -format json
	// run: 233 of 233 OSV messages carried a non-empty references array.
	//
	// Reading them here is what keeps the two producing routes saying the same
	// thing about one advisory. A finding reported by the source analysis wins
	// over the coordinate match that would otherwise have supplied its references,
	// so without this the same advisory carried its links on a metadata-only
	// record and none on an analysed one.
	References []Reference `json:"references,omitempty"`
	// Affected is the advisory's per-module-path block, read only on decode. It
	// is projected onto NamesSymbolsByPath and then dropped, because the retained
	// copy of an OSV message is deliberately minimal.
	Affected []Affected `json:"affected,omitempty"`
	// NamesSymbolsByPath answers, for each module path this advisory names,
	// whether that entry carries a symbol list. It is derived on decode rather
	// than kept as the raw block: a finding needs one boolean per path, and a
	// large stream carries hundreds of advisories.
	//
	// Absence of a path means the advisory said nothing about it, which is not
	// the same as naming it with no symbols; the two are kept distinct so a
	// finding never records an advisory fact that was not read.
	NamesSymbolsByPath map[string]bool `json:"-"`
}

// Reference is one entry of an advisory's references array, kept whole: the
// type is what separates a FIX commit from a WEB mention.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected is one OSV affected-package block, reduced to the two things a
// finding reads from it: which module path it is about, and whether it names
// any symbol within that path.
type Affected struct {
	Package struct {
		Name string `json:"name"`
	} `json:"package"`
	EcosystemSpecific struct {
		Imports []struct {
			Symbols []string `json:"symbols"`
		} `json:"imports"`
	} `json:"ecosystem_specific"`
}

// NamesSymbols reports whether this affected block names at least one symbol.
// An entry with import blocks but no symbols in them names none: govulncheck
// treats such a path as vulnerable in its entirety, which is exactly the case
// that has no symbol for a route to reach.
func (a Affected) NamesSymbols() bool {
	for _, imp := range a.EcosystemSpecific.Imports {
		if len(imp.Symbols) > 0 {
			return true
		}
	}
	return false
}

// namesSymbolsByPath projects the affected blocks onto one boolean per module
// path. A path named by several blocks counts as naming symbols when any of
// them does.
func namesSymbolsByPath(affected []Affected, intern func(string) string) map[string]bool {
	if len(affected) == 0 {
		return nil
	}
	out := make(map[string]bool, len(affected))
	for _, a := range affected {
		if a.Package.Name == "" {
			continue
		}
		p := intern(a.Package.Name)
		out[p] = out[p] || a.NamesSymbols()
	}
	return out
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

// newInternPool returns a string-interning function that collapses the many
// repeated module paths, versions and symbol names a govulncheck stream carries
// onto one copy each, so parsing a large stream does not allocate a distinct
// string per occurrence.
func newInternPool() func(string) string {
	pool := make(map[string]string)
	return func(s string) string {
		if s == "" {
			return ""
		}
		if v, ok := pool[s]; ok {
			return v
		}
		pool[s] = s
		return s
	}
}

// streamMessages frames a govulncheck -json stream into whole messages and hands
// each one, complete, to fn.
//
// Framing is by JSON value, not by newline. govulncheck writes its messages
// indent-formatted: a single finding message spans dozens of lines and no line
// carries a whole message. Every finding parser here opens with byte-level gates
// that must see the message as one unit — `"finding":` together with
// `"function"` — and an OSV message is only decodable whole. Read line by line,
// those gates can never match: on a real project stream, 10 finding messages
// produced 10 lines containing `"finding":` and 73 lines containing
// `"function"`, and zero lines containing both. Every finding was silently
// discarded and a vulnerable build parsed as clean. A json.Decoder over the
// concatenated message stream restores the unit the parsers were written for.
//
// A decode error is returned rather than swallowed: a truncated stream is a
// parse that saw less than govulncheck emitted, which is exactly the condition
// that must never be reported as a clean verdict. Callers classify a non-zero
// govulncheck exit first, so a stream cut short by a failing scan surfaces as
// that failure rather than as a parse error.
func (s *Scanner) streamMessages(ctx context.Context, r io.Reader, memLabel string, fn func(raw []byte)) error {
	dec := json.NewDecoder(r)
	count := 0
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode govulncheck message %d: %w", count+1, err)
		}
		if len(raw) == 0 {
			continue
		}
		count++
		if count%50 == 0 {
			s.logMem(ctx, fmt.Sprintf("%s_%d", memLabel, count))
			// Trigger GC periodically during large stream parsing.
			runtime.GC()
			if count%100 == 0 {
				debug.FreeOSMemory()
			}
		}
		fn(raw)
	}
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
				ID:                 id,
				Aliases:            internStrings(msg.OSV.Aliases, intern),
				Summary:            intern(msg.OSV.Summary),
				Details:            intern(details),
				Published:          msg.OSV.Published,
				Modified:           msg.OSV.Modified,
				Withdrawn:          msg.OSV.Withdrawn,
				References:         internReferences(msg.OSV.References, intern),
				NamesSymbolsByPath: namesSymbolsByPath(msg.OSV.Affected, intern),
			}
			msg.OSV = nil
		}
	}
}

// stdlibModule is govulncheck's pseudo-module for Go standard-library
// advisories. Such findings are not "another module's" dependency advisory,
// so they are kept rather than filtered out by the module-attribution check.
const stdlibModule = "stdlib"

// traceFrame is govulncheck's trace frame. Every field it publishes that names
// a hop is read: the module AND its version, the package, the receiver and the
// function. Two local copies of this struct used to exist, one dropping the
// version and one dropping the package, which is how the route came to be
// unrecoverable from a stream that carried it in full.
type traceFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

// routeFromTrace turns govulncheck's trace into a route ordered ENTRY POINT
// FIRST. govulncheck emits it the other way round — Trace[0] is the vulnerable
// symbol and the frames above it are its callers — and the stored order is
// normalised here so no consumer has to know which analyser produced a route in
// order to read it.
//
// A frame with no function is kept. It is a module- or package-level hop rather
// than a named call, and dropping it would silently shorten the route across
// exactly the boundary a reader most wants to see.
// isPackageInitFrame reports whether f names a package-initialisation function
// rather than a call a program made.
//
// The Go compiler synthesises one such function per package and names it "init";
// where a package has several initialisation bodies they are "init#1", "init#2"
// and so on, and older toolchains emitted "init.0". None of them is a symbol any
// caller wrote: the "call" is the linker running package initialisation because
// the package is in the build.
func isPackageInitFrame(f traceFrame) bool {
	fn := f.Function
	if fn == "init" {
		return true
	}
	rest, ok := strings.CutPrefix(fn, "init")
	if !ok || rest == "" {
		return false
	}
	if rest[0] != '#' && rest[0] != '.' {
		return false
	}
	for _, c := range rest[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(rest) > 1
}

// traceIsPackageInitOnly reports whether every frame of a govulncheck trace is a
// package-initialisation frame.
//
// Such a trace is not a route and must never be recorded as one. When an advisory
// entry names no symbols for a module path, govulncheck treats the whole package
// as vulnerable, and the only thing it can then report is that the package's own
// init ran — which follows from the package being linked into the build, not from
// anything calling the vulnerable code. Measured on a live advisory, that trace is
// three hops of "init" from the project to github.com/golang-jwt/jwt, and ingesting
// it as a route reported the coordinate reachable at high confidence beside a
// sibling coordinate whose route genuinely ended at the advisory's named symbol.
// A reader could not tell the two apart.
//
// A trace with even one real call frame is a route: initialisation code does call
// ordinary functions, and a path from an init frame into the vulnerable symbol is
// a path that runs.
func traceIsPackageInitOnly(trace []traceFrame) bool {
	if len(trace) == 0 {
		return false
	}
	for _, f := range trace {
		if !isPackageInitFrame(f) {
			return false
		}
	}
	return true
}

func routeFromTrace(trace []traceFrame, intern func(string) string) domain.ReachabilityRoute {
	route := make(domain.ReachabilityRoute, 0, len(trace))
	for _, f := range trace {
		route = append(route, domain.ReachabilityFrame{
			ModulePath:    intern(f.Module),
			ModuleVersion: intern(f.Version),
			Package:       intern(f.Package),
			Receiver:      intern(f.Receiver),
			Symbol:        intern(f.Function),
		})
	}
	return route.Reverse()
}

// findingMeta is the per-advisory state the single-module parse accumulates
// across the several finding messages govulncheck emits for one advisory. It
// replaces a bare "is this reachable" boolean, which could not distinguish a
// symbol that was reached from a package that was merely linked.
type findingMeta struct {
	// symbolReached is true once a trace named a real call into the vulnerable
	// code. It is the reachability answer.
	symbolReached bool
	// packageInitOnly is true once a trace arrived whose every frame was a
	// package-initialisation frame. On its own it means the vulnerable package is
	// in the build and nothing more.
	packageInitOnly bool
	// vulnModule is the module path owning the vulnerable frame, which is the
	// path whose advisory entry decides whether any symbol was ever named. It is
	// not always the scanned module: a stdlib advisory is kept under the stdlib
	// pseudo-module.
	vulnModule string
}

func (s *Scanner) processFinding(raw []byte, findings *[]domain.VulnerabilityFinding, findingIndex map[string]int, meta map[string]*findingMeta, routes map[string][]domain.ReachabilityRoute, intern func(string) string, scannedModule string) {
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

	var trace []traceFrame
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

	// A trace of nothing but package-initialisation frames is package linkage, not
	// a route: the finding is kept — the module is still affected — but no route is
	// recorded, no symbol is taken from it, and the reachability answer stays
	// undetermined at symbol level rather than claiming the vulnerable code ran.
	initOnly := traceIsPackageInitOnly(trace)

	m := meta[osvID]
	if m == nil {
		m = &findingMeta{vulnModule: intern(vuln.Module)}
		meta[osvID] = m
	}
	if initOnly {
		m.packageInitOnly = true
	} else {
		m.symbolReached = true
		// The route this finding was reached by. Accumulated per advisory because
		// govulncheck emits one finding message per reached symbol, so an OSV
		// affecting several symbols arrives as several traces and each is a real
		// route to it.
		routes[osvID] = append(routes[osvID], routeFromTrace(trace, intern))
	}
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
	//
	// "init" is never one of them. No advisory names a package's initialiser as an
	// affected symbol; it appears here only because govulncheck had no named symbol
	// to report and fell back to saying the package was initialised. Recording it
	// put a symbol in the record that the advisory never named, and sent the
	// call-graph analyser off to search for it.
	if vuln.Function == "" || initOnly {
		return
	}
	sym := vuln.Function
	if vuln.Receiver != "" {
		sym = vuln.Receiver + "." + vuln.Function
	}
	sym = intern(sym)
	existing := &(*findings)[idx]
	if slices.Contains(existing.AffectedSymbols, sym) {
		return
	}
	existing.AffectedSymbols = append(existing.AffectedSymbols, sym)
}
func (s *Scanner) parseResults(ctx context.Context, r io.Reader, scannedModule string, mode domain.ScanMode) ([]domain.VulnerabilityFinding, error) {
	var osvs = make(map[string]*OSV)
	// Map OSV ID -> index in findings slice
	findingIndex := make(map[string]int)
	var findings []domain.VulnerabilityFinding
	// Per-advisory parse state: whether a symbol was reached, whether only
	// package initialisation was seen, and which module owns the vulnerable frame.
	meta := make(map[string]*findingMeta)
	// Routes reached per advisory, keyed by OSV ID until the findings are
	// enriched below.
	routes := make(map[string][]domain.ReachabilityRoute)

	intern := newInternPool()

	var msg Message
	if err := s.streamMessages(ctx, r, "parsing_stream", func(raw []byte) {
		s.processMessage(raw, &msg, osvs, intern)
		s.processFinding(raw, &findings, findingIndex, meta, routes, intern, scannedModule)
	}); err != nil {
		return nil, err
	}
	s.logMem(ctx, "parse_decoded_stream")

	// Post-process: Fill in OSV details and set final reachability
	// We do this at the end because OSV messages might come after Findings
	for i := range findings {
		f := &findings[i]
		m := meta[f.ID]
		if m == nil {
			// Unreachable in practice: a finding exists only because processFinding
			// recorded meta for it first. An empty meta rather than a nil deref keeps
			// the parse from crashing on a shape nothing produces.
			m = &findingMeta{}
		}
		applyOSV(f, osvs[f.ID], m.vulnModule)
		// A verdict reached without a symbol route says so. Confidence Unknown is
		// the store's existing "not determined" value, and it is what the read side
		// already distinguishes from a searched negative; reporting High here would
		// carry a package-linkage observation at the same weight as a call path.
		confidence := domain.ConfidenceHigh
		if !m.symbolReached {
			confidence = domain.ConfidenceUnknown
		}
		f.Reachable = &domain.ReachabilityResult{
			IsReachable: m.symbolReached,
			Confidence:  confidence,
			Routes:      routes[f.ID],
			// Stamped on every answer, reachable or not: a binary-mode "not
			// reachable" is a symbol-table result and a source-mode one is a call
			// graph result, and nothing downstream can tell them apart otherwise.
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: domain.AnalyserGovulncheck,
				Fidelity: string(mode),
			},
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
func (s *Scanner) processFindingGrouped(raw []byte, byModule map[coordinate.ModuleCoordinate]*moduleFindings, intern func(string) string, mode domain.ScanMode) {
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

	var trace []traceFrame
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

	var key coordinate.ModuleCoordinate
	if intern(vuln.Module) == domain.StdlibModulePath {
		// Collapse every toolchain-version-tagged stdlib frame onto one key.
		key = coordinate.NewStdlibCoordinate()
	} else {
		k, err := coordinate.NewModuleCoordinate(intern(vuln.Module), intern(vuln.Version))
		if err != nil {
			// The finding names no module this scan can attribute it to. Before the
			// key was validated such a frame still produced an entry, under a key no
			// caller ever looks up; dropping it here loses nothing that was reachable.
			return
		}
		key = k
	}

	osvID := intern(partial.Finding.OSV)
	mf, ok := byModule[key]
	if !ok {
		mf = &moduleFindings{index: make(map[string]int)}
		byModule[key] = mf
	}

	// A trace of nothing but package-initialisation frames is package linkage, not
	// a route. The finding is still filed against the module — the coordinate match
	// stands — but it carries no route and no reachable claim.
	initOnly := traceIsPackageInitOnly(trace)

	idx, exists := mf.index[osvID]
	if !exists {
		mf.findings = append(mf.findings, domain.VulnerabilityFinding{
			ID:      osvID,
			FixedIn: intern(partial.Finding.FixedVersion),
			// Opened undetermined and upgraded below by the first trace that names a
			// real call. A finding whose every trace is package initialisation stays
			// undetermined at symbol level: the project-rooted analysis observed that
			// the vulnerable package is in the build, which is not a reachability
			// answer about the code the advisory is about.
			Reachable: &domain.ReachabilityResult{
				IsReachable: false,
				Confidence:  domain.ConfidenceUnknown,
				DerivedBy: domain.ReachabilityDerivation{
					Analyser: domain.AnalyserGovulncheck,
					Fidelity: string(mode),
				},
			},
		})
		idx = len(mf.findings) - 1
		mf.index[osvID] = idx
	}

	if initOnly {
		return
	}

	// The route this advisory was reached by, from the project's entry point
	// down to the vulnerable symbol, with the module version at every hop. This
	// is the answer to "which of my dependencies drags this in", and until it was
	// kept the store held only the two ends of it.
	//
	// Accumulated rather than replaced: govulncheck emits one finding message per
	// reached symbol, so an advisory affecting several symbols arrives as several
	// traces and each is a real route to it. A real route also settles the verdict
	// for good — one genuine call path is not weakened by a sibling trace that only
	// showed the package being initialised.
	res := mf.findings[idx].Reachable
	res.IsReachable = true
	res.Confidence = domain.ConfidenceHigh
	res.Routes = append(res.Routes, routeFromTrace(trace, intern))

	if vuln.Function == "" {
		return
	}
	sym := vuln.Function
	if vuln.Receiver != "" {
		sym = vuln.Receiver + "." + vuln.Function
	}
	sym = intern(sym)
	existing := &mf.findings[idx]
	if slices.Contains(existing.AffectedSymbols, sym) {
		return
	}
	existing.AffectedSymbols = append(existing.AffectedSymbols, sym)
}

// parseResultsByModule parses a project-rooted govulncheck stream, returning the
// reachable findings grouped by the module that owns each vulnerable symbol. It
// is the multi-module counterpart to parseResults; the OSV enrichment and
// deterministic finding order match, so a per-module verdict built from this map
// is identical to what a coordinate scan of that module would report for the
// same reachable findings.
func (s *Scanner) parseResultsByModule(ctx context.Context, r io.Reader, mode domain.ScanMode) (map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding, error) {
	osvs := make(map[string]*OSV)
	byModule := make(map[coordinate.ModuleCoordinate]*moduleFindings)

	intern := newInternPool()

	var msg Message
	if err := s.streamMessages(ctx, r, "parsing_project_stream", func(raw []byte) {
		s.processMessage(raw, &msg, osvs, intern)
		s.processFindingGrouped(raw, byModule, intern, mode)
	}); err != nil {
		return nil, err
	}

	out := make(map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding, len(byModule))
	for coord, mf := range byModule {
		for i := range mf.findings {
			applyOSV(&mf.findings[i], osvs[mf.findings[i].ID], coord.Path())
		}
		domain.SortFindings(mf.findings)
		out[coord] = mf.findings
	}
	return out, nil
}

// applyOSV copies the advisory-level facts of entry onto f. Both parse paths call
// it so neither can grow a field the other lacks — the retraction timestamp in
// particular, since a finding missing it is counted as a live one.
//
// modulePath is the path whose affected entry decides whether the advisory named
// any symbol for this finding. It is read here rather than at ingest because an
// OSV message may arrive after the findings that reference it.
//
// A nil entry means the stream carried findings for an advisory whose OSV message
// never arrived; f keeps its bare ID and fixed version, and no advisory fact is
// invented for it.
func applyOSV(f *domain.VulnerabilityFinding, entry *OSV, modulePath string) {
	if entry == nil {
		return
	}
	// Only an entry that actually names this path says anything about it. A path
	// the advisory never mentions leaves the field false, so "no symbols named"
	// is never recorded from silence.
	if named, ok := entry.NamesSymbolsByPath[modulePath]; ok && !named {
		f.AdvisoryNamesNoSymbols = true
	}
	f.Aliases = entry.Aliases
	f.References = advisoryReferences(entry.References)
	f.Summary = entry.Summary
	f.Details = entry.Details
	f.PublishedAt = entry.Published
	f.ModifiedAt = entry.Modified
	if entry.Withdrawn != nil {
		f.WithdrawnAt = *entry.Withdrawn
	}
}

// advisoryReferences projects the stream's references onto the domain pair,
// preserving a nil as nil so a finding for an advisory that published none does
// not put an empty array on the sealed wire.
//
// Nothing is filtered by type: a reference type this build does not recognise is
// still what the advisory published.
func advisoryReferences(refs []Reference) []domain.AdvisoryReference {
	if refs == nil {
		return nil
	}
	out := make([]domain.AdvisoryReference, 0, len(refs))
	for _, r := range refs {
		out = append(out, domain.AdvisoryReference{Type: r.Type, URL: r.URL})
	}
	return out
}

// internReferences interns both halves of every reference. A large stream
// carries hundreds of advisories and reference types repeat across all of them.
func internReferences(refs []Reference, intern func(string) string) []Reference {
	if refs == nil {
		return nil
	}
	out := make([]Reference, len(refs))
	for i, r := range refs {
		out[i] = Reference{Type: intern(r.Type), URL: intern(r.URL)}
	}
	return out
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
