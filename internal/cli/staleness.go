package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	proxyadapter "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	stalegolist "github.com/eitanity/kanonarion/internal/staleness/adapters/golist"
	staleproxy "github.com/eitanity/kanonarion/internal/staleness/adapters/proxy"
	staleretry "github.com/eitanity/kanonarion/internal/staleness/adapters/proxy/retrying"
	stalesqlite "github.com/eitanity/kanonarion/internal/staleness/adapters/store/sqlite"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	staledomain "github.com/eitanity/kanonarion/internal/staleness/domain"
	staleports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// newStalenessResolver wires the staleness resolver over an already-open ledger.
// ledger may be nil, which makes every lookup live and unwritten.
//
// latest is the port rather than the proxy adapter so the two wirings below can
// be tested for the one thing that distinguishes them: whether the ledger is
// read at all.
func newStalenessResolver(latest staleports.LatestResolver, ledger staleports.Ledger, ttl time.Duration, fresh bool) *staleapp.Resolver {
	return staleapp.NewResolver(latest, ledger, cliClock, ttl, fresh)
}

// newGomodStalenessResolver is the resolver a go.mod-scoped command gets: the
// same one, with the batched latest source wired over the scope it is reporting
// on.
//
// The batch belongs HERE and not inside newProxyLatestResolver because it is a
// different question's shape. `go list -m -u` answers about a build list, in one
// call, from a module directory — none of which a per-path @latest resolver has
// or needs. The two are composed, not substituted: the batch answers the
// same-major latest for the set, and the per-path resolver still answers the
// newer-major probe, which asks about paths that are not in the build list at
// all and which no batched answer can contain.
func newGomodStalenessResolver(latest staleports.LatestResolver, ledger staleports.Ledger,
	ttl time.Duration, fresh bool, gomodPath, goproxy string, coords []staleports.PinnedModule) *staleapp.Resolver {
	return newStalenessResolver(latest, ledger, ttl, fresh).
		WithBatch(stalegolist.New(filepath.Dir(gomodPath), goproxy), coords,
			activeConfig.Staleness.ProbeConcurrency)
}

// pinnedModulesOf splits "path@version" coordinates into the shape the resolver
// needs. The VERSION is carried, not dropped: the newer-major probe cannot plan
// its walk without it, because a +incompatible pin holds its major in the
// version while living at the unsuffixed path.
func pinnedModulesOf(coords []string) []staleports.PinnedModule {
	mods := make([]staleports.PinnedModule, 0, len(coords))
	for _, coord := range coords {
		if at := strings.LastIndex(coord, "@"); at > 0 {
			mods = append(mods, staleports.PinnedModule{Path: coord[:at], Version: coord[at+1:]})
			continue
		}
		mods = append(mods, staleports.PinnedModule{Path: coord})
	}
	return mods
}

// newProxyLatestResolver wraps the module proxy as the port the staleness
// resolver asks for a module's latest version.
//
// The retry decorator goes on the PORT rather than inside the proxy client: the
// probe and the same-major lookup both come through here, so one decorator
// covers every question this context asks, and the fetch and walk paths — which
// have their own retry policies already — are untouched by it. An absent major
// path is not a transient condition and is not retried; see the decorator.
func newProxyLatestResolver(proxy *proxyadapter.Proxy, logger *slog.Logger) staleports.LatestResolver {
	return staleretry.New(staleproxy.New(proxy), logger)
}

// newAuditStalenessResolver builds the resolver behind an audit's latest column.
//
// It takes no fresh parameter. On audit the staleness TTL is what governs that
// column: the subject of `audit --fresh` is the advisory database, and the
// command whose subject IS the latest answer — `latest` — keeps its own --fresh
// for it. Leaving the parameter off is the point; a wiring that could pass it
// is a wiring that will.
func newAuditStalenessResolver(latest staleports.LatestResolver, ledger staleports.Ledger, ttl time.Duration) *staleapp.Resolver {
	return newStalenessResolver(latest, ledger, ttl, false)
}

// The vocabulary for a staleness answer that was NOT measured. It is shared by
// every command that reports staleness — `audit`, `latest` and `fetch` — because
// a reader parsing one of them must not have to learn a second set of words for
// the same absence, and because a per-command vocabulary is how one surface ends
// up rendering an unmeasured row as an affirmative answer while its neighbour
// states the truth.
const (
	// stalenessOfflineNoEntry: a fully offline run (--from-modcache) whose
	// ledger holds no lookup for this module inside the staleness TTL. Nothing
	// was asked and nothing recorded could be served.
	stalenessOfflineNoEntry = "offline_no_ledger_entry"
	// stalenessLookupFailed: the lookup was attempted and failed (proxy error,
	// probe failure with nothing cached behind it).
	stalenessLookupFailed = "lookup_failed"
	// stalenessToolchainPinned: the standard library, whose version is the build
	// toolchain's. There is no proxy "latest" for it, so the question does not
	// apply rather than resolving in the pin's favour.
	stalenessToolchainPinned = "toolchain_pinned"
	// stalenessNotAsked: the question was never put. A `fetch <module>@latest`
	// resolves the newest version and installs it, so there is no pin to compare
	// against; `latest <module>` with no pin is the same shape. "Current" is not
	// the answer to a question nobody asked — it is the absence of one.
	stalenessNotAsked = "not_asked"
)

// stalenessUnmeasuredLabel renders the machine reason as the phrase the tables,
// the coverage line and the fetch note show. An unrecognised reason is passed
// through rather than dropped: a reason nobody has taught this function is still
// more informative than none, and an unstated one still says "unmeasured".
func stalenessUnmeasuredLabel(reason string) string {
	switch reason {
	case "":
		return "unmeasured"
	case stalenessOfflineNoEntry:
		return "unmeasured (offline)"
	case stalenessLookupFailed:
		return "unmeasured (lookup failed)"
	case stalenessToolchainPinned:
		return "unmeasured (toolchain-pinned)"
	case stalenessNotAsked:
		return "unmeasured (not asked)"
	}
	return "unmeasured (" + reason + ")"
}

// stalenessLookup is what an audit row's staleness column is answered by. Two
// implementations satisfy it: the resolver that may ask the proxy, and the
// offline lookup below that may not. Naming the capability as an interface is
// what lets the offline mode be a different ANSWER rather than a skipped column
// silently rendered as the affirmative one.
type stalenessLookup interface {
	Resolve(ctx context.Context, path, pinnedVersion string) (staleapp.Answer, error)
}

// errStalenessOffline reports that an offline run had no recorded lookup it
// could serve for a module. It is not a failure — nothing went wrong and nothing
// is retryable offline — so callers render it as an unmeasured column rather
// than an error line per module.
var errStalenessOffline = errors.New("offline: no staleness lookup inside the TTL")

// offlineStalenessLookup answers the staleness column on a fully offline run
// (--from-modcache) from the ledger alone.
//
// A recorded lookup inside the TTL is a measurement and is served — with the
// answer's own date, so the caller can state its age. Anything else is
// errStalenessOffline. It NEVER writes: an offline run learns no new upstream
// fact, and it never probes, because a probe is a network call and the mode's
// contract is that there are none.
type offlineStalenessLookup struct {
	ledger staleports.Ledger
	clk    staleports.Clock
	ttl    time.Duration
}

func newOfflineStalenessLookup(ledger staleports.Ledger, ttl time.Duration) *offlineStalenessLookup {
	return &offlineStalenessLookup{ledger: ledger, clk: cliClock, ttl: ttl}
}

// Resolve serves path's ledger row when it is inside the TTL.
func (o *offlineStalenessLookup) Resolve(ctx context.Context, path, pinnedVersion string) (staleapp.Answer, error) {
	if o.ledger == nil {
		return staleapp.Answer{}, errStalenessOffline
	}
	rec, found, err := o.ledger.GetStaleness(ctx, path)
	if err != nil {
		return staleapp.Answer{}, fmt.Errorf("reading staleness ledger for %s: %w", path, err)
	}
	if !found || !rec.FreshAt(o.clk.Now(), o.ttl) {
		return staleapp.Answer{}, errStalenessOffline
	}

	out := staledomain.Record{
		ModulePath:        path,
		LatestVersion:     rec.LatestVersion,
		LatestPublishedAt: rec.LatestPublishedAt,
		// The deprecation travels with the latest fact it was recorded beside,
		// and for the same reason: it is part of the answer that lookup gave, so
		// a row served offline states it exactly as the run that recorded it did.
		// A row recorded before the question existed carries Checked false, which
		// says "not established" — never "not deprecated".
		Deprecation: rec.Deprecation,
		LookedUpAt:  rec.LookedUpAt,
	}
	// The stored probe is reusable only when it started at the same major AND, for
	// a pin that asks the republication question, only when the stored row asked
	// it too — the same pair of rules the online resolver applies (see
	// domain.NewerMajor.FromMajor and domain.Republication.Asked). Otherwise it
	// stays unprobed here: MajorProbed false says "not asked", which is what an
	// offline run that cannot probe has to say. A row written before the
	// republication was a separate fact carries the module's own major under
	// newer_major_path, and serving it offline would keep printing the label this
	// change exists to remove.
	pin := pinnedVersion
	if pin == "" {
		pin = out.LatestVersion
	}
	plan := staledomain.PlanProbe(path, pin)
	if rec.NewerMajor.Probed && rec.NewerMajor.FromMajor == plan.Start() {
		if _, asks := plan.SameMajor(); !asks || rec.Republication.Asked {
			out.NewerMajor = rec.NewerMajor
			out.Republication = rec.Republication
		}
	}
	return staleapp.Answer{Record: out, Served: true}, nil
}

// reportOnceLookup states a whole-set failure ONCE.
//
// A batched latest resolution answers for every module in one call, so its
// failure is the same failure for each of them. `audit` reports a failed
// staleness lookup per module and keeps auditing — which is right, the column is
// one of many — but the identical batch refusal printed once per dependency
// buries every other line of the run. The rows still each report unmeasured;
// only the repetition of the reason is dropped.
type reportOnceLookup struct {
	inner    stalenessLookup
	stderr   io.Writer
	reported bool
}

func newReportOnceLookup(inner stalenessLookup, stderr io.Writer) *reportOnceLookup {
	return &reportOnceLookup{inner: inner, stderr: stderr}
}

func (r *reportOnceLookup) Resolve(ctx context.Context, path, pinnedVersion string) (staleapp.Answer, error) {
	ans, err := r.inner.Resolve(ctx, path, pinnedVersion)
	switch {
	case err == nil:
		return ans, nil
	case !errors.Is(err, staleapp.ErrBatchUnavailable):
		return ans, fmt.Errorf("resolving staleness for %s: %w", path, err)
	}
	if !r.reported {
		r.reported = true
		_, _ = fmt.Fprintf(r.stderr, "staleness: the latest column is unmeasured for every module: %v\n", err)
	}
	// The reason is stripped from the per-row error so the caller renders the
	// column as unmeasured without repeating a sentence already printed. The
	// column itself still says nothing was measured, which is the answer.
	return ans, errStalenessBatchReported
}

// errStalenessBatchReported is the per-row stand-in for a whole-set failure that
// has already been stated once. It is still an error — the row is unmeasured —
// and it is deliberately not wrapped around the original, so no caller prints
// the reason a second time.
var errStalenessBatchReported = errors.New("latest unmeasured: the batched resolution failed for the whole set")

// openStalenessLedger opens the store purely for the staleness ledger.
//
// `latest` needs the ledger and nothing else, and building the whole container
// for it would drag in every adapter the command never touches. It goes through
// the same migrated-and-gated door as every other write path, so an older binary
// still refuses a newer store here.
func openStalenessLedger(storeRoot string) (staleports.Ledger, func() error, error) {
	dbHandle, err := openMigratedStore(filepath.Join(storeRoot, "mirror.db"), storeOpenIntent())
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() error {
		if cerr := dbHandle.Close(); cerr != nil {
			return fmt.Errorf("closing database: %w", cerr)
		}
		return nil
	}
	return stalesqlite.New(dbHandle), cleanup, nil
}

// stalenessAsOf renders the lookup time a staleness answer came from.
//
// Every consumer prints it. A cached answer that does not say when it was
// measured is indistinguishable from a live one, and the whole point of dating
// the row is that the reader can tell.
func stalenessAsOf(lookedUpAt time.Time) string {
	if lookedUpAt.IsZero() {
		return ""
	}
	return lookedUpAt.UTC().Format("2006-01-02 15:04 MST")
}

// The labels the two major-line facts render under.
//
// They are constants shared by every command that prints them because the
// distinction between them is the whole point: a build where `latest` says
// "same major republished" and `audit` says "newer major" about the same module
// has contradicted itself, and two copies of a label string is how that starts.
const (
	newerMajorLabel = "newer major"
	// republicationLabel deliberately does not contain the word "major" on its
	// own. The major NUMBER is unchanged here; only the path moved.
	republicationLabel = "same major republished"
	// majorNotProbedClause is what a row says when the newer-major question was
	// not answered. It states the state of the QUESTION, never a guess at the
	// answer: "no newer major" would be a claim nothing measured, and "a newer
	// major may exist" would be an alarm nothing measured either.
	majorNotProbedClause = newerMajorLabel + ": not probed"
)

// majorClause renders one labelled path@version, with the publication date when
// there is one. A zero date prints no date rather than a fabricated one.
func majorClause(label, path, version string, publishedAt time.Time) string {
	if path == "" {
		return ""
	}
	if publishedAt.IsZero() {
		return fmt.Sprintf("%s: %s@%s", label, path, version)
	}
	return fmt.Sprintf("%s: %s@%s (%s)", label, path, version, publishedAt.UTC().Format("2006-01-02"))
}

// majorNotes renders the major-line facts as their own clauses.
//
// Neither is ever folded into the same-major status: "current" and "a newer
// major line exists" are both true at once for a module pinned behind a major
// bump, and merging them reports the module the way this context exists to stop
// reporting it.
//
// The republication comes FIRST when both hold. It is the nearer move — the
// same major number at the path the toolchain expects for it — and for a stuck
// +incompatible pin it is the likelier action; ordering the two-major migration
// ahead of it buries the cheaper answer behind the more alarming one.
//
// sameMajorAnswered says whether this row got a same-major answer at all. It is
// what separates a probe that FAILED from a row nothing was measured for: a
// probe is planned for every module whose latest resolves, so an unprobed row
// with an answer beside it lost that answer, and the row says so. A row with no
// answer at all already renders as unmeasured, and repeating it there would put
// the clause on every offline row in the table.
func majorNotes(rep staledomain.Republication, nm staledomain.NewerMajor, sameMajorAnswered bool) string {
	var parts []string
	if rep.Exists() {
		parts = append(parts, majorClause(republicationLabel, rep.Path, rep.Version, rep.PublishedAt))
	}
	switch {
	case sameMajorAnswered && !nm.Probed:
		// The unanswered question is stated on the ROW. It used to render as
		// nothing at all, which is byte-identical to the recorded negative — so
		// the surface that exists to stop a several-majors-behind module reading
		// as current showed a failed probe and a clean answer the same way. It is
		// appended rather than substituted for the whole note, so a measured
		// republication beside it is still reported.
		parts = append(parts, majorNotProbedClause)
	case nm.Exists():
		parts = append(parts, majorClause(newerMajorLabel, nm.Path, nm.Version, nm.PublishedAt))
	}
	return strings.Join(parts, "; ")
}

// deprecationNote renders the module's own deprecation notice as its own clause.
//
// The notice is REPRODUCED, not interpreted: the words are the author's, the
// successor named is whichever one they named, and kanonarion adds no judgement
// about it and infers no successor from name similarity. The only transformation
// is that the notice's newlines become spaces, because a go.mod deprecation is
// routinely two lines and a table row is one — the characters are otherwise the
// published ones.
//
// A module whose deprecation state is not established renders nothing at all. It
// is not "not deprecated": a per-path @latest lookup cannot see the notice, and
// printing a negative there would state an answer nothing established.
func deprecationNote(dep staledomain.Deprecation) string {
	if !dep.Deprecated() {
		return ""
	}
	return deprecatedLabel + ": " + strings.Join(strings.Fields(dep.Notice), " ")
}

// deprecatedLabel is the phrase the notice is reported under, shared by every
// surface so no two commands name the same fact differently.
const deprecatedLabel = "deprecated by its author"
