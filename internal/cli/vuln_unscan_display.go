package cli

import (
	"slices"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// sortUnscanReasons orders reason codes lexically, for the tail of the roll-up
// that AllUnscanReasons does not cover.
func sortUnscanReasons(rs []vuldomain.UnscanReason) {
	slices.Sort(rs)
}

// unscanDisplay is the human presentation of one UnscanReason: the label that
// replaces a bare "Unscannable" on a per-module line, the heading of the
// end-of-run roll-up section that collects modules carrying that reason, the
// explanation of what that category means, and an optional next-step direction.
//
// label is the only part that belongs on a per-module line, because it is the
// only part that varies with the module. explanation and hint are properties of
// the reason, identical for every module carrying it, so they are printed once
// per run in the roll-up section — printing them per module produced hundreds of
// byte-identical lines that trained the reader to skim exactly the region where
// the one-off lines live.
//
// hint is set only where an operator action on this host changes the outcome.
// A toolchain or host limitation gets none, because inventing a direction that
// cannot help reads as an instruction and wastes the reader's attention.
// oneFault marks a reason that describes a single fault fanned out across the
// whole build list rather than N independent module problems. ScanWalkUseCase's
// fillProjectFault stamps one project-rooted failure onto every coordinate in
// the walk, so a roll-up that listed each coordinate would report one fact N
// times and read as N findings. Such a section states the fault once and counts
// the modules it took down; the coordinates remain in the per-module progress
// stream, so naming them is redundant here, not lost.
type unscanDisplay struct {
	label       string
	heading     string
	explanation string
	hint        string
	oneFault    bool
}

// metadataOnlyNote and notScannedNote name the two shapes an Unscannable record
// takes, which differ in what the run actually learned about the module.
//
// A module the isolated scanner could not analyse still has its advisory set
// matched by coordinate (ScanModuleUseCase routes it through scanMetadataOnly),
// so the verdict is real but carries no reachability. A module that was never
// fetched or never reached — a local replace, or a project-rooted scan that
// could not start — has no advisory match behind it at all. Labelling both
// "Metadata-only" would claim a match that the second shape never performed.
const (
	metadataOnlyNote = "Metadata-only"
	notScannedNote   = "Not scanned"
)

// unscanDisplays maps every UnscanReason to its display treatment. It must be
// exhaustive over domain.AllUnscanReasons: a reason with no entry renders
// through unscanDisplayFor's loud fallback rather than silently, and
// TestUnscanDisplays_CoversEveryReason fails so the gap is closed at test time
// instead of being discovered in a scan log.
var unscanDisplays = map[vuldomain.UnscanReason]unscanDisplay{
	vuldomain.UnscanReasonVersionNotInToolchain: {
		label:       metadataOnlyNote + " (version not in project build)",
		heading:     metadataOnlyNote + " — version not in project build",
		explanation: "scanned in isolation these modules resolve a dependency version the project's build never selected; advisories matched, reachability not computed here",
		// The only reason with a direction: the module is analysable, just not in
		// isolation, and the whole-build analysis answers the question properly.
		hint: reachabilityLocalHint,
	},
	vuldomain.UnscanReasonVersionNotInToolchainUnverified: {
		label:   metadataOnlyNote + " (offline resolution failed, version unidentified)",
		heading: metadataOnlyNote + " — offline resolution failed, version could not be identified",
		explanation: "an offline module lookup failed but the toolchain error named no version, " +
			"so whether these modules reach outside the project build or the scan cache is incomplete is unverified; " +
			"advisories matched, reachability not computed here",
		// The whole-build analysis both resolves reachability and, by rooting at
		// the project, avoids the isolated re-resolution that produced this at all.
		hint: reachabilityLocalHint,
	},
	vuldomain.UnscanReasonPackageDeclarationsMissing: {
		label:   metadataOnlyNote + " (no buildable files for this toolchain)",
		heading: metadataOnlyNote + " — no buildable files for this toolchain",
	},
	vuldomain.UnscanReasonCHeadersMissing: {
		label:   metadataOnlyNote + " (needs C headers absent on this host)",
		heading: metadataOnlyNote + " — needs C headers absent on this host",
	},
	vuldomain.UnscanReasonGeneratedAssets: {
		label:   metadataOnlyNote + " (module zip lacks generated sources)",
		heading: metadataOnlyNote + " — module zip lacks generated sources",
	},
	vuldomain.UnscanReasonGoWorkMonorepo: {
		label:   metadataOnlyNote + " (go.work siblings absent from the module zip)",
		heading: metadataOnlyNote + " — go.work siblings absent from the module zip",
	},
	vuldomain.UnscanReasonWorkspaceMode: {
		label:   metadataOnlyNote + " (toolchain entered workspace mode)",
		heading: metadataOnlyNote + " — toolchain entered workspace mode",
	},
	vuldomain.UnscanReasonRelativeReplace: {
		label:   metadataOnlyNote + " (replace points outside the module zip)",
		heading: metadataOnlyNote + " — replace points outside the module zip",
	},
	vuldomain.UnscanReasonWindowsOnly: {
		label:   metadataOnlyNote + " (builds on Windows only)",
		heading: metadataOnlyNote + " — builds on Windows only",
	},
	vuldomain.UnscanReasonMissingGoSum: {
		label:   metadataOnlyNote + " (go.sum entry absent, no network)",
		heading: metadataOnlyNote + " — go.sum entry absent, no network",
	},
	vuldomain.UnscanReasonIncompleteScanCache: {
		label:   metadataOnlyNote + " (version missing from the scan cache)",
		heading: metadataOnlyNote + " — version missing from the scan cache",
	},
	vuldomain.UnscanReasonBuildIncompatible: {
		label:   metadataOnlyNote + " (module does not build on this host)",
		heading: metadataOnlyNote + " — module does not build on this host",
	},
	vuldomain.UnscanReasonOOMKilled: {
		label:   metadataOnlyNote + " (govulncheck was killed, likely OOM)",
		heading: metadataOnlyNote + " — govulncheck was killed, likely OOM",
	},
	vuldomain.UnscanReasonNoGoMod: {
		label:   metadataOnlyNote + " (module zip has no go.mod and none could be synthesised)",
		heading: metadataOnlyNote + " — module zip has no go.mod and none could be synthesised",
	},
	vuldomain.UnscanReasonLocalReplace: {
		label:   notScannedNote + " (local replace — no fetched source)",
		heading: notScannedNote + " — local replace, no fetched source to analyse",
	},
	// The two project-rooted reasons are one fault, not N. A single failure to
	// start the project scan is stamped onto every coordinate in the walk
	// (ScanWalkUseCase.fillProjectFault), so a heading that read as N independent
	// module problems would misstate the cause by the width of the build list.
	vuldomain.UnscanReasonProjectNoGoMod: {
		label:    notScannedNote + " (project directory has no go.mod)",
		heading:  notScannedNote + " — one project-level fault: the project directory has no go.mod, so no module was scanned",
		oneFault: true,
	},
	vuldomain.UnscanReasonProjectDirUnavailable: {
		label:    notScannedNote + " (project directory not accessible)",
		heading:  notScannedNote + " — one project-level fault: the project directory could not be read, so no module was scanned",
		oneFault: true,
	},
	// Not one fault: each module is independently absent from the vendored tree,
	// so the count is a real count of modules the analysed build did not contain.
	vuldomain.UnscanReasonAbsentFromVendor: {
		label:   notScannedNote + " (absent from vendor/ — not in the analysed build)",
		heading: notScannedNote + " — absent from the project's vendor/ tree, so not in the build that was analysed",
	},
	// The four shapes the scan itself records on every run. They had prose and no
	// code, which put them in the fallback bucket for producers the display does
	// not know — a bucket that then printed their reason directly beneath a
	// heading announcing that no reason was recorded. They are the best-known
	// producers there are, so they are named here.
	//
	// The first is Metadata-only: the coordinate WAS matched against the advisory
	// database, and only reachability is missing. The other three are Not
	// scanned in the same sense as local-replace — no source was there to look
	// at — but the advisory match still ran, so they keep the metadata-only
	// wording that says so, and differ in why the source was absent.
	vuldomain.UnscanReasonStdlibMetadata: {
		label:   metadataOnlyNote + " (Go standard library, toolchain-provided)",
		heading: metadataOnlyNote + " — the Go standard library is toolchain-provided, not a fetched module",
		explanation: "the standard library ships with the toolchain rather than as a module artefact, " +
			"so there is nothing in the store to analyse; its advisories are matched by coordinate against the release, " +
			"and reachability into it is answered by a project-rooted run, not by scanning it alone",
	},
	vuldomain.UnscanReasonGoModOnly: {
		label:   metadataOnlyNote + " (only go.mod fetched)",
		heading: metadataOnlyNote + " — only the go.mod was fetched, not the module source",
		explanation: "these modules were fetched for module-graph resolution only, so the store holds their go.mod " +
			"and not their source; advisories matched, reachability not computed here",
	},
	vuldomain.UnscanReasonLocalProjectSource: {
		label:   metadataOnlyNote + " (local project source, never published)",
		heading: metadataOnlyNote + " — local project source: no published artefact exists to fetch",
		// No direction line. The explanation already says where the source is
		// analysed, and the reachability direction is reserved for the
		// isolated-resolution class, whose modules are analysable and simply not in
		// isolation; borrowing it here would widen a narrow, deliberate rule.
		explanation: "the project's own module is unpublished, so no artefact exists for the store to hold; " +
			"its source is on disk and is analysed by a project-rooted run over the project directory",
	},
	vuldomain.UnscanReasonSourceNotInStore: {
		label:   metadataOnlyNote + " (module source not in the store)",
		heading: metadataOnlyNote + " — module source is not in the store",
		// No cause is named, because the scan measured none: it found no fetch
		// record and stopped there. A shallow walk is one way to arrive here and a
		// fetch under a retired pipeline generation is another, and stating either
		// would be a guess printed as a finding.
		explanation: "the store holds no fetched source for these coordinates, so only their advisory match could run; " +
			"advisories matched, reachability not computed here",
	},
	// Not scanned, not metadata-only: the advisory match this reason accompanies
	// was never performed in the run's own frame, because the frame never
	// existed. The run asked for an analysis rooted at this module and the
	// toolchain could not load it.
	//
	// oneFault is false. It names exactly one module — the run's root — and the
	// coordinate is the fact the reader needs, so stating it once and hiding
	// which module it was would remove the only useful part.
	vuldomain.UnscanReasonTargetLoadFailed: {
		label:   notScannedNote + " (the target could not be loaded)",
		heading: notScannedNote + " — the walk target could not be loaded, so nothing was rooted at it",
		explanation: "the run asked for an analysis rooted at this module and the toolchain could not load its packages, " +
			"so no call graph was built and this module has no verdict in the run's own frame; " +
			"any per-module verdicts this run reports come from isolated scans, which answer a weaker question",
	},
}

// unscanDisplayFor returns the display treatment for reason.
//
// An unmapped reason does not fall through to a bare status: it names itself,
// loudly, so a reason added without a display entry is legible to the reader who
// meets it rather than being silently rendered as an unexplained "Unscannable".
// The empty reason is a distinct case — a record that recorded no cause at all,
// which older pipeline versions could produce — and says exactly that.
func unscanDisplayFor(reason vuldomain.UnscanReason) unscanDisplay {
	if d, ok := unscanDisplays[reason]; ok {
		return d
	}
	if reason == "" {
		return unscanDisplay{
			label:   "Unscannable (no reason recorded)",
			heading: "Unscannable — no reason recorded",
		}
	}
	return unscanDisplay{
		label:   "Unscannable (" + string(reason) + " — no display mapping)",
		heading: "Unscannable — " + string(reason) + " (no display mapping)",
	}
}

// unscanLabelFor returns the one-line label for a record whose coverage axis is
// Unscannable, preferring the reason code's display treatment and falling back to
// the free-text reason the writer recorded.
//
// The fallback matters because a coverage gap can be recorded as prose without a
// taxonomy code: a module held only as a go.mod, or never fetched at all, records
// "metadata-only: module not fetched" and no reason code, since no analysis was
// attempted for a classifier to categorise. Reporting "no reason recorded" for
// such a record would be false — the reason is right there on it — and only the
// code is missing.
// unscanDisplayForSection returns the display treatment for one roll-up section.
//
// It exists because a section knows one thing unscanDisplayFor cannot: whether
// the records collected under an empty reason code recorded a free-text reason
// anyway. When they did, the section prints that prose immediately under its own
// heading, so a heading announcing that no reason was recorded is denied by its
// own body two lines later. What is missing in that case is the taxonomy code,
// not the reason, and the heading says exactly that.
//
// The bare "no reason recorded" heading survives for the records that really
// carry neither — an older pipeline version's output, or a producer that
// recorded a coverage gap and said nothing about it. That is a different and
// worse state than an uncoded reason, and collapsing the two would hide it.
//
// Both are meant for producers this display does not know. The two the scan
// itself writes on every run — the stdlib note and the metadata-only note —
// carry codes of their own, so the bucket is a fallback rather than a fixture.
func unscanDisplayForSection(reason vuldomain.UnscanReason, details []unscanDetail) unscanDisplay {
	display := unscanDisplayFor(reason)
	if reason == "" && len(details) > 0 {
		display.label = "Unscannable (reason recorded without a structured code)"
		display.heading = "Unscannable — reason recorded without a structured code"
	}
	return display
}

func unscanLabelFor(record vuldomain.VulnerabilityRecord) string {
	if record.UnscanReason == "" && record.UnscannableReason != "" {
		return record.UnscannableReason
	}
	return unscanDisplayFor(record.UnscanReason).label
}

// unscannableRollup accumulates Unscannable coordinates by reason so the run
// can print one section per reason instead of leaving a record in no summary at
// all. Insertion order of first appearance is not used for output: sections are
// printed in AllUnscanReasons order so two runs over the same walk produce the
// same roll-up regardless of scan scheduling.
type unscannableRollup struct {
	byReason map[vuldomain.UnscanReason][]string
	// detailsByReason holds the distinct free-text reasons seen under each reason
	// code, in first-appearance order, with a count each. The scanner's detail
	// text is very often constant across every module carrying a reason ("no
	// go.mod found in module zip", 30 times), so it is collected here and printed
	// once per distinct text rather than once per module. Collecting the distinct
	// set rather than the first text keeps a detail that genuinely varies visible.
	detailsByReason map[vuldomain.UnscanReason][]unscanDetail
}

// unscanDetail is one distinct free-text reason and how many modules carried it.
type unscanDetail struct {
	text  string
	count int
}

func newUnscannableRollup() *unscannableRollup {
	return &unscannableRollup{
		byReason:        map[vuldomain.UnscanReason][]string{},
		detailsByReason: map[vuldomain.UnscanReason][]unscanDetail{},
	}
}

// add records one Unscannable coordinate under its reason, together with the
// record's free-text detail (empty when none was recorded).
func (r *unscannableRollup) add(reason vuldomain.UnscanReason, coord, detail string) {
	r.byReason[reason] = append(r.byReason[reason], coord)
	if detail == "" {
		return
	}
	details := r.detailsByReason[reason]
	for i := range details {
		if details[i].text == detail {
			details[i].count++
			r.detailsByReason[reason] = details
			return
		}
	}
	r.detailsByReason[reason] = append(details, unscanDetail{text: detail, count: 1})
}

func (r *unscannableRollup) empty() bool { return len(r.byReason) == 0 }

// unscannableSection is one printable roll-up section.
type unscannableSection struct {
	display unscanDisplay
	coords  []string
	details []unscanDetail
}

// detailsToPrint returns the distinct scanner texts worth showing for this
// section. A reason with a curated explanation already states the category in
// the heading, and the scanner's own wording of the same thing adds length
// without adding information, so it is dropped there and kept everywhere else —
// where it is the only description the reader gets.
func (s unscannableSection) detailsToPrint() []unscanDetail {
	if s.display.explanation != "" {
		return nil
	}
	return s.details
}

// sections returns the non-empty sections in a stable order: the known reasons
// in AllUnscanReasons order first, then any reason that has no entry in that
// list, sorted, so an unmapped or unknown reason is still printed rather than
// dropped for not being on the list.
func (r *unscannableRollup) sections() []unscannableSection {
	if r == nil || len(r.byReason) == 0 {
		return nil
	}
	out := make([]unscannableSection, 0, len(r.byReason))
	seen := map[vuldomain.UnscanReason]bool{}
	for _, reason := range vuldomain.AllUnscanReasons() {
		seen[reason] = true
		if coords := r.byReason[reason]; len(coords) > 0 {
			out = append(out, unscannableSection{
				display: unscanDisplayForSection(reason, r.detailsByReason[reason]),
				coords:  coords,
				details: r.detailsByReason[reason],
			})
		}
	}
	rest := make([]vuldomain.UnscanReason, 0)
	for reason := range r.byReason {
		if !seen[reason] {
			rest = append(rest, reason)
		}
	}
	sortUnscanReasons(rest)
	for _, reason := range rest {
		out = append(out, unscannableSection{
			display: unscanDisplayForSection(reason, r.detailsByReason[reason]),
			coords:  r.byReason[reason],
			details: r.detailsByReason[reason],
		})
	}
	return out
}

// total returns the number of Unscannable coordinates collected.
func (r *unscannableRollup) total() int {
	n := 0
	for _, coords := range r.byReason {
		n += len(coords)
	}
	return n
}
