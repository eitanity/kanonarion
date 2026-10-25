package domain

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/recordstamp"
)

// TinyGoSourceFile is one file a TinyGo build compiles out of TINYGOROOT/src:
// its slash path under src and the SHA-256 of the installed bytes, hex.
type TinyGoSourceFile struct {
	Path   string
	SHA256 string
}

// TinyGoAnchor names what an installed TinyGo file was compared with.
type TinyGoAnchor string

const (
	// TinyGoAnchorModule is the sumdb-verified module zip of TinyGo's release.
	TinyGoAnchorModule TinyGoAnchor = "module"
	// TinyGoAnchorRelease is the release archive GitHub publishes a digest for.
	TinyGoAnchorRelease TinyGoAnchor = "release"
)

// TinyGoReleaseOutcome is what became of the release archive a TinyGo walk
// consulted for the files its module zip does not carry.
type TinyGoReleaseOutcome string

const (
	// TinyGoReleaseDigestMatched: the archive's SHA-256 equals the published digest.
	TinyGoReleaseDigestMatched TinyGoReleaseOutcome = "digest_matched"
	// TinyGoReleaseDigestMismatch: the archive's SHA-256 is not the published one.
	TinyGoReleaseDigestMismatch TinyGoReleaseOutcome = "digest_mismatch"
	// TinyGoReleaseNoDigest: the release lists the asset with no digest.
	TinyGoReleaseNoDigest TinyGoReleaseOutcome = "no_digest_published"
	// TinyGoReleaseAssetAbsent: the release, or the asset in it, does not exist.
	TinyGoReleaseAssetAbsent TinyGoReleaseOutcome = "asset_absent"
	// TinyGoReleaseUnavailable: the release could not be consulted at all.
	TinyGoReleaseUnavailable TinyGoReleaseOutcome = "unavailable"
)

// TinyGoRelease is one measurement of a TinyGo release archive as the walk
// receives it. Manifest maps a slash path under the archive's src directory to
// the SHA-256 of its bytes; it is set only when the digest matched.
type TinyGoRelease struct {
	Asset           string
	PublishedDigest string
	ObservedDigest  string
	Outcome         TinyGoReleaseOutcome
	Reason          string
	MeasuredAt      time.Time
	Manifest        map[string]string
}

// TinyGoFileDiffers is a compiled file whose installed bytes are not the
// anchor's.
type TinyGoFileDiffers struct {
	Path   string
	Anchor TinyGoAnchor
}

// TinyGoFileNotEstablished is a compiled file no anchor could judge.
type TinyGoFileNotEstablished struct {
	Path   string
	Reason string
}

// TinyGoCustody records whether the TinyGo source a build compiled is the source
// TinyGo released. Each compiled file is counted once: verified by the module,
// verified by the release, differing, or not established. Lists are by path.
type TinyGoCustody struct {
	// Module is TinyGo's module coordinate at the installed release, and
	// ModuleVerification the fetch's verification status of its zip; empty
	// when the zip could not be fetched.
	Module             string
	ModuleVerification string
	// The release fields are empty when no compiled file needed the release.
	ReleaseAsset           string
	ReleaseOutcome         TinyGoReleaseOutcome
	ReleasePublishedDigest string
	ReleaseObservedDigest  string
	ReleaseMeasuredAt      time.Time
	VerifiedByModule       int
	VerifiedByRelease      int
	Differs                []TinyGoFileDiffers
	NotEstablished         []TinyGoFileNotEstablished
}

// TinyGoCustodyInput is what the walk measured for ClassifyTinyGoCustody.
type TinyGoCustodyInput struct {
	Module string
	// ModuleVerification is the fetch's status; ModuleFailure, set instead,
	// says why the zip could not be read.
	ModuleVerification string
	ModuleFailure      string
	// ModuleFiles maps each compiled path present at src/<path> in the module
	// zip to the SHA-256 of the zip's bytes.
	ModuleFiles map[string]string
	// Release is nil when no compiled file is absent from the module zip.
	Release *TinyGoRelease
	Files   []TinyGoSourceFile
}

// AbsentFromModule reports the compiled files the module zip does not carry,
// which are the ones the release archive is consulted for.
func (in TinyGoCustodyInput) AbsentFromModule() []TinyGoSourceFile {
	var out []TinyGoSourceFile
	for _, f := range in.Files {
		if _, ok := in.ModuleFiles[f.Path]; !ok {
			out = append(out, f)
		}
	}
	return out
}

// ClassifyTinyGoCustody judges each compiled file against one anchor: the module
// zip when it carries the path, the release archive otherwise. A file the
// anchor cannot vouch for reads not established, with the reason, and a
// mismatch is a difference to report, never something to pass.
func ClassifyTinyGoCustody(in TinyGoCustodyInput) TinyGoCustody {
	out := TinyGoCustody{Module: in.Module, ModuleVerification: in.ModuleVerification}
	if r := in.Release; r != nil {
		out.ReleaseAsset, out.ReleaseOutcome = r.Asset, r.Outcome
		out.ReleasePublishedDigest, out.ReleaseObservedDigest = r.PublishedDigest, r.ObservedDigest
		out.ReleaseMeasuredAt = r.MeasuredAt
	}
	moduleVerified := fetchdomain.VerificationStatus(in.ModuleVerification).IsVerified()
	for _, f := range in.Files {
		if in.ModuleFailure != "" {
			out.notEstablished(f, "the module zip "+in.Module+" could not be read: "+in.ModuleFailure)
			continue
		}
		if h, ok := in.ModuleFiles[f.Path]; ok {
			switch {
			case !moduleVerified:
				out.notEstablished(f, fmt.Sprintf("the module zip %s is not verified (status %q)", in.Module, in.ModuleVerification))
			case h == f.SHA256:
				out.VerifiedByModule++
			default:
				out.Differs = append(out.Differs, TinyGoFileDiffers{Path: f.Path, Anchor: TinyGoAnchorModule})
			}
			continue
		}
		out.judgeAgainstRelease(f, in.Release)
	}
	out.Sort()
	return out
}

func (c *TinyGoCustody) judgeAgainstRelease(f TinyGoSourceFile, r *TinyGoRelease) {
	switch {
	case r == nil:
		c.notEstablished(f, "absent from the module zip and no release archive was consulted")
	case r.Outcome == TinyGoReleaseDigestMatched:
		h, ok := r.Manifest[f.Path]
		switch {
		case !ok:
			c.notEstablished(f, "absent from both the module zip and the release archive "+r.Asset)
		case h == f.SHA256:
			c.VerifiedByRelease++
		default:
			c.Differs = append(c.Differs, TinyGoFileDiffers{Path: f.Path, Anchor: TinyGoAnchorRelease})
		}
	case r.Outcome == TinyGoReleaseDigestMismatch:
		c.notEstablished(f, fmt.Sprintf("the release archive %s did not match its published digest (published %s, observed %s)",
			r.Asset, r.PublishedDigest, r.ObservedDigest))
	case r.Reason != "":
		c.notEstablished(f, r.Reason)
	default:
		c.notEstablished(f, fmt.Sprintf("the release archive %s: %s", r.Asset, r.Outcome))
	}
}

func (c *TinyGoCustody) notEstablished(f TinyGoSourceFile, reason string) {
	c.NotEstablished = append(c.NotEstablished, TinyGoFileNotEstablished{Path: f.Path, Reason: reason})
}

// Sort orders both lists by path, then by anchor or reason, so the record is a
// function of what was measured and not of the order files were listed in.
func (c *TinyGoCustody) Sort() {
	slices.SortFunc(c.Differs, func(a, b TinyGoFileDiffers) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Anchor, b.Anchor))
	})
	slices.SortFunc(c.NotEstablished, func(a, b TinyGoFileNotEstablished) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reason, b.Reason))
	})
}

// canonicalTinyGoCustody is the fixed-field-order form of TinyGoCustody, in
// sorted JSON-key order. The release fields are omitempty because a walk whose
// compiled files the module zip all carries consulted no release.
type canonicalTinyGoCustody struct {
	Differs                []canonicalTinyGoFileDiffers    `json:"differs"`
	Module                 string                          `json:"module"`
	ModuleVerification     string                          `json:"module_verification"`
	NotEstablished         []canonicalTinyGoNotEstablished `json:"not_established"`
	ReleaseAsset           string                          `json:"release_asset,omitempty"`
	ReleaseMeasuredAt      string                          `json:"release_measured_at,omitempty"`
	ReleaseObservedDigest  string                          `json:"release_observed_digest,omitempty"`
	ReleaseOutcome         string                          `json:"release_outcome,omitempty"`
	ReleasePublishedDigest string                          `json:"release_published_digest,omitempty"`
	VerifiedByModule       int                             `json:"verified_by_module"`
	VerifiedByRelease      int                             `json:"verified_by_release"`
}

type canonicalTinyGoFileDiffers struct {
	Anchor string `json:"anchor"`
	Path   string `json:"path"`
}

// canonicalTinyGoNotEstablished states one reason once, with every path it
// applies to, so a reason shared by every file does not repeat per file.
type canonicalTinyGoNotEstablished struct {
	Paths  []string `json:"paths"`
	Reason string   `json:"reason"`
}

func toCanonicalTinyGoCustody(c *TinyGoCustody) *canonicalTinyGoCustody {
	if c == nil {
		return nil
	}
	sorted := *c
	sorted.Differs = slices.Clone(c.Differs)
	sorted.NotEstablished = slices.Clone(c.NotEstablished)
	sorted.Sort()
	out := &canonicalTinyGoCustody{
		Differs:                []canonicalTinyGoFileDiffers{},
		Module:                 sorted.Module,
		ModuleVerification:     sorted.ModuleVerification,
		NotEstablished:         []canonicalTinyGoNotEstablished{},
		ReleaseAsset:           sorted.ReleaseAsset,
		ReleaseObservedDigest:  sorted.ReleaseObservedDigest,
		ReleaseOutcome:         string(sorted.ReleaseOutcome),
		ReleasePublishedDigest: sorted.ReleasePublishedDigest,
		VerifiedByModule:       sorted.VerifiedByModule,
		VerifiedByRelease:      sorted.VerifiedByRelease,
	}
	if !sorted.ReleaseMeasuredAt.IsZero() {
		out.ReleaseMeasuredAt = recordstamp.Format(sorted.ReleaseMeasuredAt)
	}
	for _, d := range sorted.Differs {
		out.Differs = append(out.Differs, canonicalTinyGoFileDiffers{Anchor: string(d.Anchor), Path: d.Path})
	}
	reasons, byReason := sorted.NotEstablishedByReason()
	for _, r := range reasons {
		out.NotEstablished = append(out.NotEstablished, canonicalTinyGoNotEstablished{Paths: byReason[r], Reason: r})
	}
	return out
}

func fromCanonicalTinyGoCustody(c *canonicalTinyGoCustody) (*TinyGoCustody, error) {
	if c == nil {
		return nil, nil
	}
	out := &TinyGoCustody{
		Module:                 c.Module,
		ModuleVerification:     c.ModuleVerification,
		ReleaseAsset:           c.ReleaseAsset,
		ReleaseOutcome:         TinyGoReleaseOutcome(c.ReleaseOutcome),
		ReleasePublishedDigest: c.ReleasePublishedDigest,
		ReleaseObservedDigest:  c.ReleaseObservedDigest,
		VerifiedByModule:       c.VerifiedByModule,
		VerifiedByRelease:      c.VerifiedByRelease,
	}
	if c.ReleaseMeasuredAt != "" {
		at, err := recordstamp.Parse(c.ReleaseMeasuredAt)
		if err != nil {
			return nil, fmt.Errorf("parsing the TinyGo release measurement time: %w", err)
		}
		out.ReleaseMeasuredAt = at
	}
	for _, d := range c.Differs {
		out.Differs = append(out.Differs, TinyGoFileDiffers{Path: d.Path, Anchor: TinyGoAnchor(d.Anchor)})
	}
	for _, g := range c.NotEstablished {
		for _, p := range g.Paths {
			out.NotEstablished = append(out.NotEstablished, TinyGoFileNotEstablished{Path: p, Reason: g.Reason})
		}
	}
	out.Sort()
	return out, nil
}

// Compiled is how many compiled files the custody judged.
func (c TinyGoCustody) Compiled() int {
	return c.VerifiedByModule + c.VerifiedByRelease + len(c.Differs) + len(c.NotEstablished)
}

// NotEstablishedByReason groups the not-established paths by reason, both
// sorted, so a surface states each reason once.
func (c TinyGoCustody) NotEstablishedByReason() ([]string, map[string][]string) {
	byReason := map[string][]string{}
	for _, n := range c.NotEstablished {
		byReason[n.Reason] = append(byReason[n.Reason], n.Path)
	}
	reasons := make([]string, 0, len(byReason))
	for r, paths := range byReason {
		slices.Sort(paths)
		reasons = append(reasons, r)
	}
	slices.Sort(reasons)
	return reasons, byReason
}

// DiffersFrom is the differing paths judged against anchor, sorted.
func (c TinyGoCustody) DiffersFrom(anchor TinyGoAnchor) []string {
	var out []string
	for _, d := range c.Differs {
		if d.Anchor == anchor {
			out = append(out, d.Path)
		}
	}
	slices.Sort(out)
	return out
}

// Statement says what the custody rests on, from what was reached rather than
// from the route a connected run usually takes.
func (c TinyGoCustody) Statement() string {
	parts := []string{fmt.Sprintf("%d of %d compiled TinyGo file(s) match the module zip %s", c.VerifiedByModule, c.Compiled(), c.Module)}
	if c.ModuleVerification != "" {
		parts[0] += fmt.Sprintf(" (fetch verification %s)", c.ModuleVerification)
	} else {
		parts[0] += " (the module zip could not be read)"
	}
	switch {
	case c.ReleaseAsset == "":
		parts = append(parts, "no release archive was consulted")
	case c.ReleaseOutcome == TinyGoReleaseDigestMatched:
		parts = append(parts, fmt.Sprintf("%d match the release archive %s, whose bytes matched the SHA-256 GitHub publishes for it", c.VerifiedByRelease, c.ReleaseAsset))
	case c.ReleaseOutcome == TinyGoReleaseDigestMismatch:
		parts = append(parts, fmt.Sprintf("the release archive %s did NOT match the SHA-256 GitHub publishes for it, so no file is verified against it", c.ReleaseAsset))
	default:
		parts = append(parts, fmt.Sprintf("no file was checked against the release archive %s (%s)", c.ReleaseAsset, c.ReleaseOutcome))
	}
	parts = append(parts, fmt.Sprintf("%d differ from their anchor", len(c.Differs)), fmt.Sprintf("%d not established", len(c.NotEstablished)))
	return strings.Join(parts, "; ")
}
