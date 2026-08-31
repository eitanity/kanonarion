package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ProvenanceSignal is a single artifact-discoverable contribution-licensing
// signal found in the module zip. Per §3, detection is limited to
// what the zip contains; git history and per-commit DCO trailers are out of
// scope.
type ProvenanceSignal int

const (
	// ProvenanceSignalInboundOutbound means the CONTRIBUTING file declares an
	// inbound=outbound policy: contributions are made under the project license
	// (the GitHub ToS §D.6 default, often stated explicitly).
	ProvenanceSignalInboundOutbound ProvenanceSignal = iota + 1
	// ProvenanceSignalCLARequired means the CONTRIBUTING file declares that
	// contributors must sign a Contributor License Agreement.
	ProvenanceSignalCLARequired
	// ProvenanceSignalDCORequired means the CONTRIBUTING file declares a
	// Developer Certificate of Origin requirement.
	ProvenanceSignalDCORequired
	// ProvenanceSignalAuthorsFile means the module root contains an AUTHORS
	// or AUTHORS.md file.
	ProvenanceSignalAuthorsFile
	// ProvenanceSignalContributorsFile means the module root contains a
	// CONTRIBUTORS or CONTRIBUTORS.md file.
	ProvenanceSignalContributorsFile
	// ProvenanceSignalPatentsFile means the module root contains a PATENTS
	// or PATENTS.md file.
	ProvenanceSignalPatentsFile
)

// String returns the human-readable name of the signal.
func (s ProvenanceSignal) String() string {
	switch s {
	case ProvenanceSignalInboundOutbound:
		return "inbound_outbound"
	case ProvenanceSignalCLARequired:
		return "cla_required"
	case ProvenanceSignalDCORequired:
		return "dco_required"
	case ProvenanceSignalAuthorsFile:
		return "authors_file"
	case ProvenanceSignalContributorsFile:
		return "contributors_file"
	case ProvenanceSignalPatentsFile:
		return "patents_file"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler for ProvenanceSignal. A signal is the
// evidence found in the zip, and the document names it as the text view does
// rather than publishing the constant's ordinal.
func (s ProvenanceSignal) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, "%q", s.String()), nil
}

// UnmarshalJSON implements json.Unmarshaler for ProvenanceSignal. "unknown" is
// refused: String reports it for any value outside the constant block, and no
// signal decodes back from it.
func (s *ProvenanceSignal) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal ProvenanceSignal: %w", err)
	}
	switch str {
	case "inbound_outbound":
		*s = ProvenanceSignalInboundOutbound
	case "cla_required":
		*s = ProvenanceSignalCLARequired
	case "dco_required":
		*s = ProvenanceSignalDCORequired
	case "authors_file":
		*s = ProvenanceSignalAuthorsFile
	case "contributors_file":
		*s = ProvenanceSignalContributorsFile
	case "patents_file":
		*s = ProvenanceSignalPatentsFile
	default:
		return fmt.Errorf("invalid ProvenanceSignal: %q", str)
	}
	return nil
}

// ChainOfTitleConfidence describes how well-evidenced the module's license
// chain of title is, combining contribution-licensing signals with copyright
// extraction results. Per, NotAnalysed and Low (unevidenced) are
// distinct states.
type ChainOfTitleConfidence int

const (
	// ChainOfTitleNotAnalysed is the zero value; provenance extraction has not
	// run. Distinct from Low per.
	ChainOfTitleNotAnalysed ChainOfTitleConfidence = iota
	// ChainOfTitleHigh means at least one contribution-licensing statement was
	// found in the CONTRIBUTING file (inbound=outbound, CLA, or DCO).
	ChainOfTitleHigh
	// ChainOfTitleMedium means copyright was found or
	// AUTHORS/CONTRIBUTORS/PATENTS files are present, but no explicit
	// contribution-licensing statement was found in CONTRIBUTING.
	ChainOfTitleMedium
	// ChainOfTitleLow means neither a copyright holder nor a
	// contribution-licensing statement could be established. The license grant
	// is claimed but unevidenced; per this is never rendered as
	// "validly licensed".
	ChainOfTitleLow
)

// String returns the human-readable name of the confidence level.
func (c ChainOfTitleConfidence) String() string {
	switch c {
	case ChainOfTitleHigh:
		return "high"
	case ChainOfTitleMedium:
		return "medium"
	case ChainOfTitleLow:
		return "low"
	default:
		return "not_analysed"
	}
}

// MarshalJSON implements json.Marshaler for ChainOfTitleConfidence. It is an
// evidence level, not a number, and the ordinal invites arithmetic on it.
func (c ChainOfTitleConfidence) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, "%q", c.String()), nil
}

// UnmarshalJSON implements json.Unmarshaler for ChainOfTitleConfidence.
func (c *ChainOfTitleConfidence) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal ChainOfTitleConfidence: %w", err)
	}
	switch str {
	case "not_analysed":
		*c = ChainOfTitleNotAnalysed
	case "high":
		*c = ChainOfTitleHigh
	case "medium":
		*c = ChainOfTitleMedium
	case "low":
		*c = ChainOfTitleLow
	default:
		return fmt.Errorf("invalid ChainOfTitleConfidence: %q", str)
	}
	return nil
}

// ProvenanceSummary is the contribution-licensing provenance extracted from
// the module zip. It is an additive field on LicenseRecord.
type ProvenanceSummary struct {
	// Signals lists every provenance signal found, sorted by value for
	// determinism.
	Signals    []ProvenanceSignal
	Confidence ChainOfTitleConfidence
}

// HasSignal reports whether s is present.
func (p ProvenanceSummary) HasSignal(s ProvenanceSignal) bool {
	return slices.Contains(p.Signals, s)
}

// hasContributionLicensingStatement reports whether the summary contains any
// explicit contribution-licensing signal (inbound=outbound, CLA, or DCO).
func (p ProvenanceSummary) hasContributionLicensingStatement() bool {
	return p.HasSignal(ProvenanceSignalInboundOutbound) ||
		p.HasSignal(ProvenanceSignalCLARequired) ||
		p.HasSignal(ProvenanceSignalDCORequired)
}

// contributing file name patterns (case-insensitive prefix match after
// stripping the module path prefix).
var contributingNames = []string{
	"contributing", "contributing.md", "contributing.txt", "contributing.rst",
}

var authorsNames = []string{"authors", "authors.md", "authors.txt"}
var contributorsNames = []string{"contributors", "contributors.md", "contributors.txt"}
var patentsNames = []string{"patents", "patents.md", "patents.txt"}

// inboundOutboundRe matches phrases indicating contributions are licensed
// under the project's license by default (inbound = outbound).
var inboundOutboundRe = regexp.MustCompile(
	`(?i)inbound\s*=\s*outbound|` +
		`contributions?\s+(?:are\s+|will\s+be\s+)?licensed\s+under\s+the\s+(?:same|project)|` +
		`(?:submitted?\s+(?:code|contributions?|patches?|pull\s+requests?)|by\s+submitting).*?licensed\s+under|` +
		`agree\s+to\s+(?:license|release)\s+(?:your\s+)?contributions?\s+under`,
)

// claRe matches phrases indicating a Contributor License Agreement is required.
var claRe = regexp.MustCompile(
	`(?i)contributor\s+licen[sc]e\s+agreement|` +
		`\bCLA\b.*(?:required|must\s+sign|sign\s+the|agreement)|` +
		`(?:cla-assistant|cla\s+bot|cla\s+check)`,
)

// dcoRe matches phrases indicating a Developer Certificate of Origin is used.
var dcoRe = regexp.MustCompile(
	`(?i)developer\s+certificate\s+of\s+origin|` +
		`\bDCO\b|` +
		`signed-off-by|` +
		`sign\s+(?:your\s+)?(?:commits?|off)`,
)

// ExtractProvenance scans the module zip entries for contribution-licensing
// provenance signals. modulePrefix is the "path@version/" prefix used in zip
// entry names. names is the full list of entry names; readFile reads a named
// entry and returns (content, found, err).
func ExtractProvenance(
	modulePrefix string,
	names []string,
	readFile func(name string) ([]byte, bool, error),
) ProvenanceSummary {
	signalSet := make(map[ProvenanceSignal]struct{})

	for _, name := range names {
		if !strings.HasPrefix(name, modulePrefix) {
			continue
		}
		relPath := strings.TrimPrefix(name, modulePrefix)

		// Skip vendored and non-root files.
		if provenanceIsVendored(relPath) || !provenanceIsRootLevel(relPath) {
			continue
		}

		lower := strings.ToLower(relPath)

		switch {
		case matchesAny(lower, contributingNames):
			content, found, err := readFile(name)
			if !found || err != nil {
				continue
			}
			text := string(content)
			if inboundOutboundRe.MatchString(text) {
				signalSet[ProvenanceSignalInboundOutbound] = struct{}{}
			}
			if claRe.MatchString(text) {
				signalSet[ProvenanceSignalCLARequired] = struct{}{}
			}
			if dcoRe.MatchString(text) {
				signalSet[ProvenanceSignalDCORequired] = struct{}{}
			}
		case matchesAny(lower, authorsNames):
			signalSet[ProvenanceSignalAuthorsFile] = struct{}{}
		case matchesAny(lower, contributorsNames):
			signalSet[ProvenanceSignalContributorsFile] = struct{}{}
		case matchesAny(lower, patentsNames):
			signalSet[ProvenanceSignalPatentsFile] = struct{}{}
		}
	}

	signals := signalSetToSlice(signalSet)
	summary := ProvenanceSummary{Signals: signals}
	return summary
}

// DeriveProvenanceConfidence combines provenance signals with the copyright
// status to produce a chain-of-title confidence level per.
func DeriveProvenanceConfidence(p ProvenanceSummary, copyright CopyrightStatus) ChainOfTitleConfidence {
	hasContribStatement := p.hasContributionLicensingStatement()
	hasCopyright := copyright == CopyrightStatusFound
	hasPartialEvidence := p.HasSignal(ProvenanceSignalAuthorsFile) ||
		p.HasSignal(ProvenanceSignalContributorsFile) ||
		p.HasSignal(ProvenanceSignalPatentsFile)

	switch {
	case hasContribStatement:
		return ChainOfTitleHigh
	case hasCopyright || hasPartialEvidence:
		return ChainOfTitleMedium
	default:
		return ChainOfTitleLow
	}
}

func provenanceIsVendored(relPath string) bool {
	return strings.HasPrefix(relPath, "vendor/") || strings.Contains(relPath, "/vendor/")
}

func provenanceIsRootLevel(relPath string) bool {
	return !strings.Contains(relPath, "/")
}

func matchesAny(lower string, names []string) bool {
	return slices.Contains(names, lower)
}

func signalSetToSlice(m map[ProvenanceSignal]struct{}) []ProvenanceSignal {
	out := make([]ProvenanceSignal, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	// Sort by signal value for determinism.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
