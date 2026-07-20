package domain

import (
	"encoding/json"
	"fmt"
)

// ObligationCatalogueVersion identifies the version of the static obligations
// catalogue. Bump deliberately when entries are added or corrected.
const ObligationCatalogueVersion = "1.2.0"

// ObligationStatus distinguishes a researched catalogue entry from an absent one.
// Per, an unknown SPDX identifier must never be treated as "no obligations".
type ObligationStatus int

const (
	// ObligationStatusUnknown means the SPDX identifier has no catalogue entry.
	// Human review is required — never infer "no obligations" from absence.
	ObligationStatusUnknown ObligationStatus = iota
	// ObligationStatusKnown means the catalogue has a researched entry.
	ObligationStatusKnown
)

// String returns the human-readable name of the status.
func (s ObligationStatus) String() string {
	if s == ObligationStatusKnown {
		return "known"
	}
	return "unknown"
}

// Obligations describes the conditions a license imposes on users and distributors.
// Boolean fields are only meaningful when Status == ObligationStatusKnown.
type Obligations struct {
	// Status indicates whether the SPDX identifier is in the catalogue.
	Status ObligationStatus

	// IncludeNotice: retain and distribute the original copyright notice / attribution text.
	IncludeNotice bool
	// IncludeLicenseText: include the complete license text in all distributions.
	IncludeLicenseText bool
	// StateChanges: document modifications made to the original source files.
	StateChanges bool
	// DiscloseSource: make corresponding source code available to recipients.
	DiscloseSource bool
	// SameLicense: copyleft propagation strength. CopyleftNone for permissive licenses.
	SameLicense CopyleftStrength
	// NetworkUseTrigger: providing the software over a network counts as distribution
	// and triggers copyleft and source-disclosure obligations (AGPL §13).
	NetworkUseTrigger bool
	// NoTrademarkUse: prohibits use of the licensor's name or marks to endorse derived works.
	NoTrademarkUse bool
	// ExplicitPatentGrant: includes an express grant of patent rights from contributors.
	ExplicitPatentGrant bool
}

// obligationsCatalogue maps SPDX identifiers to their curated obligation set.
// Dataset version: ObligationCatalogueVersion. Source: SPDX license list +
// choosealicense.com conditions data.
var obligationsCatalogue = map[string]Obligations{
	// --- Permissive ---

	"MIT": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
	},
	"ISC": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
	},
	"BSD-2-Clause": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
	},
	"BSD-3-Clause": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		NoTrademarkUse:     true, // clause 3: no endorsement using org name
	},
	"BSD-4-Clause": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
	},
	// BSD-2-Clause-Views (formerly BSD-2-Clause-FreeBSD): same conditions as
	// BSD-2-Clause plus a non-endorsement clause for views/opinions.
	"BSD-2-Clause-Views": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
	},
	"Apache-2.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true, // §4(b): state changes made to original files
		NoTrademarkUse:      true, // §6: no trademark use
		ExplicitPatentGrant: true, // §3: express patent licence grant
	},
	"Zlib": {
		Status:        ObligationStatusKnown,
		IncludeNotice: true, // source must retain notice
		StateChanges:  true, // altered source must be marked as changed
	},
	"BlueOak-1.0.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		ExplicitPatentGrant: true,
	},
	"0BSD": {
		Status: ObligationStatusKnown,
		// no conditions at all
	},
	"Unlicense": {
		Status: ObligationStatusKnown,
		// public domain dedication — no conditions
	},
	"CC0-1.0": {
		Status: ObligationStatusKnown,
		// public domain dedication — no conditions
	},
	// CC-BY-4.0: Creative Commons Attribution 4.0 International.
	// Primarily used for documentation and data, not code.
	"CC-BY-4.0": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true, // §3(a)(1)(B): must indicate modifications
		NoTrademarkUse:     true, // §2(b)(3): trademark rights not granted
	},
	// CC-BY-SA-3.0: Creative Commons Attribution-ShareAlike 3.0 Unported.
	// Primarily used for documentation and creative works. ShareAlike clause
	// requires derivative works to be distributed under the same or a
	// compatible license (§4(b)). Adaptation indicator required (§4(b)).
	"CC-BY-SA-3.0": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,           // §4(b): must indicate modifications
		SameLicense:        CopyleftStrong, // §4(b): ShareAlike — derivatives must use same/compatible license
		NoTrademarkUse:     true,           // §4(d): trademark rights not granted
	},
	// OFL-1.1: SIL Open Font License 1.1. Font-specific copyleft: the font
	// itself must remain under OFL if redistributed, but software embedding
	// the font is not affected (font exception). Reserved font names act as
	// a trademark-like restriction.
	"OFL-1.1": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		SameLicense:        CopyleftWeak, // font files must stay under OFL
		NoTrademarkUse:     true,         // reserved font name clause
	},

	// --- Weak copyleft ---

	"MPL-2.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true, // file-level: modifications to MPL files must be disclosed
		SameLicense:         CopyleftWeak,
		ExplicitPatentGrant: true, // §2.1
	},
	"LGPL-2.0-only": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftWeak,
	},
	"LGPL-2.0-or-later": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftWeak,
	},
	"LGPL-2.1-only": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftWeak,
	},
	"LGPL-2.1-or-later": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftWeak,
	},
	"LGPL-3.0-only": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftWeak,
		ExplicitPatentGrant: true, // inherits GPL-3 patent provisions
	},
	"LGPL-3.0-or-later": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftWeak,
		ExplicitPatentGrant: true,
	},
	"EPL-1.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftWeak,
		ExplicitPatentGrant: true, // §2
	},
	"EPL-2.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftWeak,
		ExplicitPatentGrant: true,
	},
	"EUPL-1.2": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftWeak,
		NoTrademarkUse:     true,
	},
	"CDDL-1.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true, // file-level, like MPL
		SameLicense:         CopyleftWeak,
		ExplicitPatentGrant: true, // §2.1
	},

	// --- Strong copyleft ---

	"GPL-2.0-only": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftStrong,
	},
	"GPL-2.0-or-later": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftStrong,
	},
	"GPL-3.0-only": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftStrong,
		ExplicitPatentGrant: true, // §11
	},
	"GPL-3.0-or-later": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftStrong,
		ExplicitPatentGrant: true,
	},
	"EUPL-1.1": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true,
		SameLicense:        CopyleftStrong,
		NoTrademarkUse:     true,
	},
	"BUSL-1.1": {
		// Business Source License: source-available with time-delayed open-source.
		// Modelled as strong copyleft for compatibility purposes.
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		SameLicense:        CopyleftStrong,
	},
	"SSPL-1.0": {
		// Server Side Public License: strong copyleft covering entire service stack.
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		StateChanges:       true,
		DiscloseSource:     true, // must open-source the full infrastructure stack
		SameLicense:        CopyleftStrong,
	},
	"Elastic-2.0": {
		Status:             ObligationStatusKnown,
		IncludeNotice:      true,
		IncludeLicenseText: true,
		NoTrademarkUse:     true,
		SameLicense:        CopyleftStrong,
	},

	// --- Network copyleft ---

	"AGPL-3.0-only": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftNetwork,
		NetworkUseTrigger:   true, // §13: network interaction counts as distribution
		ExplicitPatentGrant: true,
	},
	"AGPL-3.0-or-later": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftNetwork,
		NetworkUseTrigger:   true,
		ExplicitPatentGrant: true,
	},
	"OSL-3.0": {
		Status:              ObligationStatusKnown,
		IncludeNotice:       true,
		IncludeLicenseText:  true,
		StateChanges:        true,
		DiscloseSource:      true,
		SameLicense:         CopyleftNetwork,
		NetworkUseTrigger:   true,
		ExplicitPatentGrant: true,
	},
}

// LookupObligations returns the obligation set for the given SPDX identifier.
// If the identifier is not in the catalogue the returned Obligations has
// Status == ObligationStatusUnknown. Per callers must never treat an
// unknown identifier as having no obligations.
func LookupObligations(spdxID string) Obligations {
	if o, ok := obligationsCatalogue[CanonicalSPDXID(spdxID)]; ok {
		return o
	}
	return Obligations{Status: ObligationStatusUnknown}
}

// MarshalJSON serialises Obligations with Status and SameLicense as strings.
func (o Obligations) MarshalJSON() ([]byte, error) {
	type wire struct {
		Status              string `json:"status"`
		IncludeNotice       bool   `json:"include_notice"`
		IncludeLicenseText  bool   `json:"include_license_text"`
		StateChanges        bool   `json:"state_changes"`
		DiscloseSource      bool   `json:"disclose_source"`
		SameLicense         string `json:"same_license"`
		NetworkUseTrigger   bool   `json:"network_use_trigger"`
		NoTrademarkUse      bool   `json:"no_trademark_use"`
		ExplicitPatentGrant bool   `json:"explicit_patent_grant"`
		CatalogueVersion    string `json:"catalogue_version"`
	}
	b, err := json.Marshal(wire{
		Status:              o.Status.String(),
		IncludeNotice:       o.IncludeNotice,
		IncludeLicenseText:  o.IncludeLicenseText,
		StateChanges:        o.StateChanges,
		DiscloseSource:      o.DiscloseSource,
		SameLicense:         o.SameLicense.String(),
		NetworkUseTrigger:   o.NetworkUseTrigger,
		NoTrademarkUse:      o.NoTrademarkUse,
		ExplicitPatentGrant: o.ExplicitPatentGrant,
		CatalogueVersion:    ObligationCatalogueVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling obligations: %w", err)
	}
	return b, nil
}
