package domain

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
)

// spdxTextFS holds verbatim licence texts keyed by SPDX identifier, one file
// per identifier named "<SPDX-id>.txt".
//
// Module attribution reads its licence text out of the module's own zip blob,
// so it needs no table. Code *copied into first-party source* has no zip to
// read from: the snippet carries only an SPDX identifier, and the verbatim
// text has to come from somewhere. This is that somewhere.
//
// Like godebug's taxonomy.json and fips's catalogue.json, this is a *data
// asset*: covering a new identifier is adding a .txt file, never a code
// change. Texts are stored as plain files rather than JSON strings so they
// stay verbatim and reviewable in a diff — a base64 blob would hide a
// truncated or altered licence from review, and review is the only thing
// standing between this table and a wrong attribution.
//
// Files are named "spdx-<identifier>.txt". The prefix is load-bearing: bare
// SPDX identifiers include "Unlicense", which is one of the licence-file stems
// kanonarion's own licence selection matches, so an unprefixed file could be
// picked up as a licence grant for whatever project vendored it.
//
//go:embed spdxtexts/*.txt
var spdxTextFS embed.FS

// spdxTextPrefix guards the table's filenames against colliding with a
// licence-file stem. See the embed comment above.
const spdxTextPrefix = "spdx-"

// ErrUnknownSPDXText is returned by SPDXLicenseText when the identifier has no
// entry in the embedded table. Callers must treat this as fatal: emitting an
// attribution record without its licence text would publish a NOTICE that
// silently understates what the project redistributes.
var ErrUnknownSPDXText = errors.New("no embedded licence text for SPDX identifier")

var (
	spdxTextsOnce sync.Once
	spdxTexts     map[string]string
)

func loadSPDXTexts() {
	spdxTexts = make(map[string]string)
	entries, err := fs.ReadDir(spdxTextFS, "spdxtexts")
	if err != nil {
		// Unreachable: the embed directive guarantees the directory exists.
		// A test guards the table is non-empty.
		panic(fmt.Sprintf("license: reading embedded SPDX text table: %v", err))
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".txt") || !strings.HasPrefix(name, spdxTextPrefix) {
			// A file that does not follow the naming contract is an asset
			// mistake, not a licence: fail the build-time load rather than
			// silently omit an identifier callers expect to resolve.
			panic(fmt.Sprintf("license: embedded SPDX text %q must be named %s<identifier>.txt", name, spdxTextPrefix))
		}
		content, rerr := fs.ReadFile(spdxTextFS, path.Join("spdxtexts", name))
		if rerr != nil {
			panic(fmt.Sprintf("license: reading embedded SPDX text %s: %v", name, rerr))
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, spdxTextPrefix), ".txt")
		spdxTexts[id] = strings.TrimRight(string(content), "\n")
	}
}

// SPDXLicenseText returns the verbatim licence text for a single SPDX
// identifier. The lookup is exact and case-sensitive: SPDX identifiers are
// case-sensitive, and a near-miss must fail loudly rather than resolve to a
// neighbouring licence.
func SPDXLicenseText(spdx string) (string, error) {
	spdxTextsOnce.Do(loadSPDXTexts)
	text, ok := spdxTexts[spdx]
	if !ok {
		return "", fmt.Errorf("%w: %s (known: %s)", ErrUnknownSPDXText, spdx, strings.Join(KnownSPDXTextIDs(), ", "))
	}
	return text, nil
}

// KnownSPDXTextIDs returns the sorted identifiers the embedded table covers.
func KnownSPDXTextIDs() []string {
	spdxTextsOnce.Do(loadSPDXTexts)
	ids := make([]string, 0, len(spdxTexts))
	for id := range spdxTexts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
