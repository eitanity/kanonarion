package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/stdlib/adapters/godev"
	"github.com/eitanity/kanonarion/internal/stdlib/application"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// errTestClassifier stands for a licence classifier that could not run.
var errTestClassifier = errors.New("licence classifier unavailable")

// The version every test in this file acquires. It is a real-looking release so
// the constructed manifests read like the published one.
const causeVersion = "go1.26.4"

// acquireAgainstManifest runs one acquisition whose release manifest comes from a
// local stand-in for go.dev/dl, and returns the measurement it recorded.
//
// The manifest client is the REAL one (godev.NewWithManifestURL exists for
// exactly this), because the distinction under test is made from what go.dev/dl
// answers, and a hand-written fake of the client could be made to answer
// anything. Only the manifest is served: the tarball download is a fake, so no
// test reaches the network for tens of megabytes.
func acquireAgainstManifest(t *testing.T, manifest http.HandlerFunc) domain.Facts {
	t.Helper()

	// The go.dev/dl client refuses before opening a socket when the environment
	// declares no network (GOPROXY=off). The test states a permitted one, and
	// points GOENV at a file that does not exist so this machine's own go env
	// cannot change the answer.
	t.Setenv("GOENV", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("GOPROXY", "https://proxy.example.com")

	srv := httptest.NewServer(manifest)
	t.Cleanup(srv.Close)

	tarball := buildTarball(t, map[string]string{"go/LICENSE": "BSD-3-Clause text"})
	acq := application.NewAcquirer(
		godev.NewWithManifestURL(srv.URL),
		&fakeTarball{data: tarball},
		&fakeCommits{commit: "c0ffee"},
		fakeLicense{spdx: "BSD-3-Clause"},
		newMemStore(),
		nil,
		fixedClock{t: time.Unix(1_700_000_000, 0)},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	facts, err := acq.Acquire(context.Background(), causeVersion, application.Options{})
	if err != nil {
		t.Fatalf("Acquire against the constructed manifest: %v", err)
	}
	return facts
}

// manifestJSON writes a release manifest body, in the shape go.dev/dl serves.
func manifestJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

// TestAcquire_ManifestCauseIsReadableFromTheRecord is the defect this change
// removes.
//
// Two different things used to produce one record. go.dev/dl could not be
// reached, and go.dev/dl answered and publishes no checksum for this version,
// both recorded the status UnverifiedGoDevUnavailable and the sentence "go.dev/dl
// published checksum unavailable". In the second case that sentence is wrong
// rather than vague — the service was available — and the two need opposite
// actions from whoever reads the record: retry the network, or check which
// toolchain the project pins. The distinction existed only in a log line, which
// is written nowhere and shown by no command.
func TestAcquire_ManifestCauseIsReadableFromTheRecord(t *testing.T) {
	unreachable := acquireAgainstManifest(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	notListed := acquireAgainstManifest(t, manifestJSON(
		`[{"version":"go1.25.9","files":[{"filename":"go1.25.9.src.tar.gz","kind":"source","sha256":"aaaa"}]}]`))
	noSourceFile := acquireAgainstManifest(t, manifestJSON(
		`[{"version":"go1.26.4","files":[{"filename":"go1.26.4.linux-amd64.tar.gz","kind":"archive","sha256":"bbbb"}]}]`))
	// A source entry carrying no digest. The manifest answered, but no checksum
	// came back, which is what "published checksum unavailable" says — and it must
	// never be compared against the computed hash, because "" differs from every
	// digest and that comparison would report tamper evidence.
	noDigest := acquireAgainstManifest(t, manifestJSON(
		`[{"version":"go1.26.4","files":[{"filename":"go1.26.4.src.tar.gz","kind":"source","sha256":""}]}]`))
	if noDigest.VerificationStatus != domain.UnverifiedGoDevUnavailable {
		t.Errorf("a source entry with no digest recorded %s, want %s",
			noDigest.VerificationStatus, domain.UnverifiedGoDevUnavailable)
	}

	if unreachable.VerificationStatus != domain.UnverifiedGoDevUnavailable {
		t.Errorf("a manifest that could not be fetched recorded %s, want %s",
			unreachable.VerificationStatus, domain.UnverifiedGoDevUnavailable)
	}
	for name, facts := range map[string]domain.Facts{
		"the manifest does not list the version":      notListed,
		"the manifest lists no source tarball for it": noSourceFile,
	} {
		if facts.VerificationStatus != domain.UnverifiedGoDevNotPublished {
			t.Errorf("%s recorded %s, want %s — a manifest that answered is not an availability failure",
				name, facts.VerificationStatus, domain.UnverifiedGoDevNotPublished)
		}
	}

	// The acceptance: told apart from the record alone, on the prose as well as
	// the status.
	details := map[string]string{
		"unreachable":    unreachable.VerificationDetail,
		"not listed":     notListed.VerificationDetail,
		"no source file": noSourceFile.VerificationDetail,
	}
	seen := map[string]string{}
	for name, detail := range details {
		if other, dup := seen[detail]; dup {
			t.Errorf("%q and %q record the same verification detail %q", name, other, detail)
		}
		seen[detail] = name
	}

	if !strings.Contains(unreachable.VerificationDetail, "published checksum unavailable") {
		t.Errorf("an unreachable manifest reads %q", unreachable.VerificationDetail)
	}
	if !strings.Contains(notListed.VerificationDetail, "lists no release "+causeVersion) {
		t.Errorf("a version the manifest does not list reads %q", notListed.VerificationDetail)
	}
	if !strings.Contains(noSourceFile.VerificationDetail, "publishes no source tarball for it") {
		t.Errorf("a release with no source tarball reads %q", noSourceFile.VerificationDetail)
	}
	// Neither of the two answers claims go.dev/dl was unavailable.
	for name, facts := range map[string]domain.Facts{"not listed": notListed, "no source file": noSourceFile} {
		if strings.Contains(facts.VerificationDetail, "unavailable") {
			t.Errorf("%s still calls go.dev/dl unavailable: %q", name, facts.VerificationDetail)
		}
	}
}

// TestAcquire_HealthyManifestIsUnchanged is the control for the test above: the
// path every real run takes, against the same constructed server, still records
// the exact status and the exact sentence it recorded before the two causes were
// split apart.
func TestAcquire_HealthyManifestIsUnchanged(t *testing.T) {
	// The tarball acquireAgainstManifest downloads, hashed the way the manifest
	// would publish it.
	sum := sha256hex(buildTarball(t, map[string]string{"go/LICENSE": "BSD-3-Clause text"}))

	facts := acquireAgainstManifest(t, manifestJSON(
		`[{"version":"go1.26.4","files":[{"filename":"go1.26.4.src.tar.gz","kind":"source","sha256":"`+sum+`"}]}]`))

	if facts.VerificationStatus != domain.VerifiedGoDevChecksum {
		t.Fatalf("status = %s, want VerifiedGoDevChecksum", facts.VerificationStatus)
	}
	const want = "SHA-256 matched go.dev/dl published checksum for go1.26.4.src.tar.gz" +
		"; googlesource go tag → commit c0ffee"
	if facts.VerificationDetail != want {
		t.Errorf("healthy verification detail changed\n got: %q\nwant: %q", facts.VerificationDetail, want)
	}
	if facts.LicenseSPDX != "BSD-3-Clause" {
		t.Errorf("LicenseSPDX = %q, want BSD-3-Clause", facts.LicenseSPDX)
	}
}

// TestAcquire_LicenceGapNamesItsCause is the second half of the same defect.
//
// Three different things leave the SPDX identifier empty — the tarball carries
// no LICENSE file, the classifier could not run, and the classifier ran and
// recognised nothing — and all three used to produce one blank field. The third
// wrote no log line at all, so the one case where something had actually read
// the text left no trace anywhere.
func TestAcquire_LicenceGapNamesItsCause(t *testing.T) {
	withLicense := buildTarball(t, map[string]string{"go/LICENSE": "BSD-3-Clause text"})
	withoutLicense := buildTarball(t, map[string]string{"go/README": "no licence here"})

	acquire := func(t *testing.T, tarball []byte, lic fakeLicense) domain.Facts {
		t.Helper()
		m := fakeManifest{releases: []domain.Release{{
			Version: causeVersion,
			Files:   []domain.ReleaseFile{{Kind: "source", SHA256: sha256hex(tarball)}},
		}}}
		facts, err := newAcquirer(t, m, &fakeTarball{data: tarball}, &fakeCommits{commit: "c0ffee"},
			lic, newMemStore(), nil).
			Acquire(context.Background(), causeVersion, application.Options{})
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		return facts
	}

	identified := acquire(t, withLicense, fakeLicense{spdx: "BSD-3-Clause"})
	noFile := acquire(t, withoutLicense, fakeLicense{spdx: "BSD-3-Clause"})
	classifierFailed := acquire(t, withLicense, fakeLicense{err: errTestClassifier})
	unrecognised := acquire(t, withLicense, fakeLicense{})

	for name, facts := range map[string]domain.Facts{
		"no LICENSE file":    noFile,
		"classifier failed":  classifierFailed,
		"nothing recognised": unrecognised,
	} {
		if facts.LicenseSPDX != "" {
			t.Errorf("%s: LicenseSPDX = %q, want empty", name, facts.LicenseSPDX)
		}
	}

	details := map[string]string{
		"identified":         identified.VerificationDetail,
		"no LICENSE file":    noFile.VerificationDetail,
		"classifier failed":  classifierFailed.VerificationDetail,
		"nothing recognised": unrecognised.VerificationDetail,
	}
	seen := map[string]string{}
	for name, detail := range details {
		if other, dup := seen[detail]; dup {
			t.Errorf("%q and %q record the same verification detail %q", name, other, detail)
		}
		seen[detail] = name
	}

	for name, want := range map[string]string{
		"no LICENSE file":    "no LICENSE text was found to classify",
		"classifier failed":  "the licence classifier could not run",
		"nothing recognised": "matched no licence it knows",
	} {
		if !strings.Contains(details[name], want) {
			t.Errorf("%s reads %q, which does not say %q", name, details[name], want)
		}
	}

	// The control: an identified licence adds no clause, so a healthy record's
	// prose is exactly what it was before this distinction existed.
	const want = "SHA-256 matched go.dev/dl published checksum for go1.26.4.src.tar.gz" +
		"; googlesource go tag → commit c0ffee"
	if identified.VerificationDetail != want {
		t.Errorf("an identified licence changed the healthy detail\n got: %q\nwant: %q",
			identified.VerificationDetail, want)
	}
}
