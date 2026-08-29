package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"io"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	stdlibdomain "github.com/eitanity/kanonarion/internal/stdlib/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// fakeStdlibCustody is the recorded chain of custody, keyed by canonical Go
// version. An absent key is the case where nothing has been acquired.
type fakeStdlibCustody struct {
	facts map[string][]stdlibdomain.Facts
	err   error
}

func (f fakeStdlibCustody) Get(_ context.Context, goVersion string) (stdlibdomain.Facts, bool, error) {
	if f.err != nil {
		return stdlibdomain.Facts{}, false, f.err
	}
	got, ok := f.facts[goVersion]
	if !ok || len(got) == 0 {
		return stdlibdomain.Facts{}, false, nil
	}
	return got[len(got)-1], true, nil
}

func (f fakeStdlibCustody) ListFactsFor(_ context.Context, goVersion string) ([]stdlibdomain.Facts, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.facts[goVersion], nil
}

func custodyWith(recs ...stdlibdomain.Facts) fakeStdlibCustody {
	m := map[string][]stdlibdomain.Facts{}
	for _, r := range recs {
		m[r.GoVersion] = append(m[r.GoVersion], r)
	}
	return fakeStdlibCustody{facts: m}
}

func stdlibCoord(t *testing.T, version string) coordinate.ModuleCoordinate {
	t.Helper()
	coord, err := coordinate.NewStdlibCoordinateAt(version)
	if err != nil {
		t.Fatalf("NewStdlibCoordinateAt(%q): %v", version, err)
	}
	return coord
}

// The measured go.dev/dl case: the identifier and the anchor both come off the
// stored measurement, and the answer names the tarball as its basis.
func TestResolveStdlibLicence_FromAcquiredSource(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
		VerificationDetail: "SHA-256 matched go.dev/dl published checksum",
		AcquisitionRoute:   stdlibdomain.RouteGoDev,
		SourceURL:          "https://go.dev/dl/go1.26.5.src.tar.gz",
		Digests:            fetchdomain.ArtifactDigests{SHA256: "495be4"},
		AcquiredAt:         time.Date(2026, 8, 14, 7, 6, 41, 0, time.UTC),
	})

	got, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custody)
	if err != nil {
		t.Fatalf("resolveStdlibLicence: %v", err)
	}
	if got.SPDX != "BSD-3-Clause" {
		t.Errorf("SPDX = %q, want BSD-3-Clause", got.SPDX)
	}
	if got.Basis != stdlibLicenceBasisTarball {
		t.Errorf("Basis = %q, want %q", got.Basis, stdlibLicenceBasisTarball)
	}
	if got.Verification != string(stdlibdomain.VerifiedGoDevChecksum) {
		t.Errorf("Verification = %q, want VerifiedGoDevChecksum", got.Verification)
	}
	if !got.Established() {
		t.Error("Established() = false for a stored measurement")
	}
	if got.SHA256 != "495be4" || got.Route != "godev" {
		t.Errorf("artefact/route = %q/%q, want 495be4/godev", got.SHA256, got.Route)
	}
}

// The answer is READ, not asserted. A measurement naming a different identifier
// is reported as that identifier: a fix that hardcoded BSD-3-Clause would pass
// every other test here and fail this one.
func TestResolveStdlibLicence_ReportsTheRecordedIdentifierNotAConstant(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "MIT",
		VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
	})

	got, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custody)
	if err != nil {
		t.Fatalf("resolveStdlibLicence: %v", err)
	}
	if got.SPDX != "MIT" {
		t.Fatalf("SPDX = %q, want MIT — the answer is not being read off the measurement", got.SPDX)
	}
	if got.Basis != stdlibLicenceBasisTarball {
		t.Errorf("Basis = %q, want %q", got.Basis, stdlibLicenceBasisTarball)
	}
}

// The offline custody path anchors to the local toolchain and deliberately does
// NOT consult the published checksum. The answer must relay that status, never
// the go.dev/dl one — the two are different claims about different evidence.
func TestResolveStdlibLicence_OfflineAnchorIsNotUpgraded(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.VerifiedLocalToolchain,
		AcquisitionRoute:   stdlibdomain.RouteLocalToolchain,
	})

	got, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custody)
	if err != nil {
		t.Fatalf("resolveStdlibLicence: %v", err)
	}
	if got.Verification != string(stdlibdomain.VerifiedLocalToolchain) {
		t.Errorf("Verification = %q, want VerifiedLocalToolchain", got.Verification)
	}
	if strings.Contains(got.basisStatement(), string(stdlibdomain.VerifiedGoDevChecksum)) {
		t.Errorf("basis statement claims the published-checksum anchor: %q", got.basisStatement())
	}
}

// A tamper-evidence measurement is relayed as it stands. The licence identity
// still comes off the bytes that were acquired, and the status beside it says
// those bytes did not match what Go publishes.
func TestResolveStdlibLicence_MismatchStatusIsRelayed(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.GoDevChecksumMismatch,
	})

	got, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custody)
	if err != nil {
		t.Fatalf("resolveStdlibLicence: %v", err)
	}
	if got.Verification != string(stdlibdomain.GoDevChecksumMismatch) {
		t.Errorf("Verification = %q, want GoDevChecksumMismatch", got.Verification)
	}
}

// Custody established, licence not identified: the two axes must not collapse.
// The identifier falls back to published knowledge and says so, while the
// verification status the measurement DID establish stays visible.
func TestResolveStdlibLicence_EstablishedCustodyWithoutAnIdentifier(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
	})

	got, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custody)
	if err != nil {
		t.Fatalf("resolveStdlibLicence: %v", err)
	}
	if got.Basis != stdlibLicenceBasisKnown {
		t.Errorf("Basis = %q, want %q", got.Basis, stdlibLicenceBasisKnown)
	}
	if !got.Established() {
		t.Error("Established() = false although a measurement was recorded")
	}
	if !strings.Contains(got.basisStatement(), "identified none") {
		t.Errorf("basis statement does not say the measurement identified no licence: %q", got.basisStatement())
	}
}

// The offline / --from-modcache case where acquisition never ran: nothing has
// been established for this toolchain. The answer is the published constant and
// it says exactly that, claims no verification, and names a command that can
// actually establish one.
func TestResolveStdlibLicence_UnestablishedCustodySaysSo(t *testing.T) {
	got, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custodyWith())
	if err != nil {
		t.Fatalf("resolveStdlibLicence: %v", err)
	}
	if got.Established() {
		t.Fatal("Established() = true with no measurement in the ledger")
	}
	if got.Verification != "" {
		t.Errorf("Verification = %q, want empty — nothing was verified", got.Verification)
	}
	if got.Basis != stdlibLicenceBasisKnown {
		t.Errorf("Basis = %q, want %q", got.Basis, stdlibLicenceBasisKnown)
	}
	stmt := got.basisStatement()
	if !strings.Contains(stmt, "no chain of custody is recorded") {
		t.Errorf("basis statement does not state the chain is unestablished: %q", stmt)
	}
	if !strings.Contains(stmt, stdlibCustodyRemedy) {
		t.Errorf("basis statement names no way to establish custody: %q", stmt)
	}
	if strings.Contains(stmt, "kanonarion fetch") {
		t.Errorf("basis statement names a fetch the coordinate cannot be fetched by: %q", stmt)
	}
}

// A store read that fails is an error, not an answer. Reporting BSD-3-Clause
// over an unread ledger would be the invented constant this whole path exists
// to avoid.
func TestResolveStdlibLicence_ReadErrorIsNotAnAnswer(t *testing.T) {
	custody := fakeStdlibCustody{err: errors.New("ledger unreadable")}
	if _, err := resolveStdlibLicence(context.Background(), stdlibCoord(t, "v1.26.5"), custody); err == nil {
		t.Fatal("resolveStdlibLicence returned an answer over a failed ledger read")
	}
}

// The context document's licence section: never not_run for a coordinate the
// store can answer, and carrying the basis the answer rests on.
func TestBuildStdlibLicense_ContextSectionIsNotNotRun(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
		AcquisitionRoute:   stdlibdomain.RouteGoDev,
	})

	sec := buildLicense(context.Background(), stdlibCoord(t, "v1.26.5"), nil, custody)
	if sec.Status == sectionStatusNotRun {
		t.Fatal("licence section is not_run for a standard library the store has measured")
	}
	if sec.SPDX != "BSD-3-Clause" {
		t.Errorf("SPDX = %q, want BSD-3-Clause", sec.SPDX)
	}
	if sec.Custody == nil {
		t.Fatal("licence section carries no custody block")
	}
	if sec.Custody.Basis != stdlibLicenceBasisTarball ||
		sec.Custody.Verification != string(stdlibdomain.VerifiedGoDevChecksum) {
		t.Errorf("custody = %+v, want stdlib-tarball / VerifiedGoDevChecksum", *sec.Custody)
	}
	if sec.Obligations == nil {
		t.Error("licence section carries no obligations for an identified licence")
	}
}

// The unestablished case reaches the document as the published constant plus a
// statement that nothing was measured — still not not_run, because something
// did look and found the ledger empty.
func TestBuildStdlibLicense_UnestablishedCustodyInContext(t *testing.T) {
	sec := buildLicense(context.Background(), stdlibCoord(t, "v1.26.5"), nil, custodyWith())
	if sec.Status != "Known" {
		t.Errorf("Status = %q, want Known", sec.Status)
	}
	if sec.Custody == nil || sec.Custody.Verification != "" {
		t.Fatalf("custody = %+v, want a block claiming no verification", sec.Custody)
	}
	if !strings.Contains(sec.Custody.Statement, stdlibCustodyRemedy) {
		t.Errorf("custody statement names no way to establish custody: %q", sec.Custody.Statement)
	}
}

// The licence command's answer for the standard library. It must never send the
// reader to `kanonarion fetch`, which rejects the coordinate outright.
func TestRunStdlibLicense_TextNeverNamesFetch(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
		AcquisitionRoute:   stdlibdomain.RouteGoDev,
	})

	var out bytes.Buffer
	if err := runStdlibLicense(context.Background(), stdlibCoord(t, "v1.26.5"), licenseFlags{}, custody, &out); err != nil {
		t.Fatalf("runStdlibLicense: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "BSD-3-Clause") {
		t.Errorf("output does not report the licence: %q", got)
	}
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("output names a fetch the coordinate cannot be fetched by: %q", got)
	}
}

// The same on the unestablished path, which is where a remedy is offered at
// all: it names the walk that records custody, never the fetch.
func TestRunStdlibLicense_UnestablishedRemedyExists(t *testing.T) {
	var out bytes.Buffer
	if err := runStdlibLicense(context.Background(), stdlibCoord(t, "v1.26.5"), licenseFlags{}, custodyWith(), &out); err != nil {
		t.Fatalf("runStdlibLicense: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("output names a fetch the coordinate cannot be fetched by: %q", got)
	}
	if !strings.Contains(got, stdlibCustodyRemedy) {
		t.Errorf("output names no way to establish custody: %q", got)
	}
}

func TestRunStdlibLicense_JSONCarriesTheBasis(t *testing.T) {
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.VerifiedLocalToolchain,
		AcquisitionRoute:   stdlibdomain.RouteLocalToolchain,
	})

	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var out bytes.Buffer
	if err := runStdlibLicense(context.Background(), stdlibCoord(t, "v1.26.5"), licenseFlags{}, custody, &out); err != nil {
		t.Fatalf("runStdlibLicense: %v", err)
	}
	// Decoded structurally rather than into stdlibLicenceJSON: the obligation
	// catalogue's status marshals to a word and has no decoder, so the shape is
	// asserted on the fields this document is responsible for.
	var doc struct {
		SPDX    string `json:"primary_spdx"`
		Status  string `json:"status"`
		Custody struct {
			Established  bool   `json:"established"`
			Basis        string `json:"basis"`
			Verification string `json:"verification"`
			Remedy       string `json:"remedy"`
		} `json:"custody"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decoding JSON: %v (%s)", err, out.String())
	}
	if doc.SPDX != "BSD-3-Clause" || doc.Custody.Basis != stdlibLicenceBasisTarball {
		t.Errorf("doc = %+v, want BSD-3-Clause / stdlib-tarball", doc)
	}
	if doc.Custody.Verification != string(stdlibdomain.VerifiedLocalToolchain) {
		t.Errorf("verification = %q, want VerifiedLocalToolchain", doc.Custody.Verification)
	}
	if doc.Custody.Remedy != "" {
		t.Errorf("an established chain still offers a remedy: %q", doc.Custody.Remedy)
	}
}

// --history over the custody ledger: every measurement, oldest first.
func TestRunStdlibLicenceHistory_ListsEveryMeasurement(t *testing.T) {
	custody := custodyWith(
		stdlibdomain.Facts{
			GoVersion: "go1.26.5", LicenseSPDX: "BSD-3-Clause",
			VerificationStatus: stdlibdomain.UnverifiedGoDevUnavailable,
			AcquisitionRoute:   stdlibdomain.RouteLocalToolchain,
			AcquiredAt:         time.Date(2026, 8, 13, 4, 12, 57, 0, time.UTC),
		},
		stdlibdomain.Facts{
			GoVersion: "go1.26.5", LicenseSPDX: "BSD-3-Clause",
			VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
			AcquisitionRoute:   stdlibdomain.RouteGoDev,
			AcquiredAt:         time.Date(2026, 8, 14, 7, 6, 41, 0, time.UTC),
		},
	)

	var out bytes.Buffer
	if err := runStdlibLicense(context.Background(), stdlibCoord(t, "v1.26.5"),
		licenseFlags{history: true}, custody, &out); err != nil {
		t.Fatalf("runStdlibLicense --history: %v", err)
	}
	got := out.String()
	for _, want := range []string{"2 custody measurement(s)", "UnverifiedGoDevUnavailable", "VerifiedGoDevChecksum", "local-toolchain"} {
		if !strings.Contains(got, want) {
			t.Errorf("history output missing %q:\n%s", want, got)
		}
	}
}

func TestRunStdlibLicenceHistory_EmptyLedgerNamesTheRemedy(t *testing.T) {
	var out bytes.Buffer
	if err := runStdlibLicense(context.Background(), stdlibCoord(t, "v1.26.5"),
		licenseFlags{history: true}, custodyWith(), &out); err != nil {
		t.Fatalf("runStdlibLicense --history: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, stdlibCustodyRemedy) || strings.Contains(got, "kanonarion fetch") {
		t.Errorf("history output names the wrong remedy: %q", got)
	}
}

// provenance's copyright tier: the standard library holds no licence record and
// the tier must say so without sending the reader to a command that would leave
// the answer where it is.
func TestResolveLicenceBasis_StdlibNamesNoImpossibleRemedy(t *testing.T) {
	_, ok, detail := resolveLicenceBasis(context.Background(), "stdlib", "v1.26.5", nil, nil, nil)
	if ok {
		t.Fatal("resolveLicenceBasis resolved a record for the standard library")
	}
	if strings.Contains(detail, "kanonarion fetch") {
		t.Errorf("detail names a fetch the coordinate cannot be fetched by: %q", detail)
	}
	if !strings.Contains(detail, "chain of custody") {
		t.Errorf("detail does not say where the licence identity comes from: %q", detail)
	}
}

// resolvingFakeQueryLicense drives the extract callback the way the real
// ResolveForWalk does, so the closure `license --recursive` builds is exercised
// rather than stubbed past.
type resolvingFakeQueryLicense struct {
	*testfakes.FakeQueryLicense
	nodes []coordinate.ModuleCoordinate
}

func (f resolvingFakeQueryLicense) ResolveForWalk(
	ctx context.Context,
	_ string,
	_ coordinate.ModuleCoordinate,
	extractFn func(context.Context, coordinate.ModuleCoordinate) (licdomain.LicenseRecord, error),
) ([]licapp.DepLicenseResult, error) {
	out := make([]licapp.DepLicenseResult, 0, len(f.nodes))
	for _, coord := range f.nodes {
		rec, err := extractFn(ctx, coord)
		if err != nil {
			out = append(out, licapp.DepLicenseResult{Coordinate: coord, Err: err})
			continue
		}
		out = append(out, licapp.DepLicenseResult{Coordinate: coord, PrimarySPDX: rec.PrimarySPDX})
	}
	return out, nil
}

// A project walk carries the standard library as a node, so --recursive walks
// straight into it. Extraction can only ever miss there, and the miss used to
// print `run 'kanonarion fetch' first` against a coordinate fetch rejects.
func TestPrintLicenseRecursive_StdlibNodeIsNotAFetchRemedy(t *testing.T) {
	target, err := coordinate.NewLocalCoordinate("example.com/project")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.SetSummaries([]walkports.WalkSummary{
		{ID: "WALK001", Target: target, StartedAt: time.Now(), OverallStatus: walkdomain.WalkSucceeded},
	})
	queryUC := resolvingFakeQueryLicense{
		FakeQueryLicense: testfakes.NewFakeQueryLicense(),
		nodes:            []coordinate.ModuleCoordinate{stdlibCoord(t, "v1.26.5")},
	}
	custody := custodyWith(stdlibdomain.Facts{
		GoVersion:          "go1.26.5",
		LicenseSPDX:        "BSD-3-Clause",
		VerificationStatus: stdlibdomain.VerifiedGoDevChecksum,
	})

	var buf bytes.Buffer
	if rerr := printLicenseRecursive(context.Background(), target, walksUC,
		&testfakes.FakeExtractLicense{}, queryUC, custody,
		licenseFlags{all: true}, &buf, io.Discard); rerr != nil {
		t.Fatalf("printLicenseRecursive: %v", rerr)
	}
	got := buf.String()
	if strings.Contains(got, "kanonarion fetch") {
		t.Errorf("closure listing names a fetch the coordinate cannot be fetched by:\n%s", got)
	}
	if !strings.Contains(got, "BSD-3-Clause") {
		t.Errorf("closure listing does not carry the standard library's licence:\n%s", got)
	}
}
