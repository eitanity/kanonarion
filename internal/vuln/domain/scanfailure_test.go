package domain

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

func TestIsBuildIncompatibility(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		want   bool
	}{
		{"govulncheck load failure", "govulncheck exited with error: exit status 1; stderr: govulncheck: loading packages: invalid array length", true},
		{"package pattern errors", "There are errors with the provided package patterns", true},
		{"build constraints", "build constraints exclude all Go files in /tmp/x", true},
		{"missing module", "no required module provides package example.com/x", true},
		{"goproxy off lookup", "govulncheck: loading packages: There are errors with the provided package patterns:\nstdr.go:25:2: module lookup disabled by GOPROXY=off", true},
		{"case-insensitive", "GOVULNCHECK: LOADING PACKAGES failed", true},
		// The go command's own refusal, met by a plain Go child of the scan rather
		// than through the analyser. It carries none of the analyser's wording, so
		// before this it fell through to a bare failure and the coordinate match a
		// module no analysis could load is still entitled to was dropped.
		{"toolchain gap reported by a go child", "go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)", true},
		// The same class as this tool accounts for it. A reader sees kanonarion's
		// sentence, and the classification must not depend on which of the two
		// wordings reached the record.
		{"toolchain gap as this tool refuses it", "kanonarion pins the toolchain of every analysis child so it can never " +
			"download one, and this code needs go >= 1.99.0 while the analysis is running go1.26.5. The Go command " +
			"reported: go: go.mod requires go >= 1.99.0 (running go 1.26.5; GOTOOLCHAIN=local)", true},
		// Both halves are required, so a module quoting one of them in its own
		// prose cannot be mistaken for the toolchain gap.
		{"prose quoting half the sentence", "the README says this requires go >= 1.24 to build", false},
		{"generic scanner error", "exit status 1", false},
		{"oom", "govulncheck was killed (likely OOM)", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBuildIncompatibility(tc.detail); got != tc.want {
				t.Errorf("IsBuildIncompatibility(%q) = %v, want %v", tc.detail, got, tc.want)
			}
		})
	}
}

func TestStructuredUnscanReason(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		want   UnscanReason
	}{
		{
			name:   "go.work mono-repo",
			detail: "go: cannot load module accessapproval listed in go.work file: open accessapproval/go.mod: no such file or directory",
			want:   UnscanReasonGoWorkMonorepo,
		},
		{
			// Workspace mode is a scan-environment fault, distinct from the
			// mono-repo case where the workspace names siblings absent from the
			// zip. It must not collapse into the build-incompatible catch-all.
			name:   "workspace mode rejects -mod=mod (sonic pattern)",
			detail: "govulncheck: loading packages: err: exit status 1: stderr: go: -mod may only be set to readonly or vendor when in workspace mode, but it is set to \"mod\"\n\tor set GOWORK=off to disable workspace mode.",
			want:   UnscanReasonWorkspaceMode,
		},
		{
			name:   "relative replace directive",
			detail: "reading metric/go.mod: replacement directory ../../metric does not exist",
			want:   UnscanReasonRelativeReplace,
		},
		{
			name:   "windows-only build constraints",
			detail: "build constraints exclude all Go files in /tmp/x/golang.org/x/sys@v0.21.0/windows",
			want:   UnscanReasonWindowsOnly,
		},
		{
			name:   "missing C header",
			detail: "# github.com/google/gopacket/pcap\npcap/pcap_unix.go:34:10: fatal error: pcap.h: No such file or directory",
			want:   UnscanReasonCHeadersMissing,
		},
		{
			name:   "missing go.sum entry",
			detail: "missing go.sum entry for module providing package github.com/pkg/errors",
			want:   UnscanReasonMissingGoSum,
		},
		{
			// The stderr also carries downstream "undefined:" symptoms; the
			// GOPROXY=off root cause must win over the generated-assets pattern.
			name:   "version outside toolchain (goproxy off) wins over undefined symptom",
			detail: "govulncheck: loading packages: stdr.go:25:2: module lookup disabled by GOPROXY=off\nstdr.go:128:20: l.FormatInfo undefined (type logger has no field or method FormatInfo)",
			want:   UnscanReasonVersionNotInToolchain,
		},
		{
			name:   "missing generated assets (velociraptor pattern)",
			detail: "govulncheck: loading packages:\n/tmp/scan/velociraptor/utils/reflect.go:11:22: undefined: assets.ReadFile\n/tmp/scan/velociraptor/vql/unimplemented.go:176:44: undefined: assets.FileDocsReferencesVqlYaml",
			want:   UnscanReasonGeneratedAssets,
		},
		{
			name:   "generic fallback",
			detail: "some other obscure build error",
			want:   UnscanReasonBuildIncompatible,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := StructuredUnscanReason(tc.detail)
			if got != tc.want {
				t.Errorf("StructuredUnscanReason(%q) = %q, want %q", tc.detail, got, tc.want)
			}
		})
	}
}

func TestLocalReplaceUnscannableReason(t *testing.T) {
	got := LocalReplaceUnscannableReason("../local/dep")
	if got == "" {
		t.Fatal("LocalReplaceUnscannableReason returned empty prose")
	}
	if !strings.Contains(got, "../local/dep") {
		t.Errorf("LocalReplaceUnscannableReason(%q) = %q, want it to retain the local path", "../local/dep", got)
	}
}

func TestClassifyBuildIncompatibility(t *testing.T) {
	cases := []struct {
		name        string
		detail      string
		wantContain string
	}{
		{
			name:        "go.work mono-repo cannot load",
			detail:      "go: cannot load module accessapproval listed in go.work file: open accessapproval/go.mod: no such file or directory",
			wantContain: "go.work mono-repo",
		},
		{
			// A module shipping a go.work in its zip puts the toolchain into
			// workspace mode; the reason must name that rather than fall through
			// to the generic "does not build" default, which misdiagnoses a
			// scan-environment problem as a broken module.
			name:        "workspace mode rejects -mod=mod (sonic pattern)",
			detail:      "govulncheck: loading packages: err: exit status 1: stderr: go: -mod may only be set to readonly or vendor when in workspace mode, but it is set to \"mod\"\n\tRemove the -mod flag to use the default readonly value,\n\tor set GOWORK=off to disable workspace mode.",
			wantContain: "workspace mode",
		},
		{
			// The host being a point release behind is not the module failing to
			// build, and the generic default reads as an accusation. The operator
			// needs the two versions, which is the one thing the go command's own
			// sentence carries.
			name:        "host toolchain older than the module's go directive",
			detail:      "govulncheck: loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)",
			wantContain: "host Go toolchain is older",
		},
		{
			name:        "relative replace directive",
			detail:      "reading metric/go.mod: replacement directory ../../metric does not exist",
			wantContain: "relative replace directive",
		},
		{
			name:        "windows-only build constraints",
			detail:      "build constraints exclude all Go files in /tmp/x/golang.org/x/sys@v0.21.0/windows",
			wantContain: "Windows-only",
		},
		{
			name:        "missing C header",
			detail:      "# github.com/google/gopacket/pcap\npcap/pcap_unix.go:34:10: fatal error: pcap.h: No such file or directory",
			wantContain: "C system headers",
		},
		{
			name:        "missing go.sum entry",
			detail:      "missing go.sum entry for module providing package github.com/pkg/errors",
			wantContain: "go.sum entry",
		},
		{
			name:        "missing generated assets (velociraptor pattern)",
			detail:      "govulncheck: loading packages:\n/tmp/scan/velociraptor/utils/reflect.go:11:22: undefined: assets.ReadFile\n/tmp/scan/velociraptor/vql/unimplemented.go:176:44: undefined: assets.FileDocsReferencesVqlYaml",
			wantContain: "generated or embedded assets",
		},
		{
			name:        "version outside toolchain (goproxy off)",
			detail:      "govulncheck: loading packages: stdr.go:25:2: module lookup disabled by GOPROXY=off\nstdr.go:128:20: l.FormatInfo undefined",
			wantContain: "outside the analysed project toolchain",
		},
		{
			name:        "generic fallback",
			detail:      "some other obscure build error",
			wantContain: "does not build",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyBuildIncompatibility(tc.detail)
			if !strings.Contains(got, tc.wantContain) {
				t.Errorf("ClassifyBuildIncompatibility(%q) = %q, want it to contain %q", tc.detail, got, tc.wantContain)
			}
		})
	}
}

func TestUnresolvedCoordinate(t *testing.T) {
	cases := []struct {
		name        string
		detail      string
		wantPath    string
		wantVersion string
		wantOK      bool
	}{
		{
			name:        "requires chain names the unresolvable version",
			detail:      "go: github.com/bytedance/sonic/loader@v0.1.1 requires\n\tgithub.com/cloudwego/iasm@v0.2.0 requires\n\tgithub.com/stretchr/testify@v1.7.0: module lookup disabled by GOPROXY=off",
			wantPath:    "github.com/stretchr/testify",
			wantVersion: "v1.7.0",
			wantOK:      true,
		},
		{
			name:        "single line",
			detail:      "go: github.com/bytedance/sonic/loader@v0.1.1: module lookup disabled by GOPROXY=off",
			wantPath:    "github.com/bytedance/sonic/loader",
			wantVersion: "v0.1.1",
			wantOK:      true,
		},
		{
			// Attributed to a source position, not a module. Nothing to name, so
			// the caller must keep its conservative classification.
			name:   "source position names no module",
			detail: "govulncheck: loading packages: stdr.go:25:2: module lookup disabled by GOPROXY=off",
			wantOK: false,
		},
		{
			// The marker with nothing before it: there is no token to read a
			// coordinate from, so the line must be skipped rather than indexed into.
			name:   "marker with no prefix names no module",
			detail: "module lookup disabled by GOPROXY=off",
			wantOK: false,
		},
		{
			// A token containing "@" whose right-hand side is not a version — an
			// email address, a VCS ref. Reading it as a coordinate would invent a
			// version the walk graph could then be asked about.
			name:   "at-sign without a version is not a coordinate",
			detail: "go: example.com/mod@deadbeef: module lookup disabled by GOPROXY=off",
			wantOK: false,
		},
		{
			// An absolute modcache path whose file position embeds "mod@version"
			// must not be split on that "@" into a /tmp path and a version that
			// carries the file:line:col — it is a source position, not a coordinate.
			name:   "modcache source position is not a coordinate",
			detail: "/tmp/kanonarion-modcache-1/github.com/prometheus/client_golang@v1.12.1/prometheus/desc.go:22:2: module lookup disabled by GOPROXY=off",
			wantOK: false,
		},
		{
			name:   "unrelated failure",
			detail: "build constraints exclude all Go files in /tmp/x",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UnresolvedCoordinate(tc.detail)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Path() != tc.wantPath || got.Version() != tc.wantVersion {
				t.Errorf("coordinate = %s@%s, want %s@%s", got.Path(), got.Version(), tc.wantPath, tc.wantVersion)
			}
		})
	}
}

// TestClassifyOfflineResolution is the guard against a scan-cache hole being
// filed as an expected out-of-toolchain outcome, and against an out-of-toolchain
// verdict being asserted with no version behind it. The classifier maps the
// recovered coordinate and the walk's known set onto the reason and prose the
// evidence supports.
func TestClassifyOfflineResolution(t *testing.T) {
	known := map[coordinate.ModuleCoordinate]struct{}{
		coordinatetest.MustNew("github.com/stretchr/testify", "v1.7.0"): {},
	}
	inClosure := coordinatetest.MustNew("github.com/stretchr/testify", "v1.7.0")
	outside := coordinatetest.MustNew("example.com/other", "v3.0.0")
	detail := "govulncheck: loading packages: stdr.go:25:2: module lookup disabled by GOPROXY=off"

	// A version the walk records: a fault, not an expected outcome, and the prose
	// names the missing coordinate.
	reason, category := ClassifyOfflineResolution(detail, inClosure, true, known)
	if reason != UnscanReasonIncompleteScanCache {
		t.Errorf("version inside the walk closure reason = %q, want %q", reason, UnscanReasonIncompleteScanCache)
	}
	if !strings.Contains(category, inClosure.String()) {
		t.Errorf("incomplete-scan-cache prose = %q, want it to name %s", category, inClosure)
	}

	// A version confirmed outside the set: out-of-toolchain stands, and the prose
	// names the coordinate that proves it.
	reason, category = ClassifyOfflineResolution(detail, outside, true, known)
	if reason != UnscanReasonVersionNotInToolchain {
		t.Errorf("version outside the walk closure reason = %q, want it left as out-of-toolchain", reason)
	}
	if !strings.Contains(category, outside.String()) {
		t.Errorf("verified out-of-toolchain prose = %q, want it to name %s", category, outside)
	}

	// No coordinate recovered: the reason must state the cause is unverified
	// rather than assert an out-of-toolchain re-selection.
	reason, category = ClassifyOfflineResolution(detail, coordinate.ModuleCoordinate{}, false, known)
	if reason != UnscanReasonVersionNotInToolchainUnverified {
		t.Errorf("unrecovered reason = %q, want %q", reason, UnscanReasonVersionNotInToolchainUnverified)
	}
	if !strings.Contains(category, "unverified") {
		t.Errorf("unverified prose = %q, want it to state the cause is unverified", category)
	}

	// No graph to compare against: keep the conservative existing reading.
	reason, _ = ClassifyOfflineResolution(detail, inClosure, true, nil)
	if reason != UnscanReasonVersionNotInToolchain {
		t.Errorf("with no known set reason = %q, want the conservative out-of-toolchain reading", reason)
	}
}

// TestUnscanReason_VersionNotInToolchainUnverifiedIsAFault guards that the
// unverified reason does not inherit the confident, informational reading a
// recovered-and-confirmed one earns — that misclassification is what would let a
// scan-cache hole hide as expected.
func TestUnscanReason_VersionNotInToolchainUnverifiedIsAFault(t *testing.T) {
	if UnscanReasonVersionNotInToolchainUnverified.ExpectedOutOfToolchain() {
		t.Error("version-not-in-toolchain-unverified is an unverified claim; it must not be marked expected")
	}
}

// TestUnresolvedImportPath recovers the unimportable package from the
// source-position error shape — the dominant shape that names no coordinate.
func TestUnresolvedImportPath(t *testing.T) {
	cases := []struct {
		name     string
		detail   string
		wantPath string
		wantOK   bool
	}{
		{
			name: "paired source position names the package",
			detail: "rich_url.go:7:2: module lookup disabled by GOPROXY=off\n" +
				"/tmp/x/github.com/Shopify/goreferrer@v0.0.0/rich_url.go:7:2: could not import golang.org/x/net/publicsuffix (invalid package name: \"\")",
			wantPath: "golang.org/x/net/publicsuffix",
			wantOK:   true,
		},
		{
			// A coordinate-naming failure is UnresolvedCoordinate's to read; this
			// must not also recover a package from it.
			name:   "coordinate shape yields no import path",
			detail: "go: github.com/bytedance/sonic/loader@v0.1.1: module lookup disabled by GOPROXY=off",
			wantOK: false,
		},
		{
			// A could-not-import line at an unrelated position is not the offline
			// resolution failure and must not be paired with it.
			name: "unrelated could-not-import position is not paired",
			detail: "rich_url.go:7:2: module lookup disabled by GOPROXY=off\n" +
				"other.go:3:1: could not import example.com/unrelated (some other reason)",
			wantOK: false,
		},
		{
			name:   "no offline failure at all",
			detail: "build constraints exclude all Go files in /tmp/x",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UnresolvedImportPath(tc.detail)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.wantPath {
				t.Errorf("import path = %q, want %q", got, tc.wantPath)
			}
		})
	}
}

// TestUnresolvedImportPath_ColumnMismatchStillPairs guards the real govulncheck
// shape: the "module lookup disabled" diagnostic and its paired
// "could not import" diagnostic sit on the same source line but at different
// columns — the import keyword versus the import path. Pairing on the whole
// file:line:col position leaves them unpaired and recovers no package, dropping
// the module into the ambiguous unverified bucket; pairing on file:line recovers
// it. goqu (:7:8 / :7:13), httperr (:8:2 / :8:12) and client_model (:8:2 / :8:8)
// all take this shape.
func TestUnresolvedImportPath_ColumnMismatchStillPairs(t *testing.T) {
	detail := "govulncheck: loading packages: \n" +
		"mocks/SQLDialect.go:7:8: module lookup disabled by GOPROXY=off\n" +
		"/tmp/kanonarion-vuln-scan-321908063/github.com/cortezaproject/goqu/v9@v9.18.4/mocks/SQLDialect.go:7:13: " +
		"could not import github.com/stretchr/testify/mock (invalid package name: \"\")"
	got, ok := UnresolvedImportPath(detail)
	if !ok {
		t.Fatalf("ok = false, want the import path recovered from a same-line/different-column pair")
	}
	if got != "github.com/stretchr/testify/mock" {
		t.Errorf("import path = %q, want github.com/stretchr/testify/mock", got)
	}
}

// TestImportSiteModule recovers the dependency module whose source contains the
// failing import, from the cached file path the could-not-import line names.
func TestImportSiteModule(t *testing.T) {
	cases := []struct {
		name       string
		detail     string
		importPath string
		wantCoord  coordinate.ModuleCoordinate
		wantOK     bool
	}{
		{
			name: "cached dependency source names the module and version",
			detail: "/tmp/kanonarion-modcache-1/github.com/golang/protobuf@v1.5.3/proto/buffer.go:11:2: " +
				"could not import google.golang.org/protobuf/proto (invalid package name: \"\")",
			importPath: "google.golang.org/protobuf/proto",
			wantCoord:  coordinatetest.MustNew("github.com/golang/protobuf", "v1.5.3"),
			wantOK:     true,
		},
		{
			name: "filesystem-escaped module path is unescaped",
			detail: "/tmp/kanonarion-modcache-1/github.com/!paessler!a!g/jsonpath@v0.1.1/jsonpath.go:17:2: " +
				"could not import github.com/PaesslerAG/gval (invalid package name: \"\")",
			importPath: "github.com/PaesslerAG/gval",
			wantCoord:  coordinatetest.MustNew("github.com/PaesslerAG/jsonpath", "v0.1.1"),
			wantOK:     true,
		},
		{
			// A position with no "@version" segment is the scanned module's own
			// freshly extracted source, not a cached dependency.
			name:       "no version segment yields no site module",
			detail:     "inliner/element.go:6:2: could not import github.com/PuerkitoBio/goquery (invalid package name: \"\")",
			importPath: "github.com/PuerkitoBio/goquery",
			wantOK:     false,
		},
		{
			// The could-not-import line must name this import path to be paired.
			name: "different import path is not matched",
			detail: "/tmp/x/github.com/golang/protobuf@v1.5.3/proto/buffer.go:11:2: " +
				"could not import google.golang.org/protobuf/proto (invalid package name: \"\")",
			importPath: "github.com/other/pkg",
			wantOK:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ImportSiteModule(tc.detail, tc.importPath)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %v)", ok, tc.wantOK, got)
			}
			if ok && got != tc.wantCoord {
				t.Errorf("coord = %v, want %v", got, tc.wantCoord)
			}
		})
	}
}

// TestUnresolvedImportPath_EdgeShapes covers the degenerate lines the pairing
// must reject rather than read a coordinate out of noise: a marker with no
// source position, a could-not-import line at column start, and one naming no
// package.
func TestUnresolvedImportPath_EdgeShapes(t *testing.T) {
	cases := []struct {
		name   string
		detail string
	}{
		{
			// The GOPROXY=off line has nothing before the marker, so it names no
			// position and cannot be paired.
			name:   "marker with no source position",
			detail: "module lookup disabled by GOPROXY=off\nx.go:1:1: could not import example.com/foo/bar (reason)",
		},
		{
			// The could-not-import line has nothing before the marker, so its
			// position is empty and matches no offline-failure position.
			name:   "could-not-import at column start",
			detail: "x.go:1:1: module lookup disabled by GOPROXY=off\ncould not import example.com/foo/bar",
		},
		{
			// The paired could-not-import line names no package after the marker.
			name:   "could-not-import names no package",
			detail: "x.go:1:1: module lookup disabled by GOPROXY=off\nx.go:1:1: could not import ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := UnresolvedImportPath(tc.detail); ok {
				t.Errorf("ok = true (got %q), want false for a degenerate pair", got)
			}
		})
	}
}

// TestFailurePosition covers the position extractor directly, including the
// empty-prefix case a marker at column start produces.
func TestFailurePosition(t *testing.T) {
	if got := failurePosition("/tmp/x/rich_url.go:7:2: "); got != "/tmp/x/rich_url.go:7:2" {
		t.Errorf("position = %q, want /tmp/x/rich_url.go:7:2", got)
	}
	if got := failurePosition("   "); got != "" {
		t.Errorf("empty prefix position = %q, want empty", got)
	}
}

// TestPositionMatchesAny covers the empty-position guard and the no-match tail.
func TestPositionMatchesAny(t *testing.T) {
	positions := []string{"rich_url.go:7:2"}
	if positionMatchesAny("", positions) {
		t.Error("an empty position matches nothing")
	}
	if !positionMatchesAny("/tmp/x/rich_url.go:7:2", positions) {
		t.Error("a full path sharing the suffix must match the bare filename")
	}
	if positionMatchesAny("other.go:1:1", positions) {
		t.Error("an unrelated position must not match")
	}
}

// TestLooksLikeImportPath covers the shapes the recovery accepts and rejects.
func TestLooksLikeImportPath(t *testing.T) {
	cases := map[string]bool{
		"golang.org/x/net/publicsuffix": true,
		"example.com":                   true, // dotted single segment
		"":                              false,
		"internalpkg":                   false, // no dot in the first segment
		"cmd/compile":                   false,
	}
	for p, want := range cases {
		if got := looksLikeImportPath(p); got != want {
			t.Errorf("looksLikeImportPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestLongestModulePrefix resolves a package to the most specific module that
// provides it, never a shorter prefix that happens to match.
func TestLongestModulePrefix(t *testing.T) {
	paths := map[string]struct{}{
		"":                 {}, // an empty entry is skipped, never matched
		"golang.org/x":     {},
		"golang.org/x/net": {},
	}
	got, ok := LongestModulePrefix("golang.org/x/net/publicsuffix", paths)
	if !ok || got != "golang.org/x/net" {
		t.Errorf("module = %q (ok=%v), want golang.org/x/net", got, ok)
	}
	// An exact match (the package is the module root) resolves to the module.
	if got, ok := LongestModulePrefix("golang.org/x/net", paths); !ok || got != "golang.org/x/net" {
		t.Errorf("exact match module = %q (ok=%v), want golang.org/x/net", got, ok)
	}
	if _, ok := LongestModulePrefix("example.com/absent/pkg", paths); ok {
		t.Error("no module path covers the package; want ok=false")
	}
	// A prefix that is not on a path boundary must not match.
	if _, ok := LongestModulePrefix("golang.org/xtra/pkg", paths); ok {
		t.Error("golang.org/x is not a path-boundary prefix of golang.org/xtra; want ok=false")
	}
}

// TestIncompleteScanCacheReason_NamesMissingVersion guards that the operator is
// told which version was missing, not merely that one was.
func TestIncompleteScanCacheReason_NamesMissingVersion(t *testing.T) {
	got := IncompleteScanCacheReason("go: github.com/stretchr/testify@v1.7.0: module lookup disabled by GOPROXY=off")
	if !strings.Contains(got, "github.com/stretchr/testify@v1.7.0") {
		t.Errorf("reason = %q, want it to name the missing version", got)
	}
	// When the error names no version, the category still states the condition
	// rather than trailing an empty parenthesis or going silent.
	base := IncompleteScanCacheReason("govulncheck: loading packages: stdr.go:25:2: module lookup disabled by GOPROXY=off")
	if !strings.Contains(base, "incomplete scan cache") {
		t.Errorf("reason = %q, want it to still name the condition", base)
	}
	if strings.Contains(base, "(") {
		t.Errorf("reason = %q, want no empty coordinate parenthesis when none was named", base)
	}
}

// TestUnscanReason_IncompleteScanCacheIsAFault guards that the new reason does
// not read as an expected consequence of hermetic scanning — that
// misclassification is what hid it.
func TestUnscanReason_IncompleteScanCacheIsAFault(t *testing.T) {
	if UnscanReasonIncompleteScanCache.ExpectedOutOfToolchain() {
		t.Error("incomplete-scan-cache is a fault kanonarion can fix; it must not be marked expected")
	}
}

// TestUndefinedSymbolSplit guards the two failures the toolchain words
// identically. A qualified symbol means the import resolved but lacks the name —
// an absent generated file. A bare identifier means the declaration is missing
// from the package itself, which is what build-constraint exclusion looks like
// when the host Go toolchain is outside the module's supported range. Reporting
// the second as the first sends the operator hunting for a code-generation step
// in a zip where nothing is missing.
func TestUndefinedSymbolSplit(t *testing.T) {
	const generated = "govulncheck: loading packages:\n/tmp/scan/velociraptor/utils/reflect.go:11:22: undefined: assets.ReadFile\n/tmp/scan/velociraptor/vql/unimplemented.go:176:44: undefined: assets.FileDocsReferencesVqlYaml"
	// sonic/loader@v0.1.1 caps every funcdata variant below go1.23; on a newer
	// host no file is selected and the package's own types are undeclared.
	const constraints = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n/tmp/x/github.com/bytedance/sonic/loader@v0.1.1/funcdata.go:37:32: undefined: _func\n/tmp/x/github.com/bytedance/sonic/loader@v0.1.1/funcdata.go:74:12: undefined: moduledata"

	if got := StructuredUnscanReason(generated); got != UnscanReasonGeneratedAssets {
		t.Errorf("qualified symbol = %q, want %q", got, UnscanReasonGeneratedAssets)
	}
	if got := StructuredUnscanReason(constraints); got != UnscanReasonPackageDeclarationsMissing {
		t.Errorf("bare identifier = %q, want %q", got, UnscanReasonPackageDeclarationsMissing)
	}
	if got := ClassifyBuildIncompatibility(constraints); !strings.Contains(got, "build constraints") {
		t.Errorf("category = %q, want it to name build constraints", got)
	}
	if got := ClassifyBuildIncompatibility(generated); !strings.Contains(got, "generated or embedded assets") {
		t.Errorf("category = %q, want the generated-assets wording retained", got)
	}
	// Mixed evidence reads as generated assets: a missing generated file explains
	// bare and qualified symbols alike, build-constraint exclusion cannot produce
	// a qualified one.
	if got := StructuredUnscanReason(constraints + "\n" + generated); got != UnscanReasonGeneratedAssets {
		t.Errorf("mixed = %q, want the qualified reading to win", got)
	}
}

// TestImportSiteModule_SkipsLineWithoutMarker covers the arm where a detail line
// carries no could-not-import marker: it is skipped and a later matching line is
// paired, rather than the whole detail being rejected.
func TestImportSiteModule_SkipsLineWithoutMarker(t *testing.T) {
	detail := "module lookup disabled by GOPROXY=off\n" +
		"/tmp/x/github.com/foo/bar@v1.2.3/pkg/file.go:1:2: could not import github.com/foo/pkg (invalid package name: \"\")"
	got, ok := ImportSiteModule(detail, "github.com/foo/pkg")
	if !ok {
		t.Fatalf("ok = false, want true (the marker line after a non-marker line must pair)")
	}
	want := coordinatetest.MustNew("github.com/foo/bar", "v1.2.3")
	if got != want {
		t.Errorf("coord = %v, want %v", got, want)
	}
}

// TestPositionLine_Branches covers positionLine's decision arms: no colon, a
// single colon (already file:line), a numeric column stripped, and a non-numeric
// tail left intact.
func TestPositionLine_Branches(t *testing.T) {
	cases := []struct{ in, want string }{
		{"nocolon", "nocolon"},             // last <= 0
		{":leading", ":leading"},           // last == 0 (colon at index 0)
		{"file.go:12", "file.go:12"},       // prev < 0 (single colon)
		{"file.go:12:3", "file.go:12"},     // both tails numeric -> strip column
		{"pkg:name:here", "pkg:name:here"}, // non-numeric tails -> unchanged
		{"file.go:ab:12", "file.go:ab:12"}, // second-last not numeric -> unchanged
	}
	for _, c := range cases {
		if got := positionLine(c.in); got != c.want {
			t.Errorf("positionLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIsAllDigits_Branches covers the empty, non-digit, and all-digit arms.
func TestIsAllDigits_Branches(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"12a", false},
		{"007", true},
	}
	for _, c := range cases {
		if got := isAllDigits(c.in); got != c.want {
			t.Errorf("isAllDigits(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestModuleFromCachePath_Branches covers each rejection arm and the plain
// (non-escaped) success path: no '@', no slash after the version, a version not
// prefixed with 'v', a valid module coordinate, and a well-formed position whose
// prefix is no valid module path.
func TestModuleFromCachePath_Branches(t *testing.T) {
	cases := []struct {
		name      string
		pos       string
		wantOK    bool
		wantCoord coordinate.ModuleCoordinate
	}{
		{"no at-sign", "github.com/foo/bar/file.go:1:2", false, coordinate.ModuleCoordinate{}},
		{"no slash after version", "github.com/foo/bar@v1.0.0", false, coordinate.ModuleCoordinate{}},
		{"version not v-prefixed", "github.com/foo/bar@abc/file.go", false, coordinate.ModuleCoordinate{}},
		{"valid coordinate", "/tmp/x/github.com/foo/bar@v1.2.3/pkg/file.go:1:2", true,
			coordinatetest.MustNew("github.com/foo/bar", "v1.2.3")},
		// A literal (unescaped) path with an uppercase element fails UnescapePath
		// — the escaped form must be all-lowercase — but is a valid module path, so
		// it is accepted via the plain CheckPath arm.
		{"literal uppercase path", "/tmp/x/github.com/Masterminds/semver@v1.5.0/version.go:1:2", true,
			coordinatetest.MustNew("github.com/Masterminds/semver", "v1.5.0")},
		{"empty trailing segment before version", "x/@v1.0.0/file.go", false, coordinate.ModuleCoordinate{}},
		{"no valid module prefix", "not a path@v1.0.0/file.go", false, coordinate.ModuleCoordinate{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := moduleFromCachePath(c.pos)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (got %v)", ok, c.wantOK, got)
			}
			if ok && got != c.wantCoord {
				t.Errorf("coord = %v, want %v", got, c.wantCoord)
			}
		})
	}
}
