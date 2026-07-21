package domain

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
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
			if got.Path != tc.wantPath || got.Version != tc.wantVersion {
				t.Errorf("coordinate = %s@%s, want %s@%s", got.Path, got.Version, tc.wantPath, tc.wantVersion)
			}
		})
	}
}

// TestRefineOfflineResolutionReason is the guard against a scan-cache hole
// being filed as an expected out-of-toolchain outcome. A version the walk graph
// itself records is one kanonarion undertook to supply; failing to resolve it is
// a fault, and must not inherit ExpectedOutOfToolchain.
func TestRefineOfflineResolutionReason(t *testing.T) {
	known := map[coordinate.ModuleCoordinate]struct{}{
		{Path: "github.com/stretchr/testify", Version: "v1.7.0"}: {},
	}
	inClosure := "go: github.com/cloudwego/iasm@v0.2.0 requires\n\tgithub.com/stretchr/testify@v1.7.0: module lookup disabled by GOPROXY=off"
	outsideClosure := "go: example.com/other@v3.0.0: module lookup disabled by GOPROXY=off"

	if got := RefineOfflineResolutionReason(UnscanReasonVersionNotInToolchain, inClosure, known); got != UnscanReasonIncompleteScanCache {
		t.Errorf("version inside the walk closure = %q, want %q", got, UnscanReasonIncompleteScanCache)
	}
	if got := RefineOfflineResolutionReason(UnscanReasonVersionNotInToolchain, outsideClosure, known); got != UnscanReasonVersionNotInToolchain {
		t.Errorf("version outside the walk closure = %q, want it left as out-of-toolchain", got)
	}
	// No graph to compare against: keep the conservative existing reading.
	if got := RefineOfflineResolutionReason(UnscanReasonVersionNotInToolchain, inClosure, nil); got != UnscanReasonVersionNotInToolchain {
		t.Errorf("with no known set = %q, want it left untouched", got)
	}
	// Unrelated reasons are never rewritten.
	if got := RefineOfflineResolutionReason(UnscanReasonWindowsOnly, inClosure, known); got != UnscanReasonWindowsOnly {
		t.Errorf("unrelated reason = %q, want it left untouched", got)
	}
}

// TestIncompleteScanCacheReason_NamesMissingVersion guards that the operator is
// told which version was missing, not merely that one was.
func TestIncompleteScanCacheReason_NamesMissingVersion(t *testing.T) {
	got := IncompleteScanCacheReason("go: github.com/stretchr/testify@v1.7.0: module lookup disabled by GOPROXY=off")
	if !strings.Contains(got, "github.com/stretchr/testify@v1.7.0") {
		t.Errorf("reason = %q, want it to name the missing version", got)
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
