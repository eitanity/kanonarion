package domain

import (
	"strings"
	"testing"
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
