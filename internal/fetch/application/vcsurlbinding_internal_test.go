package application

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// originAt builds proxy Origin metadata naming url, with a well-formed commit so
// the Origin passes the trust checks and the route is actually taken.
func originAt(url string) ports.ModuleInfo {
	return ports.ModuleInfo{Origin: &ports.ModuleOrigin{
		VCS:  "git",
		URL:  url,
		Ref:  "refs/tags/v1.0.0",
		Hash: strings.Repeat("a", 40),
	}}
}

// TestResolveGitRef_ProxyURLTheCoordinateDerivesIsCoordinateDerived pins the
// rule that the BINDING is about the repository, not about who typed the URL. A
// proxy-supplied URL that matches what the module path derives is the stronger
// binding, because the coordinate confirms the repository independently.
func TestResolveGitRef_ProxyURLTheCoordinateDerivesIsCoordinateDerived(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: &tagRecordingVCS{}}
	coord := coordinatetest.MustNew("github.com/gorilla/mux", "v1.8.1")

	_, status, _, _, binding := uc.resolveGitRef(context.Background(), slog.Default(),
		coord, originAt("https://github.com/gorilla/mux"), domain2.DefaultVCSHostAllowlist())

	if status != domain2.Verified {
		t.Fatalf("status = %q, want Verified", status)
	}
	if binding != domain2.VCSURLBindingCoordinateDerived {
		t.Errorf("binding = %q, want %q: the proxy named the same repository the module path derives, "+
			"so the coordinate confirms it and the assurance is the stronger one",
			binding, domain2.VCSURLBindingCoordinateDerived)
	}
}

// TestResolveGitRef_VanityPathIsProxyNamed is the ticket's population in
// miniature. A vanity module path's repository cannot be derived from the
// coordinate, so the URL comes from the untrusted proxy and nothing independent
// confirms it.
func TestResolveGitRef_VanityPathIsProxyNamed(t *testing.T) {
	for _, tc := range []struct{ path, originURL string }{
		{"go.uber.org/zap", "https://github.com/uber-go/zap"},
		{"cel.dev/expr", "https://github.com/google/cel-spec"},
		{"google.golang.org/grpc", "https://github.com/grpc/grpc-go"},
		{"cloud.google.com/go/auth", "https://github.com/googleapis/google-cloud-go"},
	} {
		uc := &FetchModuleUseCase{vcs: &tagRecordingVCS{}}
		coord := coordinatetest.MustNew(tc.path, "v1.0.0")

		gitRef, status, _, _, binding := uc.resolveGitRef(context.Background(), slog.Default(),
			coord, originAt(tc.originURL), domain2.DefaultVCSHostAllowlist())

		if status != domain2.Verified {
			t.Errorf("%s: status = %q, want Verified", tc.path, status)
		}
		if gitRef.URL != tc.originURL {
			t.Errorf("%s: cloned URL = %q, want the Origin's %q", tc.path, gitRef.URL, tc.originURL)
		}
		if binding != domain2.VCSURLBindingProxyNamed {
			t.Errorf("%s: binding = %q, want %q: no rule derives %q from this coordinate",
				tc.path, binding, domain2.VCSURLBindingProxyNamed, tc.originURL)
		}
	}
}

// TestResolveGitRef_InferredRouteIsCoordinateDerived covers the other way the
// stronger binding is reached: no usable Origin, so the URL is derived from the
// module path and nothing untrusted took part in choosing it.
func TestResolveGitRef_InferredRouteIsCoordinateDerived(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: &tagRecordingVCS{}}
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.8.1")

	gitRef, status, _, _, binding := uc.resolveGitRef(context.Background(), slog.Default(),
		coord, ports.ModuleInfo{}, domain2.DefaultVCSHostAllowlist())

	if status != domain2.Verified {
		t.Fatalf("status = %q, want Verified", status)
	}
	if gitRef.URL != "https://github.com/foo/bar" {
		t.Fatalf("inferred URL = %q", gitRef.URL)
	}
	if binding != domain2.VCSURLBindingCoordinateDerived {
		t.Errorf("binding = %q, want %q", binding, domain2.VCSURLBindingCoordinateDerived)
	}
}

// TestResolveGitRef_RefusedOriginIsNotRecordedAsProxyNamed guards a misreport
// that would be worse than silence. When an Origin is refused the run falls
// through and clones a URL derived from the module path — so attributing the
// record to the proxy would name a repository the run never went near.
func TestResolveGitRef_RefusedOriginIsNotRecordedAsProxyNamed(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: &tagRecordingVCS{}}
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	info := ports.ModuleInfo{Origin: &ports.ModuleOrigin{
		URL:  `ext::sh -c "touch /tmp/pwned"`,
		Hash: "--upload-pack=touch",
	}}

	gitRef, _, _, refusal, binding := uc.resolveGitRef(context.Background(), slog.Default(),
		coord, info, domain2.DefaultVCSHostAllowlist())

	if refusal == "" {
		t.Fatal("the malicious Origin was not refused, so this test proves nothing")
	}
	if gitRef.URL != "https://github.com/foo/bar" {
		t.Fatalf("fell through to URL %q, want the derived one", gitRef.URL)
	}
	if binding != domain2.VCSURLBindingCoordinateDerived {
		t.Errorf("binding = %q, want %q: the refused Origin was not what got cloned",
			binding, domain2.VCSURLBindingCoordinateDerived)
	}
}

// TestResolveGitRef_NoURLAttributesNeitherBinding keeps the absent value meaning
// what it says. Nothing was cloned, so naming either binding would attribute an
// assurance to a check that never ran.
func TestResolveGitRef_NoURLAttributesNeitherBinding(t *testing.T) {
	uc := &FetchModuleUseCase{vcs: &tagRecordingVCS{}}
	// A bare host is not a repository, so no URL can be derived from it.
	coord := coordinatetest.MustNew("example.com", "v1.0.0")

	gitRef, status, _, _, binding := uc.resolveGitRef(context.Background(), slog.Default(),
		coord, ports.ModuleInfo{}, domain2.DefaultVCSHostAllowlist())

	if gitRef.URL != "" {
		t.Fatalf("a URL was inferred from a bare host: %q", gitRef.URL)
	}
	if status != domain2.UnverifiedMissingOrigin {
		t.Fatalf("status = %q, want UnverifiedMissingOrigin", status)
	}
	if binding != domain2.VCSURLBindingAbsent {
		t.Errorf("binding = %q, want the absent value: nothing was cloned", binding)
	}
}

// TestBindingForProxyURL_ComparesExactly pins the conservative comparison. A URL
// that differs only cosmetically is reported as the weaker binding, because
// overstating assurance is the one direction this attribution must never err in.
func TestBindingForProxyURL_ComparesExactly(t *testing.T) {
	for _, tc := range []struct {
		name, path, url string
		want            domain2.VCSURLBinding
	}{
		{"exact match", "github.com/foo/bar", "https://github.com/foo/bar", domain2.VCSURLBindingCoordinateDerived},
		{"trailing .git", "github.com/foo/bar", "https://github.com/foo/bar.git", domain2.VCSURLBindingProxyNamed},
		{"trailing slash", "github.com/foo/bar", "https://github.com/foo/bar/", domain2.VCSURLBindingProxyNamed},
		{"different host", "github.com/foo/bar", "https://gitlab.com/foo/bar", domain2.VCSURLBindingProxyNamed},
		{"same-name lookalike", "github.com/foo/bar", "https://github.com/evil/bar", domain2.VCSURLBindingProxyNamed},
		{"vanity path", "go.uber.org/zap", "https://github.com/uber-go/zap", domain2.VCSURLBindingProxyNamed},
		{"empty URL", "github.com/foo/bar", "", domain2.VCSURLBindingProxyNamed},
		{"underivable path", "example.com", "https://example.com", domain2.VCSURLBindingProxyNamed},
	} {
		if got := bindingForProxyURL(tc.path, tc.url); got != tc.want {
			t.Errorf("%s: bindingForProxyURL(%q, %q) = %q, want %q", tc.name, tc.path, tc.url, got, tc.want)
		}
	}
}
