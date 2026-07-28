package domain

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// The Origin comes from an untrusted proxy, so a non-public address in it is an
// SSRF attempt rather than an unusual forge. Each class is pinned separately
// because they name different targets, and the message is what a reader of the
// record has to act on.
func TestCheckOriginAddress_RefusesNonPublicLiterals(t *testing.T) {
	for name, tc := range map[string]struct{ url, want string }{
		"loopback v4":     {"https://127.0.0.1/foo/bar", "loopback"},
		"loopback v6":     {"https://[::1]/foo/bar", "loopback"},
		"localhost":       {"https://localhost/foo/bar", "loopback name"},
		"localhost sub":   {"https://api.localhost/foo/bar", "loopback name"},
		"unspecified":     {"https://0.0.0.0/foo/bar", "unspecified"},
		"rfc1918 ten":     {"https://10.0.0.7/foo/bar", "private"},
		"rfc1918 172":     {"https://172.16.4.4/foo/bar", "private"},
		"rfc1918 192":     {"https://192.168.1.1/foo/bar", "private"},
		"unique local v6": {"https://[fd00::1]/foo/bar", "private"},
		"link local":      {"https://169.254.1.1/foo/bar", "link-local"},
		"metadata":        {"https://169.254.169.254/foo/bar", "link-local"},
		"cgnat":           {"https://100.64.0.1/foo/bar", "carrier-grade NAT"},
	} {
		t.Run(name, func(t *testing.T) {
			err := CheckOriginAddress(tc.url)
			if err == nil {
				t.Fatalf("%s must be refused as an Origin", tc.url)
			}
			if !errors.Is(err, ErrPrivateOriginHost) {
				t.Errorf("error must be ErrPrivateOriginHost, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should name the class %q", err, tc.want)
			}
		})
	}
}

// The guard expresses no opinion about which forges are legitimate. If it
// refused any public host it would cost cross-verification coverage, which is
// the whole reason it can be on unconditionally while the host set stays
// advisory.
func TestCheckOriginAddress_PermitsPublicHosts(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/foo/bar",
		"https://git.example.org/foo/bar",
		"https://codeberg.org/foo/bar",
		"https://gopkg.in/yaml.v3",
		"https://8.8.8.8/foo/bar",
		"https://[2606:4700:4700::1111]/foo/bar",
	} {
		if err := CheckOriginAddress(raw); err != nil {
			t.Errorf("%s must be permitted, got %v", raw, err)
		}
	}
}

// A name that answers into private space is the form an SSRF attempt actually
// takes — a literal is the easy case. Any non-public address in the answer
// refuses the whole Origin rather than filtering to the public ones, because a
// name answering with both is either misconfigured or hostile and git resolves
// again a moment later.
func TestCheckOriginResolvedAddrs(t *testing.T) {
	if err := CheckOriginResolvedAddrs("forge.example.org", []net.IP{
		net.ParseIP("140.82.121.4"),
	}); err != nil {
		t.Errorf("a public answer must pass, got %v", err)
	}

	err := CheckOriginResolvedAddrs("evil.example.org", []net.IP{
		net.ParseIP("140.82.121.4"),
		net.ParseIP("169.254.169.254"),
	})
	if err == nil {
		t.Fatal("a mixed answer must be refused, not filtered down to the public address")
	}
	if !errors.Is(err, ErrPrivateOriginHost) {
		t.Errorf("error must be ErrPrivateOriginHost, got %v", err)
	}
}

// The guard is Origin-only by construction: nothing here is reachable from the
// inferred path. This pins the asymmetry as a property of the API rather than
// of one call site, so wiring it into CheckCloneURL later would break a test
// rather than silently start refusing internal forges named in a go.mod.
func TestCheckCloneURL_DoesNotApplyTheAddressGuard(t *testing.T) {
	// An internal forge the operator depends on directly. CheckCloneURL is the
	// shared path, and it must still permit this.
	if _, err := DefaultVCSHostAllowlist().CheckCloneURL("https://10.0.0.7/foo/bar"); err != nil {
		t.Errorf("the inferred path must not apply the Origin address guard, got %v", err)
	}
	// The same address as an Origin is refused.
	if _, err := DefaultVCSHostAllowlist().CheckOriginForCheckout(
		"https://10.0.0.7/foo/bar", "", strings.Repeat("a", 40)); err == nil {
		t.Error("the Origin path must apply the address guard")
	}
}
