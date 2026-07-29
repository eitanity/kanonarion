package domain

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrPrivateOriginHost is returned when a proxy-supplied Origin names an
// address that is not reachable from the public internet. It is a sentinel so a
// caller can distinguish "this Origin is an SSRF attempt" from the ordinary
// "this Origin is malformed", which are different things to report.
var ErrPrivateOriginHost = errors.New("origin host is not a public address")

// CheckOriginAddress refuses a proxy-supplied Origin URL that names a
// non-public address.
//
// This guard applies to the Origin path ONLY, and the asymmetry is the whole
// point. An Origin comes from the module proxy, which is untrusted: it can name
// any host, unrelated to anything in the operator's go.mod, and a git
// subprocess that dials it turns kanonarion into a probe for whatever the host
// running it can route to — internal services, and the cloud metadata endpoint
// most of all. An INFERRED URL is derived from a module path the operator
// already chose to depend on, so if that path names an internal forge,
// contacting it is the correct behaviour rather than an attack, and this
// function is deliberately not applied there.
//
// It expresses no opinion about which forges are legitimate. Every public host
// passes, so it costs no cross-verification coverage — unlike a host allowlist,
// which refuses by default and is therefore wrong by default. That distinction
// is why this can be on unconditionally while the host set stays advisory.
//
// The check is on the URL alone and does not resolve names; a hostname whose
// DNS record points into private space is caught by CheckOriginResolvedAddrs,
// which the application layer calls with a resolver.
func CheckOriginAddress(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing Origin URL %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: Origin URL %q names no host", ErrPrivateOriginHost, rawURL)
	}
	// RFC 6761 reserves localhost and its subdomains for the loopback
	// interface, so they need no lookup to be refused.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("%w: %q is the loopback name", ErrPrivateOriginHost, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkPublicIP(host, ip)
	}
	return nil
}

// CheckOriginResolvedAddrs refuses an Origin whose name resolves into
// non-public space. It is separate from CheckOriginAddress because resolution
// is a network act and belongs to the caller that owns the resolver.
//
// ANY non-public address in the answer refuses the whole Origin rather than
// filtering down to the public ones. A name that answers with both is either
// misconfigured or hostile, and picking the public address would hand the
// decision to whatever git resolves a moment later.
//
// This narrows the window rather than closing it: git resolves the name again
// when it dials, so a record that changes between the two lookups (DNS
// rebinding) is not caught here. Closing that would mean pinning the resolved
// address into the connection, which git does not expose. Egress control is the
// complete answer; this is the part kanonarion can do itself.
func CheckOriginResolvedAddrs(host string, addrs []net.IP) error {
	for _, ip := range addrs {
		if err := checkPublicIP(host, ip); err != nil {
			return err
		}
	}
	return nil
}

// checkPublicIP names the class an address falls into rather than reporting a
// bare refusal, because the classes mean different things to whoever reads the
// record: a link-local answer is the cloud metadata endpoint, a private one is
// an internal service, and a loopback one is the host itself.
func checkPublicIP(host string, ip net.IP) error {
	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("%w: %q is the unspecified address", ErrPrivateOriginHost, host)
	case ip.IsLoopback():
		return fmt.Errorf("%w: %q is a loopback address", ErrPrivateOriginHost, host)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.169.254 lives here. It is the single highest-value target an
		// untrusted Origin could name, so the message says so.
		return fmt.Errorf("%w: %q is a link-local address (the cloud metadata endpoint range)",
			ErrPrivateOriginHost, host)
	case ip.IsPrivate():
		// RFC 1918 and IPv6 unique-local.
		return fmt.Errorf("%w: %q is a private address", ErrPrivateOriginHost, host)
	case isSharedAddressSpace(ip):
		return fmt.Errorf("%w: %q is in carrier-grade NAT space", ErrPrivateOriginHost, host)
	}
	return nil
}

// cgnat is RFC 6598 shared address space, which net.IP has no predicate for
// and which is as unroutable from the public internet as RFC 1918.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isSharedAddressSpace(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && cgnat.Contains(v4)
}
