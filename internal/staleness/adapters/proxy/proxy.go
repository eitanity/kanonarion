// Package proxy adapts the module-proxy client to the staleness context's
// LatestResolver port.
//
// Its whole job is one translation: turning "the proxy has no such path" into
// ports.ErrPathAbsent, so the major probe can tell a definitive absence (stop,
// and record the negative) from a transport failure (record nothing).
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	directproxy "github.com/eitanity/kanonarion/internal/adapters/proxy/direct"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/staleness/ports"
)

// Bridge adapts *direct.Proxy to ports.LatestResolver.
type Bridge struct {
	proxy *directproxy.Proxy
}

// New wraps a module-proxy client.
func New(p *directproxy.Proxy) *Bridge { return &Bridge{proxy: p} }

var _ ports.LatestResolver = (*Bridge)(nil)

// LatestInfo resolves @latest for path, reporting an unpublished path as
// ports.ErrPathAbsent.
func (b *Bridge) LatestInfo(ctx context.Context, path string) (ports.LatestInfo, error) {
	info, err := b.proxy.LatestInfo(ctx, path)
	if err != nil {
		if isAbsent(err) {
			return ports.LatestInfo{}, fmt.Errorf("%w: %s", ports.ErrPathAbsent, path)
		}
		return ports.LatestInfo{}, fmt.Errorf("resolving %s@latest: %w", path, err)
	}
	return ports.LatestInfo{Version: info.Version, Time: info.Time}, nil
}

// isAbsent reports whether err means the proxy has no such path.
//
// 410 Gone is included alongside 404: the module index serves it for a path it
// has withdrawn, and both are the same definitive "not published here" as far
// as a major probe is concerned. A 429 or 5xx is deliberately not included —
// those are failures, and a failure must not be recorded as an absent major.
func isAbsent(err error) bool {
	if errors.Is(err, directproxy.ErrNotFound) {
		return true
	}
	var status *fetchdomain.ProxyStatusError
	if errors.As(err, &status) {
		return status.StatusCode == http.StatusNotFound || status.StatusCode == http.StatusGone
	}
	return false
}
