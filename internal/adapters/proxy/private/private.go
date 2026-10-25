// Package private routes each module between the configured module proxy and
// the module cache: a module the private-module matcher names is never sent to
// a proxy, and every other module takes the proxy exactly as before.
package private

import (
	"context"
	"fmt"
	"sync"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// Router is a ports.ModuleProxy that sends private modules to the module cache.
type Router struct {
	public   ports.ModuleProxy
	match    func(path string) (string, bool)
	newCache func(context.Context) (ports.ModuleProxy, error)

	once     sync.Once
	cache    ports.ModuleProxy
	cacheErr error
}

var _ ports.ModuleProxy = (*Router)(nil)

// New routes the modules match names to the proxy newCache builds, and every
// other module to public. newCache runs once, on the first private module, so
// a run with none pays nothing for it.
func New(public ports.ModuleProxy, match func(path string) (string, bool), newCache func(context.Context) (ports.ModuleProxy, error)) *Router {
	return &Router{public: public, match: match, newCache: newCache}
}

func (r *Router) route(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.ModuleProxy, error) {
	name, ok := r.match(coord.Path())
	if !ok {
		return r.public, nil
	}
	r.once.Do(func() { r.cache, r.cacheErr = r.newCache(ctx) })
	if r.cacheErr != nil {
		return nil, fmt.Errorf("%s matches %s, so it is read from the module cache: %w", coord.Path(), name, r.cacheErr)
	}
	return r.cache, nil
}

// Info returns the module's .info from the route it takes.
func (r *Router) Info(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.ModuleInfo, error) {
	p, err := r.route(ctx, coord)
	if err != nil {
		return ports.ModuleInfo{}, err
	}
	return p.Info(ctx, coord) //nolint:wrapcheck // the routed adapter's error is this one's
}

// Download returns the module's zip and go.mod from the route it takes.
func (r *Router) Download(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.ModuleDownload, error) {
	p, err := r.route(ctx, coord)
	if err != nil {
		return ports.ModuleDownload{}, err
	}
	return p.Download(ctx, coord) //nolint:wrapcheck // as above
}

// DownloadGoMod returns the module's go.mod from the route it takes.
func (r *Router) DownloadGoMod(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.GoModDownload, error) {
	p, err := r.route(ctx, coord)
	if err != nil {
		return ports.GoModDownload{}, err
	}
	return p.DownloadGoMod(ctx, coord) //nolint:wrapcheck // as above
}
