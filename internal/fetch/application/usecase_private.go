package application

import (
	"context"
	"errors"
	"fmt"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// ErrPrivateModuleUnanchored refuses a private module when no project go.sum
// was given: the module-cache route has nothing else to verify its bytes by.
var ErrPrivateModuleUnanchored = errors.New("a private module is read only from the module cache against a project go.sum, and none was given")

// WithPrivateModules routes every module match names as private through the
// module-cache route, anchored on the project go.sum in anchor, instead of the
// proxy path. match returns the variable that made the module private. The
// proxy the use case holds must send those modules to the module cache too.
func (uc *FetchModuleUseCase) WithPrivateModules(match func(path string) (string, bool), anchor ports.SumDBClient) *FetchModuleUseCase {
	uc.private = match
	uc.privateAnchor = anchor
	return uc
}

// privateRoute reports whether req is a private module, and how to read it.
func (uc *FetchModuleUseCase) privateRoute(req FetchRequest) (cacheRoute, bool, error) {
	if uc.private == nil {
		return cacheRoute{}, false, nil
	}
	name, ok := uc.private(req.Coordinate.Path())
	if !ok {
		return cacheRoute{}, false, nil
	}
	if uc.privateAnchor == nil {
		return cacheRoute{}, true, fmt.Errorf("%s matches %s: %w; %s", req.Coordinate.Path(), name, ErrPrivateModuleUnanchored,
			domain2.PrivateModuleRemedy(req.Coordinate))
	}
	return cacheRoute{
		anchor: uc.privateAnchor,
		detail: fmt.Sprintf("private module (%s): read from the module cache, fetched there by the go command as the user, "+
			"and verified against the project go.sum; checksum database not consulted; VCS cross-verification not run", name),
		goModDetail: fmt.Sprintf("go.mod-only fetch of a private module (%s); go.mod read from the module cache "+
			"and verified against the project go.sum; zip not read", name),
		vcs: domain2.LegPrivateModule,
	}, true, nil
}

// executeOffProxy takes the module-cache route for --from-modcache and for a
// private module; handled reports that it took req.
func (uc *FetchModuleUseCase) executeOffProxy(ctx context.Context, req FetchRequest) (FetchResult, bool, error) {
	if uc.modcache {
		res, err := uc.executeModcache(ctx, req)
		return res, true, err
	}
	route, private, err := uc.privateRoute(req)
	switch {
	case err != nil:
		return FetchResult{}, true, err
	case private:
		res, err := uc.executeFromCache(ctx, req, route)
		return res, true, err
	}
	return FetchResult{}, false, nil
}
