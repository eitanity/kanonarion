package cli

import "code.eitanity.com/kanonarion/internal/adapters/goenv"

// refusePrivateCoordinate refuses a private module named on its own: with no
// project go.sum there is nothing to verify the module-cache bytes against,
// and the proxy route would name the path to a proxy. Not positional, it is
// @latest that is refused: only a proxy could resolve it.
func refusePrivateCoordinate(path string, positional bool) error {
	if _, ok := goenv.NoProxy(path); !ok {
		return nil
	}
	if !positional {
		return &exitError{code: ExitConfig, msg: path + " matches GOPRIVATE/GONOPROXY: @latest is resolved only by a proxy; " +
			"name the version the project requires"}
	}
	return &exitError{code: ExitConfig, msg: path + " matches GOPRIVATE/GONOPROXY: kanonarion reads a private module " +
		"only from the module cache against a project go.sum; run from the project with --gomod"}
}
