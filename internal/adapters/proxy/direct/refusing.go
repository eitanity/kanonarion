package direct

import (
	"context"
	"errors"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// IsRefusal reports whether err is a resolution refusal — the environment
// forbidding proxy fetching (GOPROXY=off) or naming a fetch route this adapter
// does not implement (GOPROXY=direct) — as opposed to a malformed proxy URL.
//
// It exists so a wiring can tell "there is no proxy to build, and that is the
// operator's decision" from "the proxy you asked for is wrong", which are the
// same return value from New but not the same situation.
func IsRefusal(err error) bool {
	return errors.Is(err, ErrProxyOff) || errors.Is(err, ErrProxyDirectUnsupported)
}

// refusingProxy is the ModuleProxy for an environment that forbids proxy
// fetching: every method returns the refusal, and none of them opens a socket.
//
// It exists because most commands wire a proxy they may never use. The store is
// read by callgraph, interface, licence, capability, vendor, extract, ingest and
// the rest, and an operator inside an air gap has to be able to run all of them
// against a warm store; failing to construct the container would take those away
// on the same declaration that is supposed to protect them. So the container
// keeps its adapter, the read paths keep working, and the refusal lands exactly
// where a fetch is attempted — still before any network I/O.
type refusingProxy struct{ err error }

// Refusing returns a ModuleProxy that answers every request with cause.
//
// cause is the error New returned; passing anything else would state a reason
// the resolution did not give.
func Refusing(cause error) ports.ModuleProxy { return refusingProxy{err: cause} }

func (r refusingProxy) Info(context.Context, coordinate.ModuleCoordinate) (ports.ModuleInfo, error) {
	return ports.ModuleInfo{}, r.err
}

func (r refusingProxy) Download(context.Context, coordinate.ModuleCoordinate) (ports.ModuleDownload, error) {
	return ports.ModuleDownload{}, r.err
}

func (r refusingProxy) DownloadGoMod(context.Context, coordinate.ModuleCoordinate) (ports.GoModDownload, error) {
	return ports.GoModDownload{}, r.err
}
