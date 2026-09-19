package gotoolchain

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
)

// SupportedTargets is every platform this resolver's toolchain can build for,
// as `go tool dist list` prints them, in the toolchain's own order.
//
// It is the only authority worth asking. The set moves between Go releases — a
// port is added, a port is dropped — so a list compiled into this binary would
// refuse a pair the toolchain in hand builds for perfectly well, and accept one
// it has since dropped. Asking the toolchain makes the answer a property of the
// installed Go rather than of kanonarion's release date.
//
// It costs one subprocess and is therefore asked only when a caller declared a
// target. The default path never reaches here: a target nobody declared is the
// host, and the host needs no validating.
func (r *Resolver) SupportedTargets(ctx context.Context) ([]goenv.Target, error) {
	bin := r.goBin()
	if cached, ok := loadDistList(bin); ok {
		return cached, nil
	}
	// The environment is deliberately NOT this resolver's target: `go tool dist
	// list` reports what the toolchain can build for, and a GOOS in its own
	// environment would have it report about one platform. It is the one child
	// of this package that must not be told a target.
	cmd := childproc.CommandContext(ctx, bin, "tool", "dist", "list") // #nosec G204 -- binary path is either "go" (hardcoded) or caller-supplied and trusted
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go tool dist list: %w", err)
	}
	var targets []goenv.Target
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		t, perr := goenv.ParseTarget(line)
		if perr != nil {
			return nil, fmt.Errorf("go tool dist list printed %q, which is not a GOOS/GOARCH pair: %w", line, perr)
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		// The command succeeded and named no platform. A toolchain that cannot
		// say what it builds for is not one a declared target can be checked
		// against, and answering "unsupported" from it would refuse every pair.
		return nil, fmt.Errorf("go tool dist list named no platform; this toolchain cannot say what it builds for")
	}
	storeDistList(bin, targets)
	return targets, nil
}

// Supports reports whether this resolver's toolchain builds for t, and the list
// it was checked against so a refusal can name what it offers.
//
// An undeclared target is supported without asking: it is the host, and the
// toolchain running on a host builds for it.
func (r *Resolver) Supports(ctx context.Context, t goenv.Target) (bool, []goenv.Target, error) {
	if !t.Declared() {
		return true, nil, nil
	}
	targets, err := r.SupportedTargets(ctx)
	if err != nil {
		return false, nil, err
	}
	for _, s := range targets {
		if s == t {
			return true, targets, nil
		}
	}
	return false, targets, nil
}

// distLists memoises `go tool dist list` per go binary, which is what "queried
// once from the toolchain in hand" means when one process runs several children
// under one toolchain. Only successes are stored: a failed probe is a fact about
// this moment rather than about the toolchain, and caching it would make one
// stumble answer for the rest of the run.
var (
	distListMu sync.Mutex
	distLists  = map[string][]goenv.Target{}
)

func loadDistList(bin string) ([]goenv.Target, bool) {
	distListMu.Lock()
	defer distListMu.Unlock()
	list, ok := distLists[bin]
	return list, ok
}

func storeDistList(bin string, list []goenv.Target) {
	distListMu.Lock()
	defer distListMu.Unlock()
	distLists[bin] = list
}
