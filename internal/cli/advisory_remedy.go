package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	osvdb "github.com/eitanity/kanonarion/internal/vuln/adapters/vulndb/osv"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// discardSetAside drops the set-aside rows an inspection read meets: the
// command's own read reports them, and once is the contract.
func discardSetAside([]recordseal.SetAsideRow) {}

// storedSnapshots lists the advisory-database snapshots the store holds, newest
// first. It opens the store for inspection only, so naming a remedy writes
// nothing; tests replace it.
var storedSnapshots = func(ctx context.Context) ([]vuldomain.DatabaseSnapshot, error) {
	st, err := openStorage(storage.Request{StoreRoot: storeRoot, Intent: storage.IntentInspect, Config: activeConfig,
		SetAside: discardSetAside})
	if errors.As(err, new(*storage.NotFoundError)) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = storageCloser(st)() }()           //nolint:errcheck // an inspection writes nothing
	return st.Vulnerabilities.ListDatabaseSnapshots(ctx) //nolint:wrapcheck // the caller names the read
}

// withAdvisoryRemedy appends to an advisory-database download refusal what the
// command that hit it accepts instead. The adapter cannot know which command is
// running, so offline renders that here from the snapshots the store holds.
func withAdvisoryRemedy(ctx context.Context, err error, offline func(held []vuldomain.DatabaseSnapshot) string) error {
	if !errors.Is(err, osvdb.ErrNetworkForbidden) {
		return err
	}
	held, lerr := storedSnapshots(ctx)
	switch {
	case lerr != nil:
		return fmt.Errorf("%w\n  the snapshots this store holds could not be counted: %v", err, lerr) //nolint:errorlint // the refusal is the chain; the count failure is context
	case len(held) == 0:
		return fmt.Errorf("%w\n  the store holds no advisory-database snapshot, so nothing here can judge a scan without the download", err)
	}
	return fmt.Errorf("%w\n  %s\n  to see what is held: kanonarion vuln-snapshot-list", err, offline(held))
}

// scanOffline is the remedy of a command whose one advisory flag is --fresh.
func scanOffline(fresh bool) func([]vuldomain.DatabaseSnapshot) string {
	return func(held []vuldomain.DatabaseSnapshot) string {
		if !fresh {
			return fmt.Sprintf("the store holds %d snapshot(s)", len(held))
		}
		return fmt.Sprintf("the store holds %d snapshot(s): drop --fresh and the scan is judged against the newest, %s@%s",
			len(held), held[0].Source(), held[0].Version())
	}
}

// rescanOffline pins the re-scan to the newest snapshot the store holds.
func rescanOffline(walkID string) func([]vuldomain.DatabaseSnapshot) string {
	return func(held []vuldomain.DatabaseSnapshot) string {
		return fmt.Sprintf("the store holds %d snapshot(s); re-scan against the newest without the download:\n    "+
			"kanonarion vuln-scan-rescan %s --snapshot-source %s --snapshot-version %s",
			len(held), walkID, held[0].Source(), held[0].Version())
	}
}
