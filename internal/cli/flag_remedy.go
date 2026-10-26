package cli

import (
	"errors"
	"fmt"

	proxyadapter "code.eitanity.com/kanonarion/internal/adapters/proxy/direct"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	fetchports "code.eitanity.com/kanonarion/internal/fetch/ports"
	vulnports "code.eitanity.com/kanonarion/internal/vuln/ports"
)

// flagRemedies are the ways through an adapter's refusal that are a flag. The
// adapter cannot know which command is running, so the remedy is added here,
// and only for a command that defines the flag.
var flagRemedies = []struct {
	sentinel error
	flag     string
	remedy   string
}{
	{proxyadapter.ErrPlainHTTP, "insecure", "pass --insecure to allow it; the modules fetched are then recorded unverified"},
	{fetchports.ErrVCSToolMissing, "skip-vcs-verify", "pass --skip-vcs-verify to record the run as checksum-verified only"},
	{fetchdomain.ErrEmptyVCSHostAllowlist, "skip-vcs-verify", "to skip the git leg entirely, pass --skip-vcs-verify; checksum-database verification still runs"},
	{vulnports.ErrSnapshotIntegrity, "fresh", "--fresh re-fetches the advisory database, which overwrites the stored snapshot"},
	{vulnports.ErrSnapshotEmpty, "fresh", "run it again with --fresh to download a populated advisory database"},
	{vulnports.ErrSnapshotUnavailable, "fresh", "run it again with --fresh to re-fetch the advisory database"},
}

// withFlagRemedy appends the remedy for the first refusal in err's chain that
// this invocation's command can act on, and leaves every other error alone.
func withFlagRemedy(err error) error {
	if err == nil || invokedCmd == nil {
		return err
	}
	for _, r := range flagRemedies {
		if errors.Is(err, r.sentinel) && invokedCmd.Flags().Lookup(r.flag) != nil {
			return fmt.Errorf("%w\n  %s", err, r.remedy)
		}
	}
	return err
}
