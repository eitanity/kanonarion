package cli

import "code.eitanity.com/kanonarion/internal/exitcode"

// Exit codes; the taxonomy is documented in package exitcode.
const (
	ExitOK        = exitcode.OK
	ExitPartial   = exitcode.Partial
	ExitFailed    = exitcode.Failed
	ExitCancelled = exitcode.Cancelled
	ExitNotFound  = exitcode.NotFound
	ExitPolicy    = exitcode.Policy
	ExitIntegrity = exitcode.Integrity
	ExitConfig    = exitcode.Config
)
