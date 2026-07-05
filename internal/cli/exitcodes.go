package cli

// Exit codes.
const (
	ExitOK        = 0
	ExitPartial   = 1
	ExitFailed    = 2
	ExitCancelled = 3
	// ExitNotFound signals that a record requested by ID (walk, scan, run,
	// directive scan,...) does not exist. Distinct from ExitConfig so scripts
	// can tell 'no such record' from a policy denial.
	ExitNotFound  = 4
	ExitIntegrity = 10
	ExitConfig    = 20
)
