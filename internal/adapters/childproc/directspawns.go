package childproc

// DirectSpawns is the closed set of production functions allowed to build a
// child process with os/exec directly instead of through this package, keyed
// "<repo-relative package dir> <function>" and valued with the reason.
//
// It exists because the alternative is an unexplained divergence. A reader who
// finds an exec.Command outside this package has no way to tell a considered
// exemption from an oversight, and this class has already regrown once: the
// wrapper was written, the sites that prompted it were converted, and eleven
// others were added or left afterwards. TestEveryChildProcessIsHardened reads
// this map, so a new direct spawn fails until somebody writes down why.
//
// The map must drain. An entry naming a function that no longer spawns a child
// fails as loudly as an unregistered one, so a permission cannot outlive the
// call it was granted for.
//
// "The child is short-lived" is not on its own a reason. The hardening costs a
// process-group attribute and a cancel function, so brevity buys nothing that
// would pay for a second regime. A reason has to say why the default cannot
// apply at all.
var DirectSpawns = map[string]string{
	"internal/adapters/factstore/sqlite NewAuditLog": "chattr is not a Go or git child and has nothing to harden: " +
		"one ioctl on a path this process just created, no context in scope, no grandchildren, " +
		"no working set to strand, and its error is deliberately discarded because the attribute " +
		"is unavailable on most filesystems. Setpgid would take it out of the terminal's group " +
		"and gain nothing, since there is no cancellation for the group kill to serve",
}
