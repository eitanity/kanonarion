package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	// A new invocation starts from a known state, not from whatever the last
	// one left in the process-wide variables the resolve* helpers write.
	resetInvocationState()

	root := &cobra.Command{
		Use:     "kanonarion",
		Short:   "Dependency assurance software for Go",
		Version: resolveVersion(),
		// Runtime errors must not dump the cobra Usage/help block (it lands on
		// stdout and corrupts machine-readable output). main already prints
		// the returned error to stderr and sets a non-zero exit code, so
		// silence cobra's own error/usage printing here.
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// 1. Resolve store root (flag > env var > default).
			if !cmd.Flags().Changed("store-root") {
				if envStore := os.Getenv("KANONARION_STORE"); envStore != "" {
					storeRoot = envStore
				}
			}

			// 2. Refuse a store root that is not there, unless this command
			// declared that it creates one. It happens here, before the config
			// load and before any command body opens the store, because the
			// defect is not the wrong answer but the directory: a check made
			// after the open would still leave a store behind.
			storeIntent = storeIntentOf(cmd)
			if err := requireStoreRoot(storeRoot); err != nil {
				return err
			}

			// 3. Load config from store root. A store with no config file
			// resolves to the built-in defaults and is not an error. A file
			// that exists and cannot be loaded is a refusal: running on
			// built-in defaults would evaluate every later answer against a
			// policy the operator did not write, and say nothing about it.
			// Commands that exist to show or repair the file are exempt, or
			// one typo would make the file unfixable by the tool that wrote it.
			activeConfig, activeConfigErr = loadStoreConfig(storeRoot)
			if activeConfigErr != nil && !usableWithRejectedConfig(cmd) {
				return &exitError{code: ExitConfig, msg: activeConfigErr.Error()}
			}

			// 4. Apply config defaults for flags not explicitly set (flag > config > default).
			if !cmd.Flags().Changed("log-level") {
				logLevel = activeConfig.Preferences.LogLevel
			}
			if !cmd.Flags().Changed("json") {
				jsonOut = activeConfig.Preferences.JSON
			}

			// 5. Install one process-wide logger now that the format (--json) is
			// resolved, so subsystems that log via slog.Default — e.g. the
			// vulnerability scanner and OSV client — emit the same single format
			// on stderr as every injected logger.
			slog.SetDefault(buildLogger(logLevel, stderr))

			// 6. An exempted command still says what happened. Reaching here
			// with a rejection means this command is part of the repair path,
			// and its answers describe the built-in defaults rather than the
			// file. It goes to stderr so a --json document on stdout stays
			// parseable; a command whose stdout is a standalone document
			// (config show) also renders it there.
			if activeConfigErr != nil {
				if _, err := fmt.Fprintf(stderr, "warning: %v\n", activeConfigErr); err != nil {
					return fmt.Errorf("writing config rejection notice: %w", err)
				}
			}
			return nil
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("kanonarion {{.Version}}\n")
	root.PersistentFlags().StringVar(&storeRoot, "store-root", defaultStoreRoot(), "root directory for blobs and SQLite")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "log level: debug|info|warn|error")
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "emit output as JSON")

	root.AddCommand(
		newFetchCmd(stdout, stderr),
		newWalkCmd(stdout, stderr),
		newWalkListCmd(stdout, stderr),
		newWalkShowCmd(stdout, stderr),
		newWalkDiffCmd(stdout, stderr),
		newVerificationCoverageCmd(stdout, stderr),
		newPolicyCmd(stdout, stderr),
		newLicenseCmd(stdout, stderr),
		newLicenseListCmd(stdout, stderr),
		newLicenseDiffCmd(stdout, stderr),
		newLicenseCompatCmd(stdout, stderr),
		newNoticeCmd(stdout, stderr),
		newExamplesCmd(stdout, stderr),
		newExamplesShowCmd(stdout, stderr),
		newExamplesFindCmd(stdout, stderr),
		newExamplesListCmd(stdout, stderr),
		newInterfaceCmd(stdout, stderr),
		newInterfaceShowCmd(stdout, stderr),
		newInterfaceDiffCmd(stdout, stderr),
		newInterfaceListCmd(stdout, stderr),
		newSymbolFindCmd(stdout, stderr),
		newSymbolContextCmd(stdout, stderr),
		newCallGraphCmd(stdout, stderr),
		newCallGraphShowCmd(stdout, stderr),
		newCallGraphListCmd(stdout, stderr),
		newCallersCmd(stdout, stderr),
		newCalleesCmd(stdout, stderr),
		newImplementersCmd(stdout, stderr),
		newCapabilityCmd(stdout, stderr),
		newDependentsCmd(stdout, stderr),
		NewExtractCmd(stdout, stderr),
		newVulnCmd(stdout, stderr),
		newVulnScanCmd(stdout, stderr),
		newVulnScanListCmd(stdout, stderr),
		newVulnScanShowCmd(stdout, stderr),
		newVulnShowCmd(stdout, stderr),
		newVulnByIDCmd(stdout, stderr),
		newVulnSnapshotListCmd(stdout, stderr),
		newVulnSnapshotShowCmd(stdout, stderr),
		newVulnScanRescanCmd(stdout, stderr),
		newVulnScanHistoryCmd(stdout, stderr),
		newVulnScanDiffCmd(stdout, stderr),
		newSBOMCmd(stdout, stderr),
		newSBOMShowCmd(stdout, stderr),
		newSBOMListCmd(stdout, stderr),
		newConfigCmd(stdout),
		newStoreCmd(stdout, stderr),
		newContextCmd(stdout, stderr),
		newReachabilityCmd(stdout, stderr),
		newInspectCmd(stdout, stderr),
		newAuditCmd(stdout, stderr),
		newDirectivesCmd(stdout, stderr),
		newGoDebugCmd(stdout, stderr),
		newVendorCmd(stdout, stderr),
		newFIPSCmd(stdout, stderr),
		newNativeCmd(stdout, stderr),
		newLatestCmd(stdout, stderr),
		newProvenanceCmd(stdout, stderr),
		newUseCmd(stdout, stderr),
		newLocalCmd(stdout, stderr),
	)

	return root
}

// installDefaultSubcommands adds cobra's own `help` and `completion` and gives
// them a store intent, which cobra has no notion of.
//
// They open no store, so the only honest declaration is "none". Without one
// they would inherit the safe default and refuse to print help on a machine
// that has no store yet — a refusal about a store the command never opens.
//
// It is called by the two entry points that need the real, executable tree —
// Run before Execute, and RegisteredCommands — rather than by newRootCmd,
// because the tree newRootCmd returns is what this package's own guards read,
// and cobra's built-ins are not this package's to answer for. Both Init calls
// are idempotent, so the ones Execute makes later are no-ops.
func installDefaultSubcommands(root *cobra.Command) {
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, name := range []string{"help", "completion"} {
		if cmd, _, err := root.Find([]string{name}); err == nil && cmd != root {
			declareStoreIntentTree(cmd, StoreIntentNone)
		}
	}
}

// declareStoreIntentTree annotates cmd and everything under it, for the
// command trees this package does not construct itself.
func declareStoreIntentTree(cmd *cobra.Command, intent string) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[annotationStoreIntent] = intent
	for _, sub := range cmd.Commands() {
		declareStoreIntentTree(sub, intent)
	}
}

// usageErr returns a non-zero usage error for a command invoked with the
// wrong number of positional arguments. It is used instead of cmd.Help,
// which returns nil and so exits 0 — hiding the misuse from scripts and
// CI. The usage line is included so the message is still actionable.
func usageErr(cmd *cobra.Command) error {
	return fmt.Errorf("invalid arguments\nusage: %s", cmd.UseLine())
}

// Run is the testable entry point for the kanonarion CLI.
func Run(args []string, stdout, stderr io.Writer) error {
	// Cancel the command context on SIGINT, SIGTERM, or SIGHUP so that
	// in-progress walks can save their walk records before the process exits.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	root := newRootCmd(stdout, stderr)
	installDefaultSubcommands(root)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("execute root command: %w", err)
	}
	return nil
}
