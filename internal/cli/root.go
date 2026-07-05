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

			// 2. Load config from store root; errors fall back to defaults.
			activeConfig = loadStoreConfig(storeRoot)

			// 3. Apply config defaults for flags not explicitly set (flag > config > default).
			if !cmd.Flags().Changed("log-level") {
				logLevel = activeConfig.Preferences.LogLevel
			}
			if !cmd.Flags().Changed("json") {
				jsonOut = activeConfig.Preferences.JSON
			}

			// 4. Install one process-wide logger now that the format (--json) is
			// resolved, so subsystems that log via slog.Default — e.g. the
			// vulnerability scanner and OSV client — emit the same single format
			// on stderr as every injected logger.
			slog.SetDefault(buildLogger(logLevel, stderr))
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
		newInterfaceListCmd(stdout, stderr),
		newSymbolFindCmd(stdout, stderr),
		newSymbolContextCmd(stdout, stderr),
		newCallGraphCmd(stdout, stderr),
		newCallGraphShowCmd(stdout, stderr),
		newCallGraphListCmd(stdout, stderr),
		newCallersCmd(stdout, stderr),
		newCalleesCmd(stdout, stderr),
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
		newConfigCmd(stdout, stderr),
		newStoreCmd(stdout, stderr),
		newContextCmd(stdout, stderr),
		newReachabilityCmd(stdout, stderr),
		newInspectCmd(stdout, stderr),
		newAuditCmd(stdout, stderr),
		newDirectivesCmd(stdout, stderr),
		newGoDebugCmd(stdout, stderr),
		newVendorCmd(stdout, stderr),
		newFIPSCmd(stdout, stderr),
		newLatestCmd(stdout, stderr),
		newProvenanceCmd(stdout, stderr),
		newUseCmd(stdout, stderr),
		newLocalCmd(stdout, stderr),
	)
	return root
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
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("execute root command: %w", err)
	}
	return nil
}
