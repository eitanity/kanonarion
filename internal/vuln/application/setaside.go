package application

import (
	"context"
	"errors"
	"log/slog"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// SetAsideReporter states the stored generations a scan's writes and reuse
// reads set aside because this build cannot reproduce them. Module scans run
// concurrently, so it must be safe to call from several goroutines.
type SetAsideReporter func(rows []recordseal.SetAsideRow)

// WithSetAsideReporter sets where the scan states set-aside generations. Without
// one they are logged at warn level, so they are never dropped unseen; returns
// the receiver for chaining.
func (uc *ScanModuleUseCase) WithSetAsideReporter(r SetAsideReporter) *ScanModuleUseCase {
	uc.setAside = r
	return uc
}

// reportSetAside states rows through the reporter, or the logger when none is
// set.
func reportSetAside(r SetAsideReporter, logger *slog.Logger, rows []recordseal.SetAsideRow) {
	if len(rows) == 0 {
		return
	}
	if r != nil {
		r(rows)
		return
	}
	for _, row := range rows {
		logger.Warn("set aside a stored "+row.Kind+" generation",
			"generation", row.Label(), "meaning", recordseal.SetAsideRemedy)
	}
}

// putRecord appends record and states any generation the write set aside. The
// write has committed when the store reports a set-aside, so that report is not
// a failure; every other error is.
func putRecord(ctx context.Context, store ports.VulnerabilityStore, record domain.VulnerabilityRecord, r SetAsideReporter, logger *slog.Logger) error {
	err := store.PutVulnerabilityRecord(ctx, record)
	var aside *recordseal.SetAside
	if errors.As(err, &aside) {
		reportSetAside(r, logger, aside.Rows)
		return nil
	}
	return err //nolint:wrapcheck // every caller names the write it attempted
}

// setAsideReporter is the reporter the walk scan's own writes use: the module
// scanner's, so one command states every set-aside generation in one place.
func (uc *ScanWalkUseCase) setAsideReporter() SetAsideReporter {
	if uc.moduleScanner == nil {
		return nil
	}
	return uc.moduleScanner.setAside
}
