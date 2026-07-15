package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestVerificationStatus_IsVerified(t *testing.T) {
	verified := []domain.VerificationStatus{
		domain.Verified,
		domain.VerifiedBySumDBOnly,
		domain.VerifiedByGoSum,
		domain.LocalSource,
	}
	for _, s := range verified {
		if !s.IsVerified() {
			t.Errorf("status %q should be positively verified", s)
		}
	}

	// Hard failures and un-analysed/unknown outcomes are alike NOT positively
	// verified: only a trust anchor flips IsVerified to true.
	notVerified := []domain.VerificationStatus{
		domain.UnverifiedNoSumDB,
		domain.UnverifiedMissingOrigin,
		domain.UnverifiedHashMismatch,
		domain.UnverifiedGoModInconsistent,
		domain.UnverifiedNoVCS,
		domain.UnverifiedVCSToolMissing,
		"",
		"something-made-up",
	}
	for _, s := range notVerified {
		if s.IsVerified() {
			t.Errorf("status %q should not be positively verified", s)
		}
	}
}
