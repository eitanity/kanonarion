package cli

import (
	"errors"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func isWalkNotFound(err error) bool  { return errors.Is(err, walkports.ErrWalkNotFound) }
func isWalkIntegrity(err error) bool { return errors.Is(err, walkports.ErrWalkIntegrity) }

// walkNotServable returns the refusal for a walk this build cannot reproduce,
// stated without the read's wrapping: it names the walk and both remedies, and
// exits 4. Nil when err is not that refusal.
func walkNotServable(err error) error {
	var none *recordseal.NothingServable
	if errors.As(err, &none) {
		return none
	}
	return nil
}
