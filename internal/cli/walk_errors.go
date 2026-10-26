package cli

import (
	"errors"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

func isWalkNotFound(err error) bool  { return errors.Is(err, walkports.ErrWalkNotFound) }
func isWalkIntegrity(err error) bool { return errors.Is(err, walkports.ErrWalkIntegrity) }

// walkIntegrityRefusal is the exit-10 refusal for a walk that failed its
// integrity check. A misfiled walk is stated in its own words, which name the
// row, the table and the remedy; anything else keeps msg.
func walkIntegrityRefusal(err error, msg string) error {
	var misfiled *recordseal.Misfiled
	if errors.As(err, &misfiled) {
		msg = misfiled.Error()
	}
	return &exitError{code: ExitIntegrity, msg: msg}
}

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
