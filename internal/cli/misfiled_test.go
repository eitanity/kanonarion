package cli

import (
	"errors"
	"fmt"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/recordseal"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// A misfiled record is evidence in doubt whichever store raised it, including
// one with no integrity sentinel of its own.
func TestExitCodeForError_MisfiledIsIntegrity(t *testing.T) {
	err := recordseal.CheckFiled("native record", "native_records", "", recordseal.Key("a@v1", "b@v1"))
	if got := ExitCodeForError(fmt.Errorf("listing native records: %w", err)); got != ExitIntegrity {
		t.Fatalf("exit = %d, want %d", got, ExitIntegrity)
	}
}

// A walk refused as misfiled is stated in the refusal's own words; any other
// walk integrity failure keeps the message it had.
func TestWalkIntegrityRefusal_StatesAMisfiledWalk(t *testing.T) {
	misfiled := recordseal.CheckFiled("walk record", "walks", "", recordseal.Key("A", "B"))
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: %w", walkports.ErrWalkIntegrity, misfiled), misfiled.Error()},
		{fmt.Errorf("%w: content hash mismatch", walkports.ErrWalkIntegrity), "walk record \"A\" failed integrity check"},
	} {
		got := walkIntegrityRefusal(tc.err, `walk record "A" failed integrity check`)
		var ee *exitError
		if !errors.As(got, &ee) || ee.code != ExitIntegrity || ee.msg != tc.want {
			t.Errorf("refusal = %v, want exit %d with %q", got, ExitIntegrity, tc.want)
		}
	}
}
