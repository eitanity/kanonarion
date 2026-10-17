package sqlite

import (
	"errors"
	"testing"
)

func TestCloseError_NamesTheFailedClose(t *testing.T) {
	cause := errors.New("disk gone")
	if err := closeError(cause); !errors.Is(err, cause) || err.Error() != "closing database: disk gone" {
		t.Errorf("closeError = %v, want the cause wrapped as a database close", err)
	}
	if err := closeError(nil); err != nil {
		t.Errorf("closeError(nil) = %v, want nil", err)
	}
}
