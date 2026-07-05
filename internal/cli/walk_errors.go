package cli

import (
	"errors"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func isWalkNotFound(err error) bool  { return errors.Is(err, walkports.ErrWalkNotFound) }
func isWalkIntegrity(err error) bool { return errors.Is(err, walkports.ErrWalkIntegrity) }
