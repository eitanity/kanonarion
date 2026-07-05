// Package clock provides ports.Clock implementations for production and tests.
package clock

import "time"

// System is the production clock: returns time.Now.
type System struct{}

// Now returns the current UTC time.
func (System) Now() time.Time { return time.Now().UTC() }

// Fixed is a deterministic clock for tests. It always returns the same instant.
type Fixed struct {
	T time.Time
}

// Now returns the fixed instant.
func (f Fixed) Now() time.Time { return f.T }
