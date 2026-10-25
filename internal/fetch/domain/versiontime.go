package domain

import (
	"fmt"
	"time"
)

// VersionTime is the time the module source (proxy or module cache) reported
// for a version in its .info, as time.RFC3339Nano in UTC. Empty means unknown:
// the source gave none, or the record predates the field.
type VersionTime string

// VersionTimeOf records t. A zero time is a source that gave none, so it is
// unknown rather than 0001-01-01.
func VersionTimeOf(t time.Time) VersionTime {
	if t.IsZero() {
		return ""
	}
	return VersionTime(t.UTC().Format(time.RFC3339Nano))
}

// ParseVersionTime parses a recorded value; ok is false when it is unknown. It is
// a free function so the published alias of VersionTime grows no behaviour.
func ParseVersionTime(v VersionTime) (t time.Time, ok bool, err error) {
	if v == "" {
		return time.Time{}, false, nil
	}
	t, err = time.Parse(time.RFC3339Nano, string(v))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parsing version_time %q: %w", string(v), err)
	}
	return t, true, nil
}

// MarshalJSON renders an unknown VersionTime as null.
func (v VersionTime) MarshalJSON() ([]byte, error) {
	if v == "" {
		return []byte("null"), nil
	}
	b, err := marshalJSONString(string(v))
	if err != nil {
		return nil, fmt.Errorf("marshalling version_time: %w", err)
	}
	return b, nil
}
