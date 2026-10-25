package recordseal

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// Filed is one value a store selected a row by, beside the value sealed in the
// record that row holds. Column is empty for the row's key.
type Filed struct {
	Column string
	Field  string
	Filed  string
	Sealed string
}

// Key is the row key a read looked the record up by, against the key sealed in
// it.
func Key(filed, sealed string) Filed {
	return Filed{Filed: filed, Sealed: sealed}
}

// Column is a selection column a read filtered on, against the field sealed in
// the record.
func Column(column, field, filed, sealed string) Filed {
	return Filed{Column: column, Field: field, Filed: filed, Sealed: sealed}
}

// Misfiled is a record whose seal verifies but which sits under a key or a
// selection value its seal does not carry. The seal says the bytes are genuine;
// it does not say they belong where they were found, so the read refuses.
type Misfiled struct {
	// Kind names the record in prose, such as "licence record".
	Kind  string
	Table string
	// Store is where the table lives, empty when the run did not say.
	Store  string
	Value  Filed
	Remedy string
}

func (e *Misfiled) Error() string {
	var b strings.Builder
	if e.Value.Column == "" {
		fmt.Fprintf(&b, "%s filed under %s is sealed as %s", e.Kind, e.Value.Filed, e.Value.Sealed)
	} else {
		fmt.Fprintf(&b, "%s %s does not match the sealed %s %s of the %s it selected",
			e.Value.Column, quoted(e.Value.Filed), e.Value.Field, quoted(e.Value.Sealed), e.Kind)
	}
	fmt.Fprintf(&b, " (table %s", e.Table)
	if e.Store != "" {
		fmt.Fprintf(&b, " in the store at %s", e.Store)
	}
	b.WriteString(")")
	if e.Remedy != "" {
		b.WriteString("; ")
		b.WriteString(e.Remedy)
	}
	return b.String()
}

// quoted shows an empty value as "" so a blank column still reads as a value.
func quoted(v string) string {
	if v == "" {
		return `""`
	}
	return v
}

// IsMisfiled reports whether err carries a Misfiled refusal.
func IsMisfiled(err error) bool {
	return errors.As(err, new(*Misfiled))
}

// CheckFiled compares each value a read selected a row by with the value sealed
// in the decoded record, and returns the first that differs as a *Misfiled. It
// reads fields already decoded, so it adds no hashing to the read.
func CheckFiled(kind, table, remedy string, values ...Filed) error {
	for _, v := range values {
		if v.Filed != v.Sealed {
			return &Misfiled{Kind: kind, Table: table, Store: storeLocation(), Value: v, Remedy: remedy}
		}
	}
	return nil
}

// location is the store the running invocation reads, for a refusal to name.
var location atomic.Pointer[string]

// SetStoreLocation names the store this process reads, so a Misfiled refusal
// names it; an empty path clears it.
func SetStoreLocation(path string) {
	if path == "" {
		location.Store(nil)
		return
	}
	location.Store(&path)
}

func storeLocation() string {
	if p := location.Load(); p != nil {
		return *p
	}
	return ""
}
