package domain_test

import (
	"encoding/json"
	"strings"
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestWalkStatus_MarshalJSON(t *testing.T) {
	cases := []struct {
		s    domain.WalkStatus
		want string
	}{
		{domain.WalkSucceeded, `"succeeded"`},
		{domain.WalkPartial, `"partial"`},
		{domain.WalkFailed, `"failed"`},
		{domain.WalkCancelled, `"cancelled"`},
	}
	for _, tc := range cases {
		b, err := json.Marshal(tc.s)
		if err != nil {
			t.Fatalf("json.Marshal(%v): %v", tc.s, err)
		}
		if got := string(b); got != tc.want {
			t.Errorf("json.Marshal(%v) = %s, want %s", tc.s, got, tc.want)
		}
	}
}

func TestWalkStatus_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		input string
		want  domain.WalkStatus
	}{
		{`"succeeded"`, domain.WalkSucceeded},
		{`"partial"`, domain.WalkPartial},
		{`"failed"`, domain.WalkFailed},
		{`"cancelled"`, domain.WalkCancelled},
	}
	for _, tc := range cases {
		var s domain.WalkStatus
		if err := json.Unmarshal([]byte(tc.input), &s); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", tc.input, err)
		}
		if s != tc.want {
			t.Errorf("json.Unmarshal(%s) = %v, want %v", tc.input, s, tc.want)
		}
	}
}

func TestWalkStatus_UnmarshalJSON_Invalid(t *testing.T) {
	var s domain.WalkStatus
	if err := json.Unmarshal([]byte(`"unknown"`), &s); err == nil {
		t.Error("expected error for invalid WalkStatus, got nil")
	}
}

func TestModuleCoordinate_MarshalJSON_FlatString(t *testing.T) {
	c := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.2.3"}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(b)
	if got != `"example.com/mod@v1.2.3"` {
		t.Errorf("MarshalJSON = %s, want %q", got, "example.com/mod@v1.2.3")
	}
	// Must not contain PascalCase keys
	for _, bad := range []string{`"Path"`, `"Version"`} {
		if strings.Contains(got, bad) {
			t.Errorf("MarshalJSON contains PascalCase key %s: %s", bad, got)
		}
	}
}

func TestModuleCoordinate_RoundTrip(t *testing.T) {
	orig := fetchdomain.ModuleCoordinate{Path: "example.com/mod", Version: "v1.2.3"}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got fetchdomain.ModuleCoordinate
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != orig {
		t.Errorf("round-trip: got %v, want %v", got, orig)
	}
}
