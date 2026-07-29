package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

func TestParseModuleHash(t *testing.T) {
	tests := []struct {
		input   string
		wantAlg string
		wantVal string
		wantErr bool
	}{
		{"h1:abc123==", "h1", "abc123==", false},
		{"h1:", "", "", true},
		{":abc", "", "", true},
		{"", "", "", true},
		{"nodcolon", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			h, err := domain.ParseModuleHash(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseModuleHash(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr {
				if h.Algorithm() != tt.wantAlg || h.Value() != tt.wantVal {
					t.Errorf("got %+v, want alg=%s val=%s", h, tt.wantAlg, tt.wantVal)
				}
			}
		})
	}
}

// NewModuleHash is the only way to state a hash, so it is where a half-stated
// one has to be turned away. A hash with an algorithm and no value serialises
// to "h1:", which ParseModuleHash rejects — the struct literal that used to be
// possible could write a value no reader could read back.
func TestNewModuleHash_RefusesAHalfStatedHash(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		value     string
		wantErr   bool
	}{
		{name: "well-formed", algorithm: "h1", value: "abc123==", wantErr: false},
		{name: "another algorithm", algorithm: "sha256", value: "0f00", wantErr: false},
		{name: "no value", algorithm: "h1", value: "", wantErr: true},
		{name: "no algorithm", algorithm: "", value: "abc123==", wantErr: true},
		{name: "neither", algorithm: "", value: "", wantErr: true},
		{name: "algorithm carrying the separator", algorithm: "h1:x", value: "abc123==", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := domain.NewModuleHash(tt.algorithm, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewModuleHash(%q, %q) err = %v, wantErr = %v", tt.algorithm, tt.value, err, tt.wantErr)
			}
			if tt.wantErr {
				if !h.IsZero() {
					t.Errorf("refused hash = %v, want the zero hash", h)
				}
				return
			}
			if h.Algorithm() != tt.algorithm || h.Value() != tt.value {
				t.Errorf("got %+v, want alg=%s val=%s", h, tt.algorithm, tt.value)
			}
			round, err := domain.ParseModuleHash(h.String())
			if err != nil || !round.Equal(h) {
				t.Errorf("ParseModuleHash(%q) = %v, %v; want the hash back", h.String(), round, err)
			}
		})
	}
}

func TestModuleHash_String(t *testing.T) {
	h := fetchtest.H1("abc123==")
	if got := h.String(); got != "h1:abc123==" {
		t.Errorf("String() = %q", got)
	}
}

func TestModuleHash_Equal(t *testing.T) {
	a := fetchtest.H1("x")
	b := fetchtest.H1("x")
	c := fetchtest.H1("y")
	if !a.Equal(b) {
		t.Error("expected equal")
	}
	if a.Equal(c) {
		t.Error("expected not equal")
	}
}
