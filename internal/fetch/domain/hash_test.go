package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
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
				if h.Algorithm != tt.wantAlg || h.Value != tt.wantVal {
					t.Errorf("got %+v, want alg=%s val=%s", h, tt.wantAlg, tt.wantVal)
				}
			}
		})
	}
}

func TestModuleHash_String(t *testing.T) {
	h := domain.ModuleHash{Algorithm: "h1", Value: "abc123=="}
	if got := h.String(); got != "h1:abc123==" {
		t.Errorf("String() = %q", got)
	}
}

func TestModuleHash_Equal(t *testing.T) {
	a := domain.ModuleHash{Algorithm: "h1", Value: "x"}
	b := domain.ModuleHash{Algorithm: "h1", Value: "x"}
	c := domain.ModuleHash{Algorithm: "h1", Value: "y"}
	if !a.Equal(b) {
		t.Error("expected equal")
	}
	if a.Equal(c) {
		t.Error("expected not equal")
	}
}
