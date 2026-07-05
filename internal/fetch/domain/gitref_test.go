package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestGitReference_ShortHash(t *testing.T) {
	r := domain.GitReference{CommitHash: "abcdef123456789012345678901234567890abcd"}
	if got := r.ShortHash(); got != "abcdef123456" {
		t.Errorf("ShortHash() = %q, want %q", got, "abcdef123456")
	}
}

func TestGitReference_ShortHashShort(t *testing.T) {
	r := domain.GitReference{CommitHash: "abc"}
	if got := r.ShortHash(); got != "abc" {
		t.Errorf("ShortHash() = %q, want %q", got, "abc")
	}
}

func TestGitReference_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ref     domain.GitReference
		wantErr bool
	}{
		{
			"valid",
			domain.GitReference{URL: "https://github.com/foo/bar", CommitHash: "abcdef123456789012345678901234567890abcd"},
			false,
		},
		{"missing URL", domain.GitReference{CommitHash: "abcdef123456789012345678901234567890abcd"}, true},
		{"short commit", domain.GitReference{URL: "https://github.com/foo/bar", CommitHash: "abc"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ref.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
