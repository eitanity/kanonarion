package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/iface/domain"
)

func TestNormalizeSignature(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "leading single-line comment stripped",
			in:   "// Foo does a thing.\nfunc Foo() error",
			want: "func Foo() error",
		},
		{
			name: "multiple leading comment lines stripped",
			in:   "// Foo does a thing.\n// It can span lines.\nfunc Foo() error",
			want: "func Foo() error",
		},
		{
			name: "doc-style triple-slash stripped",
			in:   "/// Foo\nfunc Foo()",
			want: "func Foo()",
		},
		{
			name: "indented comment stripped",
			in:   "    // indented doc\ntype T struct{}",
			want: "type T struct{}",
		},
		{
			name: "comment-only input yields empty",
			in:   "// just a comment\n// and another",
			want: "",
		},
		{
			name: "empty input yields empty",
			in:   "",
			want: "",
		},
		{
			name: "block comment left intact",
			in:   "/* package doc */\nfunc Foo()",
			want: "/* package doc */\nfunc Foo()",
		},
		{
			name: "no leading comment unchanged",
			in:   "func Bar(x int) string",
			want: "func Bar(x int) string",
		},
		{
			name: "comment after signature not stripped",
			in:   "func Baz() // trailing",
			want: "func Baz() // trailing",
		},
		{
			name: "surrounding whitespace trimmed",
			in:   "\n  func Qux()  \n",
			want: "func Qux()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domain.NormalizeSignature(tt.in); got != tt.want {
				t.Errorf("NormalizeSignature(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
