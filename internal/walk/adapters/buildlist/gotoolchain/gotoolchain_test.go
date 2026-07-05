package gotoolchain

import (
	"reflect"
	"testing"

	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func TestParseModules(t *testing.T) {
	// `go list -m -json all` emits one JSON object per module, concatenated
	// (not a JSON array). The main module has Main:true and no Version.
	const listOut = `{
	"Path": "example.com/project",
	"Main": true,
	"Dir": "/home/u/project",
	"GoMod": "/home/u/project/go.mod"
}
{
	"Path": "golang.org/x/mod",
	"Version": "v0.35.0",
	"Indirect": false
}
{
	"Path": "golang.org/x/sys",
	"Version": "v0.20.0",
	"Indirect": true
}
{
	"Path": "example.com/forked",
	"Version": "v1.0.0",
	"Replace": {
		"Path": "example.com/fork",
		"Version": "v1.2.0"
	}
}
{
	"Path": "example.com/local",
	"Version": "v0.0.0",
	"Replace": {
		"Path": "../local",
		"Dir": "/home/u/local"
	}
}
`

	got, err := parseModules([]byte(listOut))
	if err != nil {
		t.Fatalf("parseModules: %v", err)
	}

	want := []walkports.BuildListModule{
		{Path: "example.com/project", Main: true},
		{Path: "golang.org/x/mod", Version: "v0.35.0"},
		{Path: "golang.org/x/sys", Version: "v0.20.0", Indirect: true},
		{
			Path:    "example.com/forked",
			Version: "v1.0.0",
			Replace: &walkports.BuildListReplace{Path: "example.com/fork", Version: "v1.2.0"},
		},
		{
			Path:    "example.com/local",
			Version: "v0.0.0",
			Replace: &walkports.BuildListReplace{Path: "../local"},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseModules mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseModules_Empty(t *testing.T) {
	got, err := parseModules(nil)
	if err != nil {
		t.Fatalf("parseModules(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("parseModules(nil) = %v, want empty", got)
	}
}

func TestParseModules_Malformed(t *testing.T) {
	if _, err := parseModules([]byte("{not json")); err == nil {
		t.Fatal("parseModules: expected error for malformed JSON, got nil")
	}
}

func TestParseGraph(t *testing.T) {
	// `go mod graph` is line-oriented: "from to", each "path@version" except the
	// main module (bare path) and the go/toolchain pseudo-nodes.
	const graphOut = `example.com/project golang.org/x/mod@v0.35.0
example.com/project golang.org/x/sys@v0.20.0
golang.org/x/mod@v0.35.0 golang.org/x/sys@v0.18.0
example.com/project go@1.23
example.com/project toolchain@go1.23.4
`

	got, err := parseGraph([]byte(graphOut))
	if err != nil {
		t.Fatalf("parseGraph: %v", err)
	}

	want := []walkports.BuildListEdge{
		{From: "example.com/project", To: "golang.org/x/mod@v0.35.0"},
		{From: "example.com/project", To: "golang.org/x/sys@v0.20.0"},
		{From: "golang.org/x/mod@v0.35.0", To: "golang.org/x/sys@v0.18.0"},
		{From: "example.com/project", To: "go@1.23"},
		{From: "example.com/project", To: "toolchain@go1.23.4"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseGraph mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseGraph_Empty(t *testing.T) {
	got, err := parseGraph([]byte("\n  \n"))
	if err != nil {
		t.Fatalf("parseGraph: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("parseGraph blank input = %v, want empty", got)
	}
}

func TestParseGraph_Malformed(t *testing.T) {
	if _, err := parseGraph([]byte("only-one-token")); err == nil {
		t.Fatal("parseGraph: expected error for a line without two tokens, got nil")
	}
}

func TestGoBinDefault(t *testing.T) {
	if got := New("", nil).goBin(); got != "go" {
		t.Errorf("goBin() with empty binary = %q, want \"go\"", got)
	}
	if got := New("/opt/go/bin/go", nil).goBin(); got != "/opt/go/bin/go" {
		t.Errorf("goBin() = %q, want the configured path", got)
	}
}
