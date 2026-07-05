package xmod_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
)

func TestParse_simple(t *testing.T) {
	src := `module example.com/target

go 1.21

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.7.0 // indirect
)
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.ModulePath != "example.com/target" {
		t.Errorf("ModulePath = %q, want %q", got.ModulePath, "example.com/target")
	}
	if got.GoVersion != "1.21" {
		t.Errorf("GoVersion = %q, want %q", got.GoVersion, "1.21")
	}
	if len(got.Require) != 2 {
		t.Fatalf("len(Require) = %d, want 2", len(got.Require))
	}
	r0 := got.Require[0]
	if r0.Coordinate.Path != "github.com/foo/bar" || r0.Coordinate.Version != "v1.2.3" {
		t.Errorf("Require[0] = %v, want github.com/foo/bar@v1.2.3", r0.Coordinate)
	}
	if r0.Indirect {
		t.Error("Require[0] should not be indirect")
	}
	r1 := got.Require[1]
	if !r1.Indirect {
		t.Error("Require[1] should be indirect")
	}
}

func TestParse_noRequires(t *testing.T) {
	src := `module example.com/empty

go 1.20
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Require) != 0 {
		t.Errorf("Require should be empty, got %d entries", len(got.Require))
	}
}

func TestParse_replaceModule(t *testing.T) {
	src := `module example.com/target

go 1.21

require github.com/old/pkg v1.0.0

replace github.com/old/pkg v1.0.0 => github.com/new/pkg v1.1.0
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Replace) != 1 {
		t.Fatalf("len(Replace) = %d, want 1", len(got.Replace))
	}
	r := got.Replace[0]
	if r.OldPath != "github.com/old/pkg" {
		t.Errorf("Replace.OldPath = %q", r.OldPath)
	}
	if r.OldVersion != "v1.0.0" {
		t.Errorf("Replace.OldVersion = %q", r.OldVersion)
	}
	if r.IsLocal {
		t.Error("should not be local replace")
	}
	if r.NewCoordinate.Path != "github.com/new/pkg" {
		t.Errorf("Replace.New.Path = %q", r.NewCoordinate.Path)
	}
	if r.NewCoordinate.Version != "v1.1.0" {
		t.Errorf("Replace.New.Version = %q", r.NewCoordinate.Version)
	}
}

func TestParse_replaceLocal(t *testing.T) {
	src := `module example.com/target

go 1.21

require github.com/local/pkg v1.0.0

replace github.com/local/pkg => ./local/pkg
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Replace) != 1 {
		t.Fatalf("len(Replace) = %d, want 1", len(got.Replace))
	}
	r := got.Replace[0]
	if !r.IsLocal {
		t.Error("should be local replace")
	}
	if r.LocalPath != "./local/pkg" {
		t.Errorf("LocalPath = %q, want %q", r.LocalPath, "./local/pkg")
	}
}

func TestParse_exclude(t *testing.T) {
	src := `module example.com/target

go 1.21

require github.com/foo/bar v1.2.3

exclude github.com/foo/bar v1.2.3
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Exclude) != 1 {
		t.Fatalf("len(Exclude) = %d, want 1", len(got.Exclude))
	}
	e := got.Exclude[0]
	if e.Coordinate.Path != "github.com/foo/bar" || e.Coordinate.Version != "v1.2.3" {
		t.Errorf("Exclude[0] = %v", e.Coordinate)
	}
}

func TestParse_retract(t *testing.T) {
	src := `module example.com/mymod

go 1.21

retract (
	v1.0.0 // security issue
	[v1.1.0, v1.2.0] // broken range
)
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Retract) != 2 {
		t.Fatalf("len(Retract) = %d, want 2", len(got.Retract))
	}
	single := got.Retract[0]
	if single.Low != "v1.0.0" || single.High != "v1.0.0" {
		t.Errorf("single retract: Low=%q High=%q", single.Low, single.High)
	}
	if single.Rationale != "security issue" {
		t.Errorf("Rationale = %q", single.Rationale)
	}
	rng := got.Retract[1]
	if rng.Low != "v1.1.0" || rng.High != "v1.2.0" {
		t.Errorf("range retract: Low=%q High=%q", rng.Low, rng.High)
	}
}

func TestParse_malformed(t *testing.T) {
	src := `this is not a valid go.mod file ;;;`
	p := xmod.New()
	_, err := p.Parse("go.mod", []byte(src))
	if err == nil {
		t.Fatal("expected parse error for malformed go.mod")
	}
}

func TestParse_pseudoVersion(t *testing.T) {
	src := `module example.com/target

go 1.21

require github.com/some/mod v0.0.0-20230101120000-abcdef012345
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Require) != 1 {
		t.Fatalf("len(Require) = %d, want 1", len(got.Require))
	}
	if got.Require[0].Coordinate.Version != "v0.0.0-20230101120000-abcdef012345" {
		t.Errorf("pseudo-version not preserved: %q", got.Require[0].Coordinate.Version)
	}
}

func TestParse_toolchain(t *testing.T) {
	src := `module example.com/target

go 1.22

toolchain go1.22.0
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Toolchain != "go1.22.0" {
		t.Errorf("Toolchain = %q, want %q", got.Toolchain, "go1.22.0")
	}
}

func TestParse_replaceWildcard(t *testing.T) {
	src := `module example.com/target

go 1.21

require github.com/old/pkg v1.0.0

replace github.com/old/pkg => github.com/new/pkg v1.1.0
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Replace) != 1 {
		t.Fatalf("len(Replace) = %d, want 1", len(got.Replace))
	}
	r := got.Replace[0]
	if r.OldVersion != "" {
		t.Errorf("wildcard replace should have empty OldVersion, got %q", r.OldVersion)
	}
}

func TestParse_toolDirectives(t *testing.T) {
	src := `module example.com/target

go 1.24

require (
	golang.org/x/tools v0.30.0
	github.com/golangci/golangci-lint v1.64.0
	github.com/foo/dep v1.5.0
)

tool (
	golang.org/x/tools/cmd/stringer
	github.com/golangci/golangci-lint/cmd/golangci-lint
)
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Tools) != 2 {
		t.Fatalf("len(Tools) = %d, want 2", len(got.Tools))
	}
	if got.Tools[0] != "golang.org/x/tools/cmd/stringer" {
		t.Errorf("Tools[0] = %q, want golang.org/x/tools/cmd/stringer", got.Tools[0])
	}
	if got.Tools[1] != "github.com/golangci/golangci-lint/cmd/golangci-lint" {
		t.Errorf("Tools[1] = %q, want github.com/golangci/golangci-lint/cmd/golangci-lint", got.Tools[1])
	}
}

func TestParse_noToolDirectives(t *testing.T) {
	src := `module example.com/target

go 1.21

require github.com/foo/bar v1.2.3
`
	p := xmod.New()
	got, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Tools) != 0 {
		t.Errorf("len(Tools) = %d, want 0", len(got.Tools))
	}
}
