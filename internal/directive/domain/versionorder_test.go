package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/directive/domain"
)

// A directive's version legs order semantically, so a listing that holds
// several versions of one module presents v9 above v10 rather than below it.
func TestDirectiveLess_OrdersVersionsSemantically(t *testing.T) {
	t.Parallel()
	ds := []domain.Directive{
		{Source: "go.mod", Line: 1, Kind: "replace", OldPath: "example.com/mod", OldVersion: "v10.0.0"},
		{Source: "go.mod", Line: 1, Kind: "replace", OldPath: "example.com/mod", OldVersion: "v9.0.0"},
	}
	domain.Sort(ds)
	if ds[0].OldVersion != "v9.0.0" {
		t.Errorf("first directive names %q, want v9.0.0", ds[0].OldVersion)
	}

	ns := []domain.Directive{
		{Source: "go.mod", Line: 1, Kind: "replace", NewPath: "example.com/fork", NewVersion: "v10.0.0"},
		{Source: "go.mod", Line: 1, Kind: "replace", NewPath: "example.com/fork", NewVersion: "v9.0.0"},
	}
	domain.Sort(ns)
	if ns[0].NewVersion != "v9.0.0" {
		t.Errorf("first directive replaces with %q, want v9.0.0", ns[0].NewVersion)
	}
}

// A local replace names a path, not a version, and a branch name is not semver.
// The comparator stays a total order over those, which is what keeps Hash a
// function of the set alone.
func TestDirectiveLess_StaysTotalOnVersionsSemverRefuses(t *testing.T) {
	t.Parallel()
	a := domain.Directive{Source: "go.mod", Line: 1, Kind: "replace", OldVersion: "main"}
	b := domain.Directive{Source: "go.mod", Line: 1, Kind: "replace", OldVersion: "master"}
	if domain.DirectiveLess(a, b) == domain.DirectiveLess(b, a) {
		t.Error("two directives differing only in a non-semver version compare equal both ways; the order is not total")
	}
	if !domain.DirectiveLess(a, domain.Directive{Source: "go.mod", Line: 1, Kind: "replace", OldVersion: "v0.0.1"}) {
		t.Error("a version semver refuses does not rank below one it accepts")
	}
}

// The control on the hash cost. The version leg is reached only after the
// source, the line, the kind and the path have all compared equal — two
// directives on one line of one file — so no directive set the store holds
// reorders, and no stored record is darkened.
func TestHash_UnreachableVersionLegLeavesTheHashAlone(t *testing.T) {
	t.Parallel()
	ds := []domain.Directive{
		{Source: "go.mod", Line: 2, Kind: "replace", OldPath: "example.com/b", OldVersion: "v10.0.0"},
		{Source: "go.mod", Line: 1, Kind: "replace", OldPath: "example.com/a", OldVersion: "v9.0.0"},
	}
	byLine := []domain.Directive{ds[1], ds[0]}
	domain.Sort(ds)
	if got, want := domain.Hash(ds), domain.Hash(byLine); got != want {
		t.Errorf("hash %s, want %s: the version leg moved a set whose earlier keys already differ", got, want)
	}
}
