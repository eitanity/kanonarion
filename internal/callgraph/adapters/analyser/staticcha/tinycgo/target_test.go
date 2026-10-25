package tinycgo

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The pico chain is TinyGo v0.42.0's own targets/pico.json, rp2040.json,
// cortex-m0plus.json and cortex-m.json, copied unchanged (Copyright (c)
// 2018-2026 The TinyGo Authors, BSD-3-Clause).
func TestLoadTarget_ReadsThePicoChainAsTinyGoMergesIt(t *testing.T) {
	spec, err := LoadTarget(filepath.Join("testdata", "pico-targets", ".."), "pico-targets/pico.json")
	if err == nil {
		t.Fatalf("a path target resolves its parents by name under the root, so this must fail: %+v", spec)
	}
	root := t.TempDir()
	linkTargets(t, root, "pico-targets")

	spec, err = LoadTarget(root, "pico")
	if err != nil {
		t.Fatalf("LoadTarget: %v", err)
	}
	if spec.CPU != "cortex-m0plus" || spec.Triple != "thumbv6m-unknown-unknown-eabi" {
		t.Errorf("cpu %q, llvm-target %q", spec.CPU, spec.Triple)
	}
	want := []string{"-Werror", "-fshort-enums", "-fomit-frame-pointer", "-mfloat-abi=soft", "-fno-exceptions",
		"-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections"}
	if !reflect.DeepEqual(spec.CFlags, want) {
		t.Errorf("cflags = %q, want cortex-m's nine in order %q", spec.CFlags, want)
	}
	if got := cFlags(spec, "/tg", spec.Triple, "arm"); !reflect.DeepEqual(got[len(got)-2:],
		[]string{"--target=thumbv6m-unknown-unknown-eabi", "-mcpu=cortex-m0plus"}) {
		t.Errorf("flags end %q", got)
	}
}

func TestLoadTarget_ADuplicateSliceEntryIsAnError(t *testing.T) {
	root := t.TempDir()
	linkTargets(t, root, "dup-targets")

	_, err := LoadTarget(root, "dupboard")

	if err == nil || !strings.Contains(err.Error(), "duplicate value '-Werror' in field CFlags") {
		t.Fatalf("LoadTarget = %v, want the duplicate named", err)
	}
}

func TestLoadTarget_NoDefinitionIsAnEmptyChain(t *testing.T) {
	spec, err := LoadTarget(t.TempDir(), "x86_64-unknown-linux")
	if err != nil || !reflect.DeepEqual(spec, &TargetSpec{}) {
		t.Fatalf("LoadTarget = %+v, %v; a bare triple has no definition", spec, err)
	}
	if _, err := LoadTarget(t.TempDir(), "missing.json"); err == nil {
		t.Error("a target named by a path that does not exist was accepted")
	}
}

func TestLoadTarget_AMissingParentIsAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "targets"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "targets", "orphan.json"), `{"inherits": ["nosuchchip"]}`)
	if _, err := LoadTarget(root, "orphan"); err == nil || !strings.Contains(err.Error(), "nosuchchip") {
		t.Fatalf("LoadTarget = %v", err)
	}
	writeFile(t, filepath.Join(root, "targets", "garbled.json"), `{`)
	if _, err := LoadTarget(root, "garbled"); err == nil {
		t.Fatal("a definition that is not JSON was accepted")
	}
}

// The fake chain carries the four things the flags are built from: an
// inherits list, a cpu, a cflag with {root}, and an ABI.
func TestCFlags_FollowTinyGosOrderAndSpelling(t *testing.T) {
	spec, err := LoadTarget(filepath.Join("testdata", "tinygoroot"), "fakeboard")
	if err != nil {
		t.Fatalf("LoadTarget: %v", err)
	}
	got := cFlags(spec, "/opt/tinygo", spec.Triple, "arm")
	want := []string{"-Werror", "-I/opt/tinygo/include", "-DFAKEBOARD=1", "--target=thumbv6m-unknown-unknown-eabi",
		"-mcpu=cortex-m0plus", "-mabi=aapcs"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cFlags = %q, want %q", got, want)
	}
	for _, tc := range []struct{ triple, goarch, want string }{
		{"avr", "arm", "-mmcu=atmega328p"},
		{"x86_64-unknown-linux", "amd64", "-march=atmega328p"},
		{"i386-unknown-linux", "386", "-march=atmega328p"},
	} {
		flags := cFlags(&TargetSpec{CPU: "atmega328p"}, "/r", tc.triple, tc.goarch)
		if flags[len(flags)-1] != tc.want {
			t.Errorf("%s/%s: cpu flag %q, want %q", tc.triple, tc.goarch, flags[len(flags)-1], tc.want)
		}
	}
	if flags := cFlags(&TargetSpec{}, "/r", "wasm32-unknown-wasi", "wasm"); !reflect.DeepEqual(flags, []string{"--target=wasm32-unknown-wasi"}) {
		t.Errorf("an empty chain gives %q", flags)
	}
}

// Every field kind the merge knows overrides or appends as TinyGo's does.
func TestOverrideProperties_ScalarsOverrideWhenSetAndSlicesAppend(t *testing.T) {
	yes := true
	parent := &TargetSpec{CPU: "a", DefaultStackSize: 4, CFlags: []string{"-x"}}
	child := &TargetSpec{CPU: "", GC: "leaking", SoftFloat: true, DefaultStackSize: 8, AutoStackSize: &yes, CFlags: []string{"-y"}}
	if err := parent.overrideProperties(child); err != nil {
		t.Fatal(err)
	}
	if parent.CPU != "a" || parent.GC != "leaking" || !parent.SoftFloat || parent.DefaultStackSize != 8 ||
		parent.AutoStackSize != &yes || !reflect.DeepEqual(parent.CFlags, []string{"-x", "-y"}) {
		t.Errorf("merged = %+v", parent)
	}
}
