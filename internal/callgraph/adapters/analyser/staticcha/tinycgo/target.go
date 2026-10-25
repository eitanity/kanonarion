package tinycgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright (c) 2018-2026 The TinyGo Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: TinyGo cgo transform, target definitions and type sizes
// SPDX-SnippetComment: Ported from github.com/tinygo-org/tinygo@v0.42.0, compileopts/target.go (TargetSpec, overrideProperties, resolveInherits) and compileopts/config.go (CFlags)

// TargetSpec is a TinyGo target definition, the fields of compileopts.TargetSpec
// as its JSON files spell them. Every field is kept, not only the ones the C
// flags read, because the merge refuses a duplicate in any slice.
type TargetSpec struct {
	Inherits         []string `json:"inherits,omitempty"`
	InheritableOnly  bool     `json:"inheritable-only"`
	Triple           string   `json:"llvm-target,omitempty"`
	CPU              string   `json:"cpu,omitempty"`
	ABI              string   `json:"target-abi,omitempty"`
	Features         string   `json:"features,omitempty"`
	GOOS             string   `json:"goos,omitempty"`
	GOARCH           string   `json:"goarch,omitempty"`
	SoftFloat        bool
	BuildTags        []string `json:"build-tags,omitempty"`
	BuildMode        string   `json:"buildmode,omitempty"`
	GC               string   `json:"gc,omitempty"`
	Scheduler        string   `json:"scheduler,omitempty"`
	Serial           string   `json:"serial,omitempty"`
	Linker           string   `json:"linker,omitempty"`
	LinkerFlavor     string   `json:"linker-flavor,omitempty"`
	RTLib            string   `json:"rtlib,omitempty"`
	Libc             string   `json:"libc,omitempty"`
	AutoStackSize    *bool    `json:"automatic-stack-size,omitempty"`
	DefaultStackSize uint64   `json:"default-stack-size,omitempty"`
	CFlags           []string `json:"cflags,omitempty"`
	LDFlags          []string `json:"ldflags,omitempty"`
	LinkerScript     string   `json:"linkerscript,omitempty"`
	ExtraFiles       []string `json:"extra-files,omitempty"`
	RP2040BootPatch  *bool    `json:"rp2040-boot-patch,omitempty"`
	BootPatches      []string `json:"boot-patches,omitempty"`
	Emulator         string   `json:"emulator,omitempty"`
	FlashCommand     string   `json:"flash-command,omitempty"`
	GDB              []string `json:"gdb,omitempty"`
	PortReset        string   `json:"flash-1200-bps-reset,omitempty"`
	SerialPort       []string `json:"serial-port,omitempty"`
	FlashMethod      string   `json:"flash-method,omitempty"`
	FlashVolume      []string `json:"msd-volume-name,omitempty"`
	FlashFilename    string   `json:"msd-firmware-name,omitempty"`
	UF2FamilyID      string   `json:"uf2-family-id,omitempty"`
	BinaryFormat     string   `json:"binary-format,omitempty"`
	OpenOCDInterface string   `json:"openocd-interface,omitempty"`
	OpenOCDTarget    string   `json:"openocd-target,omitempty"`
	OpenOCDTransport string   `json:"openocd-transport,omitempty"`
	OpenOCDCommands  []string `json:"openocd-commands,omitempty"`
	OpenOCDVerify    *bool    `json:"openocd-verify,omitempty"`
	JLinkDevice      string   `json:"jlink-device,omitempty"`
	ADBPreCommands   []string `json:"adb-pre-commands,omitempty"`
	ADBPushRemote    string   `json:"adb-push-remote,omitempty"`
	ADBPostCommands  []string `json:"adb-post-commands,omitempty"`
	ProbeRSChip      string   `json:"probe-rs-chip,omitempty"`
	CodeModel        string   `json:"code-model,omitempty"`
	RelocationModel  string   `json:"relocation-model,omitempty"`
	WITPackage       string   `json:"wit-package,omitempty"`
	WITWorld         string   `json:"wit-world,omitempty"`
}

// overrideProperties merges child into spec: strings, unsigned integers, bools
// and pointers override when set, slices append, and a duplicate value in a
// slice is an error.
func (spec *TargetSpec) overrideProperties(child *TargetSpec) error {
	specType := reflect.TypeFor[TargetSpec]()
	specValue := reflect.ValueOf(spec).Elem()
	childValue := reflect.ValueOf(child).Elem()

	for i := range specType.NumField() {
		field := specType.Field(i)
		src := childValue.Field(i)
		dst := specValue.Field(i)

		switch kind := field.Type.Kind(); kind {
		case reflect.String:
			if src.Len() > 0 {
				dst.Set(src)
			}
		case reflect.Uint, reflect.Uint32, reflect.Uint64:
			if src.Uint() != 0 {
				dst.Set(src)
			}
		case reflect.Bool:
			if src.Bool() {
				dst.Set(src)
			}
		case reflect.Pointer:
			if !src.IsNil() {
				dst.Set(src)
			}
		case reflect.Slice:
			dst.Set(reflect.AppendSlice(dst, src))
			for i := 0; i < dst.Len(); i++ {
				v := dst.Index(i).String()
				for j := i + 1; j < dst.Len(); j++ {
					if v == dst.Index(j).String() {
						return fmt.Errorf("duplicate value '%s' in field %s", v, field.Name)
					}
				}
			}
		default:
			return fmt.Errorf("unknown field type: %s", kind)
		}
	}
	return nil
}

// loadTargetFile reads one definition: a path when name ends in .json,
// otherwise <root>/targets/<name>.json.
func loadTargetFile(root, name string) (*TargetSpec, error) {
	path := name
	if !strings.HasSuffix(name, ".json") {
		path = filepath.Join(root, "targets", strings.ToLower(name)+".json")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a target definition under TINYGOROOT, or the path the declaration named
	if err != nil {
		return nil, fmt.Errorf("reading the target definition: %w", err)
	}
	spec := &TargetSpec{}
	if err := json.Unmarshal(raw, spec); err != nil {
		return nil, fmt.Errorf("reading the target definition %s: %w", path, err)
	}
	return spec, nil
}

// resolveInherits loads the inherited definitions, recursively, parents first
// in inherits order and then spec itself.
func (spec *TargetSpec) resolveInherits(root string) error {
	inheritableOnly := spec.InheritableOnly
	newSpec := &TargetSpec{}
	for _, name := range spec.Inherits {
		sub, err := loadTargetFile(root, name)
		if err != nil {
			return err
		}
		if err := sub.resolveInherits(root); err != nil {
			return err
		}
		if err := newSpec.overrideProperties(sub); err != nil {
			return err
		}
	}
	if err := newSpec.overrideProperties(spec); err != nil {
		return err
	}
	*spec = *newSpec
	spec.InheritableOnly = inheritableOnly
	return nil
}

// cFlags is the target part of the clang command, in TinyGo's order: the
// definition's cflags with {root} as TINYGOROOT, the triple, the CPU flag as
// TinyGo spells it for the architecture, and the ABI when the chain names one.
// TinyGo's resource-dir, libc, debug and optimisation flags are left out.
func cFlags(spec *TargetSpec, root, triple, goarch string) []string {
	var cflags []string
	for _, flag := range spec.CFlags {
		cflags = append(cflags, strings.ReplaceAll(flag, "{root}", root))
	}
	cflags = append(cflags, "--target="+triple)
	if spec.CPU != "" {
		switch {
		case goarch == "amd64" || goarch == "386":
			cflags = append(cflags, "-march="+spec.CPU)
		case strings.HasPrefix(triple, "avr"):
			cflags = append(cflags, "-mmcu="+spec.CPU)
		default:
			cflags = append(cflags, "-mcpu="+spec.CPU)
		}
	}
	if spec.ABI != "" {
		cflags = append(cflags, "-mabi="+spec.ABI)
	}
	return cflags
}

// SPDX-SnippetEnd

// LoadTarget reads target's definition chain from root. A target with no
// definition file, such as a bare LLVM triple, has an empty chain.
func LoadTarget(root, target string) (*TargetSpec, error) {
	spec, err := loadTargetFile(root, target)
	if errors.Is(err, fs.ErrNotExist) && !strings.HasSuffix(target, ".json") {
		return &TargetSpec{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := spec.resolveInherits(root); err != nil {
		return nil, fmt.Errorf("the target definition %s: %w", target, err)
	}
	return spec, nil
}
